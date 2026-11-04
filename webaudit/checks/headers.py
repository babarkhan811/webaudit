"""HTTP response headers and cookie flags on the landing page."""

from __future__ import annotations

import re

import httpx

from webaudit.checks.base import register
from webaudit.context import SiteContext
from webaudit.models import CheckResult, Severity

MIN_HSTS_SECONDS = 15_552_000  # 180 days
TRACKED_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "server",
    "x-powered-by",
)
_VERSIONED = re.compile(r"\d+\.\d+")


def parse_csp(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return directives


def _check_hsts(result: CheckResult, headers: httpx.Headers, is_https: bool) -> None:
    if not is_https:
        return  # browsers ignore HSTS over http; the routing check flags plain http
    value = headers.get("strict-transport-security")
    if value is None:
        result.add(
            Severity.HIGH,
            "Missing Strict-Transport-Security",
            "Browsers may connect over plain http before being redirected.",
            "Send: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        )
        return
    match = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.IGNORECASE)
    if match is None or int(match.group(1)) < MIN_HSTS_SECONDS:
        result.add(
            Severity.MEDIUM,
            "Weak Strict-Transport-Security",
            f"max-age is below {MIN_HSTS_SECONDS} seconds (180 days).",
            "Raise max-age to at least 31536000.",
            [value],
        )


def _check_csp(result: CheckResult, headers: httpx.Headers) -> dict[str, list[str]]:
    value = headers.get("content-security-policy")
    if value is None:
        if "content-security-policy-report-only" in headers:
            result.add(
                Severity.MEDIUM,
                "Content-Security-Policy is report-only",
                "Violations are reported but not blocked.",
                "Enforce the policy once the reports are clean.",
            )
        else:
            result.add(
                Severity.MEDIUM,
                "Missing Content-Security-Policy",
                "The browser has no policy limiting where scripts may load from.",
                "Define a Content-Security-Policy, starting from default-src 'self'.",
            )
        return {}

    csp = parse_csp(value)
    scripts = csp.get("script-src", csp.get("default-src", []))
    if not scripts:
        result.add(
            Severity.MEDIUM,
            "Content-Security-Policy does not restrict scripts",
            "Neither script-src nor default-src is set.",
            "Add a script-src or default-src directive.",
        )
    # A nonce or hash makes modern browsers ignore 'unsafe-inline'.
    has_nonce = any(s.startswith(("'nonce-", "'sha")) for s in scripts)
    if "'unsafe-inline'" in scripts and not has_nonce:
        result.add(
            Severity.MEDIUM,
            "Content-Security-Policy allows inline scripts",
            "'unsafe-inline' removes most of the protection against XSS.",
            "Use nonces or hashes for inline scripts.",
        )
    if "'unsafe-eval'" in scripts:
        result.add(
            Severity.LOW,
            "Content-Security-Policy allows eval",
            "'unsafe-eval' lets strings run as code.",
            "Remove the dependency on eval and drop 'unsafe-eval'.",
        )
    if "*" in scripts:
        result.add(
            Severity.MEDIUM,
            "Content-Security-Policy allows scripts from anywhere",
            "A wildcard source defeats the script policy.",
            "List the specific origins you need.",
        )
    return csp


def _check_framing(
    result: CheckResult, headers: httpx.Headers, csp: dict[str, list[str]]
) -> None:
    if "frame-ancestors" in csp:
        return  # supersedes X-Frame-Options in every current browser
    value = headers.get("x-frame-options", "").strip().upper()
    if value not in ("DENY", "SAMEORIGIN"):
        result.add(
            Severity.MEDIUM,
            "Missing clickjacking protection",
            "No valid X-Frame-Options value or CSP frame-ancestors directive was sent.",
            "Send X-Frame-Options: DENY, or use CSP frame-ancestors 'none'.",
        )


def _check_simple_headers(result: CheckResult, headers: httpx.Headers) -> None:
    if headers.get("x-content-type-options", "").strip().lower() != "nosniff":
        result.add(
            Severity.LOW,
            "Missing X-Content-Type-Options",
            "Browsers may guess content types, which can turn uploads into scripts.",
            "Send X-Content-Type-Options: nosniff.",
        )
    if "referrer-policy" not in headers:
        result.add(
            Severity.LOW,
            "Missing Referrer-Policy",
            "Full URLs may be sent to third-party sites.",
            "Send Referrer-Policy: strict-origin-when-cross-origin.",
        )
    if "permissions-policy" not in headers:
        result.add(
            Severity.INFO,
            "Missing Permissions-Policy",
            "Browser features such as the camera are not explicitly restricted.",
            "Send a Permissions-Policy that disables features you don't use.",
        )
    leaks = [
        f"{name}: {headers[name]}"
        for name in ("server", "x-powered-by")
        if name in headers and _VERSIONED.search(headers[name])
    ]
    if leaks:
        result.add(
            Severity.LOW,
            "Server software version disclosed",
            "Version numbers make it easier to match the site to known vulnerabilities.",
            "Remove version details from these headers.",
            leaks,
        )


def _check_cookies(result: CheckResult, headers: httpx.Headers, is_https: bool) -> None:
    problems: dict[str, list[str]] = {"Secure": [], "HttpOnly": [], "SameSite": []}
    cookies = []
    for raw in headers.get_list("set-cookie"):
        pair, *attributes = raw.split(";")
        name = pair.split("=", 1)[0].strip()  # names only: values may be session tokens
        cookies.append(name)
        flags = {a.split("=", 1)[0].strip().lower() for a in attributes}
        if is_https and "secure" not in flags:
            problems["Secure"].append(name)
        if "httponly" not in flags:
            problems["HttpOnly"].append(name)
        if "samesite" not in flags:
            problems["SameSite"].append(name)

    result.data["cookies"] = cookies
    severities = {
        "Secure": Severity.MEDIUM,
        "HttpOnly": Severity.LOW,
        "SameSite": Severity.LOW,
    }
    for flag, names in problems.items():
        if names:
            result.add(
                severities[flag],
                f"Cookies without the {flag} attribute",
                f"{len(names)} cookie(s) on the landing page lack {flag}.",
                f"Add the {flag} attribute to these cookies.",
                names,
            )


@register("headers", "Security headers (HSTS, CSP, X-Frame-Options...) and cookie flags")
async def run(ctx: SiteContext, result: CheckResult) -> None:
    response = (await ctx.require_home()).response
    headers = response.headers
    is_https = response.url.startswith("https://")

    result.data.update(
        url=response.url,
        headers={name: headers[name] for name in TRACKED_HEADERS if name in headers},
    )
    _check_hsts(result, headers, is_https)
    csp = _check_csp(result, headers)
    _check_framing(result, headers, csp)
    _check_simple_headers(result, headers)
    _check_cookies(result, headers, is_https)
