"""Availability, the redirect path, and enforcement of HTTPS."""

from __future__ import annotations

from urllib.parse import urlsplit

from webaudit.checks.base import register
from webaudit.context import (
    NETWORK_ERRORS,
    REDIRECT_CODES,
    BlockedRequest,
    SiteContext,
)
from webaudit.models import CheckResult, Severity


async def _check_http_upgrade(ctx: SiteContext, result: CheckResult) -> None:
    """Does plain http on the same host send visitors to https?"""
    host = ctx.target.host
    url = f"http://[{host}]/" if ":" in host else f"http://{host}/"
    try:
        response = await ctx.request(url)
    except (*NETWORK_ERRORS, BlockedRequest):
        result.data["http_upgrade"] = "http not served"
        return
    location = response.headers.get("location", "")
    upgraded = response.status in REDIRECT_CODES and location.startswith("https://")
    result.data["http_upgrade"] = "redirects to https" if upgraded else "not redirected"
    if not upgraded:
        result.add(
            Severity.MEDIUM,
            "Plain http is not redirected to https",
            f"{url} answered {response.status} without moving to https.",
            "Redirect all http traffic to https with a 301.",
        )


@register("routing", "Availability, redirect chain and HTTPS enforcement")
async def run(ctx: SiteContext, result: CheckResult) -> None:
    home = await ctx.home()
    result.data["redirect_chain"] = home.hops

    if home.response is None:
        result.add(
            Severity.CRITICAL,
            "Site is unreachable",
            home.error or "No response.",
            "Check that the server is running and reachable.",
        )
        return

    response = home.response
    result.data.update(
        final_url=response.url,
        final_status=response.status,
        response_time_s=response.elapsed_s,
    )
    if response.status >= 500:
        result.add(
            Severity.HIGH,
            "Landing page returns a server error",
            f"{response.url} answered {response.status}.",
            "Check the application and upstream services.",
        )
    elif response.status >= 400:
        result.add(
            Severity.MEDIUM,
            "Landing page returns a client error",
            f"{response.url} answered {response.status}.",
            "Confirm the URL. Bot protection can also cause this.",
        )

    urls = [hop["url"] for hop in home.hops]
    schemes = [urlsplit(url).scheme for url in urls]
    if any(a == "https" and b == "http" for a, b in zip(schemes, schemes[1:])):
        result.add(
            Severity.HIGH,
            "Redirect downgrades https to http",
            "The redirect chain moves visitors from https back to plain http.",
            "Keep every redirect on https.",
            urls,
        )
    if len(home.hops) - 1 > 3:
        result.add(
            Severity.LOW,
            "Long redirect chain",
            f"Reaching the page takes {len(home.hops) - 1} redirects.",
            "Point the first URL directly at the final destination.",
            urls,
        )

    if response.url.startswith("http://"):
        result.add(
            Severity.HIGH,
            "Site is served over plain http",
            f"The final URL is {response.url}.",
            "Serve the site over https and redirect http to it.",
        )
    elif ctx.target.default_port:
        await _check_http_upgrade(ctx, result)
