"""Domain registration data: RDAP first, classic WHOIS on port 43 as the fallback."""

from __future__ import annotations

import asyncio
import re
from contextlib import suppress
from datetime import UTC, datetime

import httpx

from webaudit.checks.base import register
from webaudit.checks.domains import registrable_domain
from webaudit.context import (
    NETWORK_ERRORS,
    CheckSkipped,
    SiteContext,
    verifying_context,
)
from webaudit.models import CheckResult, Severity

RDAP_URL = "https://rdap.org/domain/{domain}"
MAX_WHOIS_BYTES = 65_536

_EXPIRY = re.compile(
    r"^\s*(?:registry expiry date|registrar registration expiration date|expiry date"
    r"|expiration date|expires on|expires|paid-till|renewal date)\s*:\s*(.+?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_REGISTRAR = re.compile(r"^\s*registrar\s*:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_REFER = re.compile(r"^(?:refer|whois):\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_DATE_FORMATS = ("%Y-%m-%d", "%d-%b-%Y", "%d.%m.%Y", "%Y.%m.%d", "%Y/%m/%d")


def parse_date(value: str) -> datetime | None:
    value = value.strip()
    with suppress(ValueError):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    for fmt in _DATE_FORMATS:
        with suppress(ValueError):
            return datetime.strptime(value.split()[0], fmt).replace(tzinfo=UTC)
    return None


def parse_rdap(payload: dict) -> dict:
    events = {e.get("eventAction"): e.get("eventDate") for e in payload.get("events", [])}
    registrar = None
    for entity in payload.get("entities", []):
        if "registrar" in entity.get("roles", []):
            for item in (entity.get("vcardArray") or [None, []])[1]:
                if item[0] == "fn":
                    registrar = item[3]
    return {
        "source": "rdap",
        "registrar": registrar,
        "registered": events.get("registration"),
        "expires": events.get("expiration"),
        "status": payload.get("status", []),
    }


def parse_whois(text: str) -> dict:
    expiry = _EXPIRY.search(text)
    registrar = _REGISTRAR.search(text)
    return {
        "source": "whois",
        "registrar": registrar.group(1) if registrar else None,
        "registered": None,
        "expires": expiry.group(1) if expiry else None,
        "status": [],
    }


async def _rdap(domain: str, timeout: float) -> dict | None:
    # This client verifies certificates, unlike the scanning client.
    async with httpx.AsyncClient(
        verify=verifying_context(), timeout=timeout, follow_redirects=True
    ) as client:
        response = await client.get(RDAP_URL.format(domain=domain))
    return parse_rdap(response.json()) if response.status_code == 200 else None


async def _whois_query(server: str, query: str, timeout: float) -> str:
    async with asyncio.timeout(timeout):
        reader, writer = await asyncio.open_connection(server, 43)
        try:
            writer.write(f"{query}\r\n".encode())
            await writer.drain()
            raw = await reader.read(MAX_WHOIS_BYTES)
            while raw and len(raw) < MAX_WHOIS_BYTES:
                more = await reader.read(MAX_WHOIS_BYTES - len(raw))
                if not more:
                    break
                raw += more
        finally:
            writer.close()
    return raw.decode("utf-8", errors="replace")


async def _whois(domain: str, timeout: float) -> dict | None:
    tld = domain.rsplit(".", 1)[-1]
    referral = _REFER.search(await _whois_query("whois.iana.org", tld, timeout))
    if not referral:
        return None
    return parse_whois(await _whois_query(referral.group(1), domain, timeout))


@register("whois", "Domain registration and expiry (RDAP, WHOIS fallback)")
async def run(ctx: SiteContext, result: CheckResult) -> None:
    if ctx.target.is_ip:
        raise CheckSkipped("target is an IP address")
    domain = registrable_domain(ctx.target.host)
    if domain is None:
        raise CheckSkipped(f"{ctx.target.host} has no public registrable domain")

    timeout = ctx.config.request_timeout
    info = None
    for lookup in (_rdap, _whois):
        with suppress(*NETWORK_ERRORS):
            found = await lookup(domain, timeout)
            if found and (info is None or found["expires"]):
                info = found
        if info and info["expires"]:
            break

    if not info:
        result.add(
            Severity.INFO,
            "Registration data unavailable",
            f"Neither RDAP nor WHOIS returned data for {domain}.",
        )
        return

    result.data.update(domain=domain, **info)
    expires = parse_date(info["expires"]) if info["expires"] else None
    if expires is None:
        result.add(
            Severity.INFO,
            "Domain expiry date not published",
            f"The registry for {domain} does not expose an expiry date.",
        )
        return

    days = (expires - datetime.now(UTC)).days
    result.data["days_until_expiry"] = days
    renew = "Renew the domain and enable auto-renewal."
    if days < 0:
        result.add(
            Severity.CRITICAL,
            "Domain registration has expired",
            f"{domain} expired on {expires.date()}.",
            renew,
        )
    elif days <= 30:
        result.add(
            Severity.HIGH,
            "Domain registration expires soon",
            f"{domain} expires in {days} days.",
            renew,
        )
    elif days <= 90:
        result.add(
            Severity.LOW,
            "Domain renewal is approaching",
            f"{domain} expires in {days} days.",
            renew,
        )
