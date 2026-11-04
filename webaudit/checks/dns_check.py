"""DNS availability plus the records that affect mail and certificate security."""

from __future__ import annotations

import asyncio
from functools import cache

import dns.asyncresolver
import dns.exception
import dns.resolver

from webaudit.checks.base import register
from webaudit.checks.domains import registrable_domain
from webaudit.context import CheckSkipped, SiteContext
from webaudit.models import CheckResult, Severity


@cache
def _resolver() -> dns.asyncresolver.Resolver:
    return dns.asyncresolver.Resolver()


async def _lookup(name: str, rtype: str, timeout: float) -> tuple[str, list[str]]:
    """Return (outcome, records); outcome is ok, nxdomain, empty or failed."""
    try:
        answer = await _resolver().resolve(name, rtype, lifetime=timeout)
    except dns.resolver.NXDOMAIN:
        return "nxdomain", []
    except dns.resolver.NoAnswer:
        return "empty", []
    except dns.exception.DNSException:
        return "failed", []
    return "ok", [record.to_text() for record in answer]


@register("dns", "DNS resolution, nameservers, CAA, SPF and DMARC")
async def run(ctx: SiteContext, result: CheckResult) -> None:
    host = ctx.target.host
    if ctx.target.is_ip:
        raise CheckSkipped("target is an IP address")
    domain = registrable_domain(host) or host
    timeout = ctx.config.request_timeout

    queries = {
        "A": (host, "A"),
        "AAAA": (host, "AAAA"),
        "NS": (domain, "NS"),
        "MX": (domain, "MX"),
        "CAA": (domain, "CAA"),
        "TXT": (domain, "TXT"),
        "DMARC": (f"_dmarc.{domain}", "TXT"),
    }
    answers = dict(
        zip(
            queries,
            await asyncio.gather(*(_lookup(n, t, timeout) for n, t in queries.values())),
        )
    )
    records = {key: value[1] for key, value in answers.items()}
    result.data.update(domain=domain, records=records)

    if not records["A"] + records["AAAA"]:
        _report_no_address(result, host, {answers["A"][0], answers["AAAA"][0]})
        return

    if answers["NS"][0] == "ok" and len(records["NS"]) < 2:
        result.add(
            Severity.LOW,
            "Only one nameserver",
            "A single nameserver is a single point of failure.",
            "Use at least two nameservers.",
        )
    if answers["CAA"][0] in ("empty", "nxdomain"):
        result.add(
            Severity.INFO,
            "No CAA record",
            "Any certificate authority may issue certificates for this domain.",
            "Publish a CAA record naming your certificate authorities.",
        )
    _check_mail(result, answers, records)


def _report_no_address(result: CheckResult, host: str, outcomes: set[str]) -> None:
    if "failed" in outcomes:
        result.add(
            Severity.HIGH,
            "DNS lookup failed",
            f"The resolver gave no usable answer for {host}.",
            "Confirm the authoritative nameservers are responding.",
        )
    elif "nxdomain" in outcomes:
        result.add(
            Severity.CRITICAL,
            "Domain does not exist in DNS",
            f"{host} returned NXDOMAIN.",
            "Check the domain's registration and DNS zone.",
        )
    else:
        result.add(
            Severity.CRITICAL,
            "No A or AAAA records",
            f"{host} exists but has no address.",
            "Publish an A or AAAA record.",
        )


def _check_mail(result: CheckResult, answers: dict, records: dict) -> None:
    if not records["MX"] or "failed" in (answers["TXT"][0], answers["DMARC"][0]):
        return
    if not any("v=spf1" in txt.lower() for txt in records["TXT"]):
        result.add(
            Severity.MEDIUM,
            "No SPF record",
            "The domain receives mail but does not say which servers may send it.",
            "Publish an SPF TXT record.",
        )
    dmarc = next((t for t in records["DMARC"] if "v=dmarc1" in t.lower()), None)
    if dmarc is None:
        result.add(
            Severity.MEDIUM,
            "No DMARC record",
            "Receivers have no policy for mail that spoofs this domain.",
            "Publish a DMARC record at _dmarc.<domain>.",
        )
    elif "p=none" in dmarc.lower().replace(" ", ""):
        result.add(
            Severity.LOW,
            "DMARC policy is monitor-only",
            "p=none reports on spoofed mail but does not block it.",
            "Move to p=quarantine or p=reject after reviewing DMARC reports.",
        )
