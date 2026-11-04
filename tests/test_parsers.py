from datetime import UTC, datetime

import pytest

from webaudit.checks.domains import registrable_domain
from webaudit.checks.headers import parse_csp
from webaudit.checks.traceroute import parse_output
from webaudit.checks.whois import parse_date, parse_rdap, parse_whois
from webaudit.models import CheckResult, Finding, Severity, SiteReport


@pytest.mark.parametrize(
    "host, expected",
    [
        ("www.example.co.uk", "example.co.uk"),
        ("a.b.example.com", "example.com"),
        ("localhost", None),
    ],
)
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


@pytest.mark.parametrize(
    "value",
    ["2030-01-02T03:04:05Z", "2030-01-02", "02-Jan-2030", "02.01.2030", "2030.01.02"],
)
def test_parse_date_formats(value):
    parsed = parse_date(value)
    assert (parsed.year, parsed.month, parsed.day) == (2030, 1, 2)
    assert parsed.tzinfo is not None


def test_parse_date_rejects_nonsense():
    assert parse_date("soon") is None


def test_parse_rdap():
    info = parse_rdap(
        {
            "events": [
                {"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
            ],
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                }
            ],
            "status": ["active"],
        }
    )
    assert info["registrar"] == "Example Registrar"
    assert info["expires"] == "2030-01-01T00:00:00Z"


def test_parse_whois():
    info = parse_whois(
        "Domain Name: EXAMPLE.COM\r\nRegistrar: Example Inc\r\n"
        "Registry Expiry Date: 2030-08-13T04:00:00Z\r\n"
    )
    assert info["registrar"] == "Example Inc"
    assert info["expires"] == "2030-08-13T04:00:00Z"


def test_parse_csp():
    assert parse_csp("Default-Src 'self'; img-src *;;") == {
        "default-src": ["'self'"],
        "img-src": ["*"],
    }


WINDOWS_TRACERT = """
Tracing route to example.com [93.184.216.34]
over a maximum of 20 hops:

  1    <1 ms    <1 ms     1 ms  192.168.1.1
  2     *        *        *     Request timed out.
  3    12 ms    11 ms    13 ms  93.184.216.34

Trace complete.
"""

UNIX_TRACEROUTE = """traceroute to example.com (93.184.216.34), 20 hops max
 1  192.168.1.1  0.512 ms  0.433 ms  0.401 ms
 2  * * *
 3  93.184.216.34  12.1 ms  11.9 ms  12.3 ms
"""


@pytest.mark.parametrize("output", [WINDOWS_TRACERT, UNIX_TRACEROUTE])
def test_parse_traceroute(output):
    hops = parse_output(output)
    assert [h["ip"] for h in hops] == ["192.168.1.1", None, "93.184.216.34"]
    assert len(hops[0]["rtt_ms"]) == 3
    assert hops[1]["rtt_ms"] == []


def _report(*severities):
    result = CheckResult("x")
    result.findings = [Finding("x", s, "t") for s in severities]
    report = SiteReport("t", "https://t/", datetime.now(UTC).isoformat(), reachable=True)
    report.checks = {"x": result}
    report.finalize()
    return report


def test_clean_site_scores_full_marks():
    report = _report()
    assert (report.score, report.grade, report.status) == (100, "A", "completed")


def test_score_uses_severity_weights():
    assert _report(Severity.HIGH, Severity.LOW).score == 83
    assert _report(Severity.INFO).score == 100


def test_any_critical_finding_fails_the_site():
    report = _report(Severity.CRITICAL)
    assert report.score == 49
    assert report.grade == "F"


def test_findings_are_sorted_most_severe_first():
    report = _report(Severity.LOW, Severity.CRITICAL, Severity.MEDIUM)
    assert [f.severity for f in report.findings] == [
        Severity.CRITICAL,
        Severity.MEDIUM,
        Severity.LOW,
    ]
