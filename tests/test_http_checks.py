import asyncio

import httpx
import pytest

from conftest import HTML, audit, titles
from webaudit.checks import links
from webaudit.checks.exposure import PROBES, matches
from webaudit.checks.links import extract_links
from webaudit.config import AuditConfig
from webaudit.context import BlockedRequest, Home, Response, SiteContext, build_client, resolves_internal
from webaudit.models import CheckResult
from webaudit.targets import parse_target

SECURE_HEADERS = HTML + [
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=()"),
]


def test_missing_headers_are_reported(make_site):
    site = make_site({"/": (200, HTML, b"<html></html>")})
    found = titles(audit(site.url, ["headers"]))
    assert {
        "Missing Content-Security-Policy",
        "Missing clickjacking protection",
        "Missing X-Content-Type-Options",
        "Missing Referrer-Policy",
    } <= found


def test_good_headers_produce_no_findings(make_site):
    site = make_site({"/": (200, SECURE_HEADERS, b"<html></html>")})
    report = audit(site.url, ["headers"])
    assert report.findings == []
    assert report.grade == "A"


def test_csp_weaknesses(make_site):
    headers = HTML + [("Content-Security-Policy", "script-src 'self' 'unsafe-inline' 'unsafe-eval' *")]
    site = make_site({"/": (200, headers, b"")})
    assert {
        "Content-Security-Policy allows inline scripts",
        "Content-Security-Policy allows eval",
        "Content-Security-Policy allows scripts from anywhere",
    } <= titles(audit(site.url, ["headers"]))


def test_cookie_flags_are_checked_and_values_are_not_recorded(make_site):
    headers = HTML + [("Set-Cookie", "session=topsecretvalue; Path=/")]
    site = make_site({"/": (200, headers, b"")})
    report = audit(site.url, ["headers"])
    assert "Cookies without the HttpOnly attribute" in titles(report)
    assert report.checks["headers"].data["cookies"] == ["session"]
    assert "topsecretvalue" not in str(report.to_dict())


def test_redirect_chain_is_traced(make_site):
    site = make_site(
        {
            "/": (302, [("Location", "/next")], b""),
            "/next": (301, [("Location", "/final")], b""),
            "/final": (200, HTML, b"ok"),
        }
    )
    report = audit(site.url, ["routing"])
    chain = report.checks["routing"].data["redirect_chain"]
    assert [hop["status"] for hop in chain] == [302, 301, 200]
    assert report.final_url.endswith("/final")
    assert "Site is served over plain http" in titles(report)


def test_redirect_loop_is_detected_and_ends(make_site):
    site = make_site(
        {"/": (302, [("Location", "/a")], b""), "/a": (302, [("Location", "/")], b"")}
    )
    report = audit(site.url, ["routing"])
    assert report.status == "unreachable"
    assert "Site is unreachable" in titles(report)


def test_server_error_on_landing_page(make_site):
    site = make_site({"/": (503, HTML, b"down")})
    assert "Landing page returns a server error" in titles(audit(site.url, ["routing"]))


def test_refused_connection_marks_site_unreachable(make_site):
    site = make_site()
    url = f"http://127.0.0.1:1/"
    report = audit(url, ["routing", "headers"])
    assert report.status == "unreachable"
    assert report.grade == "F"
    assert report.checks["headers"].status == "skipped"
    assert site.requests == []


def test_broken_links_are_found_by_kind(make_site):
    page = b"""<html><body>
      <a href="/good">fine</a> <a href="/gone">broken</a>
      <a href="mailto:a@example.com">mail</a> <a href="#top">anchor</a>
      <a href="/protected">protected</a>
      <img src="/missing.png"><script src="/missing.js"></script>
    </body></html>"""
    site = make_site(
        {
            "/": (200, HTML, page),
            "/good": (200, HTML, b"<a href='/deep-gone'>x</a>"),
            "/protected": (403, HTML, b""),
        }
    )
    report = audit(site.url, ["links"])
    data = report.checks["links"].data
    broken = {item["url"].rsplit("/", 1)[1] for item in data["broken"]}
    assert broken == {"gone", "missing.png", "missing.js", "deep-gone"}
    assert [i["status"] for i in data["unverified"]] == [403]
    assert {"Broken internal links", "Broken page resources"} <= titles(report)


def test_link_limits_are_respected(make_site):
    anchors = "".join(f'<a href="/p{i}">x</a>' for i in range(50)).encode()
    site = make_site({"/": (200, HTML, anchors)}, catch_all=(200, HTML, b"<html></html>"))
    report = audit(site.url, ["links"], max_pages=3, max_links=10)
    data = report.checks["links"].data
    assert data["links_found"] == 50
    assert data["links_checked"] == 10
    assert data["pages_crawled"] == 3


def test_extract_links_honours_base_and_ignores_other_schemes():
    html = '<base href="/sub/"><a href="x">a</a><a href="javascript:evil()">b</a><a href="http://[bad">c</a>'
    assert extract_links(html, "https://example.com/page") == [
        ("https://example.com/sub/x", "link")
    ]


def test_exposed_files_are_found_and_contents_never_stored(make_site):
    text = [("Content-Type", "text/plain")]
    site = make_site(
        {
            "/": (200, HTML, b"<html></html>"),
            "/.env": (200, text, b"DB_PASSWORD=supersecret\nAPP_KEY=abc\n"),
            "/.env.example": (200, text, b"DB_PASSWORD=\n"),
            "/.git/HEAD": (200, text, b"ref: refs/heads/main\n"),
            "/.git/config": (200, text, b"[core]\n\tbare = false\n"),
        }
    )
    report = audit(site.url, ["exposure"])
    exposed = {item["path"] for item in report.checks["exposure"].data["exposed"]}
    assert exposed == {"/.env", "/.env.example", "/.git/HEAD", "/.git/config"}
    assert report.severity_counts["critical"] == 3
    assert report.severity_counts["medium"] == 1
    assert report.grade == "F"
    assert "supersecret" not in str(report.to_dict())


def test_soft_404_site_causes_no_false_positives(make_site):
    site = make_site(catch_all=(200, HTML, b"<!doctype html><html>DB_NAME=x welcome</html>"))
    report = audit(site.url, ["exposure"])
    assert report.checks["exposure"].data["soft_404"] is True
    assert report.checks["exposure"].data["exposed"] == []


def test_plain_text_catch_all_is_not_flagged(make_site):
    site = make_site(catch_all=(200, [("Content-Type", "text/plain")], b"Hello there"))
    assert audit(site.url, ["exposure"]).checks["exposure"].data["exposed"] == []


@pytest.mark.parametrize(
    "path, body, expected",
    [
        ("/.env", b"export API_KEY=abc\n", True),
        ("/.env", b"# nothing useful here\n", False),
        ("/.git/HEAD", b"0123456789abcdef0123456789abcdef01234567\n", True),
        ("/.git/HEAD", b"not a git head", False),
        ("/.htpasswd", b"admin:$apr1$abc$def\n", True),
        ("/backup.sql", b"-- MySQL dump 10.13\n", True),
        ("/phpinfo.php", b"<html>PHP Version 8.2</html>", True),
    ],
)
def test_signatures(path, body, expected):
    probe = next(p for p in PROBES if p.path == path)
    assert matches(probe, body) is expected


def _public_context(client):
    context = SiteContext(parse_target("https://public.example/"), AuditConfig(), client)
    context.target_internal = False
    return context


def test_public_target_cannot_reach_internal_addresses(make_site):
    site = make_site({"/": (200, HTML, b"")})

    async def scenario():
        async with build_client(AuditConfig()) as client:
            with pytest.raises(BlockedRequest):
                await _public_context(client).request(site.url)

    asyncio.run(scenario())
    assert site.requests == []


def test_links_on_public_page_to_internal_hosts_are_not_requested(make_site):
    internal = make_site({"/": (200, HTML, b"")})
    html = f'<a href="{internal.url}admin">x</a><a href="http://169.254.169.254/latest/">y</a>'

    async def scenario():
        async with build_client(AuditConfig()) as client:
            context = _public_context(client)
            page = Response(
                "https://public.example/",
                200,
                httpx.Headers({"content-type": "text/html"}),
                html.encode(),
                False,
                0.1,
            )
            context._home = Home(page, [])
            result = CheckResult("links")
            await links.run(context, result)
            return result

    result = asyncio.run(scenario())
    assert len(result.data["blocked_internal"]) == 2
    assert internal.requests == []
    assert result.findings[0].title == "Links to private network addresses"


@pytest.mark.parametrize(
    "host, expected",
    [
        ("127.0.0.1", True),
        ("10.1.2.3", True),
        ("169.254.169.254", True),
        ("::1", True),
        ("[::ffff:192.168.0.1]", True),
        ("8.8.8.8", False),
    ],
)
def test_internal_address_detection(host, expected):
    assert asyncio.run(resolves_internal(host)) is expected


def test_target_on_internal_network_is_allowed_on_purpose(make_site):
    site = make_site({"/": (200, HTML, b"ok")})
    assert audit(site.url, ["routing"]).reachable is True
