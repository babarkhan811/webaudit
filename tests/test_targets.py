import pytest

from webaudit.targets import InvalidTarget, parse_lines, parse_target


def test_bare_domain_defaults_to_https_without_explicit_scheme():
    target = parse_target("Example.COM")
    assert target.url == "https://example.com/"
    assert target.port == 443
    assert target.explicit_scheme is False


def test_port_and_path_are_preserved():
    target = parse_target("http://localhost:8080/app?x=1")
    assert target.url == "http://localhost:8080/app?x=1"
    assert target.port == 8080
    assert target.explicit_scheme is True


def test_bare_host_with_port():
    assert parse_target("example.com:8443").url == "https://example.com:8443/"


def test_ipv6_literal():
    target = parse_target("http://[::1]:8080/")
    assert target.host == "::1"
    assert target.url == "http://[::1]:8080/"
    assert target.is_ip


def test_international_domain_becomes_punycode():
    assert parse_target("bücher.example").host == "xn--bcher-kva.example"


@pytest.mark.parametrize(
    "bad",
    [
        "ftp://example.com",
        "https://user:pass@example.com",
        "https://",
        "exa mple.com",
        "-oProxyCommand=evil",
        "https://example.com:99999/",
    ],
)
def test_rejected_targets(bad):
    with pytest.raises(InvalidTarget):
        parse_target(bad)


def test_parse_lines_skips_comments_dedupes_and_reports_bad_lines():
    targets, rejected = parse_lines(
        ["# heading", "", "example.com  # inline", "https://example.com/", "ftp://nope"]
    )
    assert [t.url for t in targets] == ["https://example.com/"]
    assert len(rejected) == 1 and "ftp://nope" in rejected[0]
