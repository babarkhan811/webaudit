from conftest import HTML, audit, titles


def _audit(site, ca):
    return audit(site.url, ["tls"], ca_bundle=ca.path)


def test_valid_certificate_has_no_findings(make_site, ca):
    site = make_site({"/": (200, HTML, b"")}, tls_context=ca.server_context())
    report = _audit(site, ca)
    data = report.checks["tls"].data
    assert report.findings == []
    assert data["trusted"] is True
    assert data["protocol"] in ("TLSv1.2", "TLSv1.3")
    assert 88 <= data["days_until_expiry"] <= 90


def test_expired_certificate_is_critical(make_site, ca):
    site = make_site(tls_context=ca.server_context(days_left=-5))
    report = _audit(site, ca)
    assert report.checks["tls"].data["trusted"] is False
    assert titles(report) == {"TLS certificate has expired"}
    assert report.severity_counts["critical"] == 1


def test_certificate_close_to_expiry(make_site, ca):
    site = make_site(tls_context=ca.server_context(days_left=7))
    assert titles(_audit(site, ca)) == {"TLS certificate expires very soon"}

    site = make_site(tls_context=ca.server_context(days_left=25))
    assert titles(_audit(site, ca)) == {"TLS certificate expires soon"}


def test_self_signed_certificate(make_site, ca):
    site = make_site(tls_context=ca.server_context(self_signed=True))
    assert titles(_audit(site, ca)) == {"Self-signed certificate"}


def test_certificate_for_another_host(make_site, ca):
    site = make_site(tls_context=ca.server_context(ip="10.9.9.9"))
    assert titles(_audit(site, ca)) == {"Certificate does not match IP address"}


def test_untrusted_issuer_when_ca_is_unknown(make_site, ca):
    site = make_site(tls_context=ca.server_context())
    report = audit(site.url, ["tls"])
    assert titles(report) == {"Certificate issuer is not trusted"}


def test_no_https_listener(make_site):
    site = make_site({"/": (200, HTML, b"")})
    report = audit(f"https://127.0.0.1:{site.port}/", ["tls"])
    assert titles(report) == {"HTTPS is not available"}


def test_bad_certificate_does_not_stop_header_checks(make_site, ca):
    site = make_site({"/": (200, HTML, b"")}, tls_context=ca.server_context(days_left=-5))
    report = audit(site.url, ["tls", "headers"], ca_bundle=ca.path)
    assert report.reachable is True
    assert report.checks["headers"].status == "ok"
    assert {"TLS certificate has expired", "Missing Strict-Transport-Security"} <= titles(report)
