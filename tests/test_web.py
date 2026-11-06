import time

import pytest
from starlette.testclient import TestClient

from conftest import HTML
from webaudit.web.app import config_from_options, create_app

TOKEN = "test-token-123"
AUTH = {"X-Auth-Token": TOKEN}


@pytest.fixture
def client(tmp_path):
    app = create_app(tmp_path / "reports", TOKEN)
    with TestClient(app, base_url="http://127.0.0.1:8765") as c:
        yield c


def _wait(client, scan_id, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        state = client.get(f"/api/scans/{scan_id}", headers=AUTH).json()
        if state["status"] != "running":
            return state
        time.sleep(0.05)
    raise AssertionError("scan did not finish in time")


def test_token_is_required_for_api(client):
    assert client.get("/api/meta").status_code == 403
    assert client.get("/api/meta", headers=AUTH).status_code == 200


def test_non_local_host_is_rejected(client):
    r = client.get("/api/meta", headers={**AUTH, "Host": "evil.example.com"})
    assert r.status_code == 403


def test_index_and_static_served(client):
    assert "webaudit" in client.get("/").text
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/../app.py").status_code == 404


def test_meta_lists_checks(client):
    data = client.get("/api/meta", headers=AUTH).json()
    names = {c["name"] for c in data["checks"]}
    assert {"dns", "tls", "headers", "exposure"} <= names
    assert data["version"]


def test_full_scan_flow(client, make_site):
    good = make_site({"/": (200, HTML, b"<html></html>")})
    exposed = make_site(
        {
            "/": (200, HTML, b"<html></html>"),
            "/.env": (200, [("Content-Type", "text/plain")], b"SECRET=topsecret\n"),
        }
    )
    body = {
        "targets": f"{good.url}\n{exposed.url}\nftp://bad",
        "checks": ["routing", "headers", "exposure"],
        "options": {"timeout": 2, "concurrency": 2},
    }
    start = client.post("/api/scans", json=body, headers=AUTH).json()
    assert start["total"] == 2
    assert any("ftp://bad" in r for r in start["rejected"])

    state = _wait(client, start["id"])
    assert state["status"] == "completed"
    summary = state["summary"]
    assert summary["sites_audited"] == 2
    assert summary["severity_totals"]["critical"] == 1  # the exposed .env

    # Worst site first, and findings present
    assert summary["sites"][0]["url"] == exposed.url
    titles = {f["title"] for f in summary["sites"][0]["findings"]}
    assert "Environment file is public" in titles
    # File contents are never shipped to the browser
    assert "topsecret" not in client.get(f"/api/scans/{start['id']}", headers=AUTH).text

    # HTML report is available
    report = client.get(f"/api/scans/{start['id']}/report", headers=AUTH)
    assert report.status_code == 200
    assert "Website audit summary" in report.text


def test_scan_rejects_bad_input(client):
    assert client.post("/api/scans", json={"targets": "", "checks": ["dns"]}, headers=AUTH).status_code == 400
    assert client.post("/api/scans", json={"targets": "x.com", "checks": []}, headers=AUTH).status_code == 400
    bad = client.post("/api/scans", json={"targets": "x.com", "checks": ["nope"]}, headers=AUTH)
    assert bad.status_code == 400


def test_history_lists_finished_runs(client, make_site):
    site = make_site({"/": (200, HTML, b"")})
    start = client.post(
        "/api/scans",
        json={"targets": site.url, "checks": ["routing"], "options": {"timeout": 2}},
        headers=AUTH,
    ).json()
    _wait(client, start["id"])

    runs = client.get("/api/scans", headers=AUTH).json()["runs"]
    assert any(run["id"] == start["id"] and run["sites"] == 1 for run in runs)


def test_unknown_and_malformed_ids(client):
    assert client.get("/api/scans/does-not-exist", headers=AUTH).status_code == 404
    assert client.get("/api/scans/..%2f..%2fetc", headers=AUTH).status_code == 404
    assert client.get("/api/scans/19990101-000000/report", headers=AUTH).status_code == 404


def test_options_are_clamped():
    config = config_from_options({"concurrency": 9999, "timeout": -5, "max_pages": "x"})
    assert config.concurrency == 50
    assert config.request_timeout == 1.0
    assert config.max_pages == 5  # invalid falls back to the default
