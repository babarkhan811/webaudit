import json
import os
import subprocess
import sys
from pathlib import Path

from conftest import HTML, audit
from webaudit.reporting import (
    build_summary,
    create_run_dir,
    render_html,
    site_filename,
    write_site_report,
    write_summary,
)

ROOT = Path(__file__).resolve().parent.parent
HTTP_CHECKS = "routing,headers,links,exposure"


def _summary(reports, **overrides):
    options = dict(
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:01:00+00:00",
        rejected=[],
        interrupted=False,
        not_run=[],
    )
    return build_summary(reports, **{**options, **overrides})


def _cli(*args, cwd):
    return subprocess.run(
        [sys.executable, "-m", "webaudit", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        env={**os.environ, "PYTHONPATH": str(ROOT), "PYTHONIOENCODING": "utf-8"},
    )


def test_site_filenames_are_safe_and_unique():
    first = site_filename("https://example.com/a?b=../../etc/passwd")
    second = site_filename("https://example.com/a?b=..\\..\\etc\\passwd")
    assert first != second
    for name in (first, second):
        assert "/" not in name and "\\" not in name and ".." not in name
        assert name.endswith(".json")


def test_run_folders_never_collide(tmp_path):
    assert create_run_dir(tmp_path) != create_run_dir(tmp_path)


def test_site_report_is_valid_json_with_expected_shape(make_site, tmp_path):
    site = make_site({"/": (200, HTML, b"<html></html>")})
    report = audit(site.url, ["headers", "routing"])
    run_dir = create_run_dir(tmp_path)
    path = write_site_report(report, run_dir)

    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["url"] == site.url
    assert saved["status"] == "completed"
    assert set(saved["checks"]) == {"headers", "routing"}
    assert saved["findings"][0]["severity"] == "high"
    assert isinstance(saved["score"], int)
    assert list(run_dir.glob("**/*.tmp")) == []


def test_hostile_site_content_is_escaped_in_html(make_site):
    payload = "<script>alert(1)</script>/1.2"
    site = make_site({"/": (200, HTML + [("Server", payload)], b"")})
    report = audit(site.url, ["headers"])
    assert payload in str(report.to_dict())

    html = render_html(_summary([report]))
    assert "<script" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_summary_orders_worst_first_and_totals_findings(make_site, tmp_path):
    good = make_site({"/": (200, HTML, b"")})
    bad = make_site(
        {
            "/": (200, HTML, b""),
            "/.env": (200, [("Content-Type", "text/plain")], b"SECRET_KEY=abc\n"),
        }
    )
    reports = [audit(good.url, ["routing"]), audit(bad.url, ["routing", "exposure"])]
    summary = _summary(reports)
    assert summary["sites"][0]["url"] == bad.url
    assert summary["severity_totals"]["critical"] == 1

    run_dir = create_run_dir(tmp_path)
    assert write_summary(summary, run_dir).exists()
    assert json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))["sites_audited"] == 2


def test_html_notes_interrupted_runs_and_rejected_lines():
    html = render_html(_summary([], interrupted=True, not_run=["https://a/"], rejected=["bad line"]))
    assert "This run was interrupted" in html
    assert "bad line" in html


def test_cli_end_to_end(make_site, tmp_path):
    clean = make_site({"/": (200, HTML, b"<html><a href='/x'>x</a></html>"), "/x": (200, HTML, b"")})
    exposed = make_site(
        {
            "/": (200, HTML, b"<html></html>"),
            "/.env": (200, [("Content-Type", "text/plain")], b"API_TOKEN=secretvalue\n"),
        }
    )
    targets = tmp_path / "sites.txt"
    targets.write_text(
        f"# test list\n{clean.url}\n{exposed.url}\nftp://not-supported\n", encoding="utf-8"
    )
    output = tmp_path / "out"

    result = _cli(
        "scan", str(targets), "-c", "2", "--only", HTTP_CHECKS, "-o", str(output),
        "--timeout", "2", "--retries", "0", "--fail-on", "critical",
        cwd=tmp_path,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "Skipped target" in result.stdout

    (run_dir,) = output.iterdir()
    assert len(list((run_dir / "sites").glob("*.json"))) == 2
    html = (run_dir / "summary.html").read_text(encoding="utf-8")
    assert "Environment file is public" in html
    for path in run_dir.rglob("*.*"):
        assert "secretvalue" not in path.read_text(encoding="utf-8")


def test_cli_exit_zero_without_fail_on(make_site, tmp_path):
    site = make_site({"/": (200, HTML, b"")})
    result = _cli(
        "scan", "-u", site.url, "--only", "routing", "-o", str(tmp_path / "out"), "-q",
        cwd=tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_cli_rejects_bad_usage(tmp_path):
    assert _cli("scan", "--only", "nonsense", "-u", "example.com", cwd=tmp_path).returncode == 2
    assert _cli("scan", cwd=tmp_path).returncode == 2
    assert _cli("scan", str(tmp_path / "missing.txt"), cwd=tmp_path).returncode == 2
    assert _cli("scan", "-u", "example.com", "-c", "0", cwd=tmp_path).returncode == 2


def test_cli_lists_checks(tmp_path):
    result = _cli("list-checks", cwd=tmp_path)
    assert result.returncode == 0
    assert "exposure" in result.stdout and "traceroute" in result.stdout
