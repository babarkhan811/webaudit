"""Write per-site JSON reports and the run summary (JSON and HTML)."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from webaudit import __version__
from webaudit.models import SiteReport


def create_run_dir(root: Path) -> Path:
    """Create a fresh timestamped folder, so that runs never overwrite each other."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    for attempt in range(100):
        run_dir = root / (stamp if attempt == 0 else f"{stamp}-{attempt}")
        try:
            (run_dir / "sites").mkdir(parents=True)
        except FileExistsError:
            continue
        return run_dir
    raise OSError(f"could not create a run folder under {root}")


def site_filename(url: str) -> str:
    """A safe, unique filename. The hash separates URLs that sanitise alike."""
    name = re.sub(r"^https?://", "", url)
    name = re.sub(r"[^a-zA-Z0-9.-]+", "_", name)
    name = re.sub(r"\.{2,}", ".", name).strip("_.")[:80]
    return f"{name}-{hashlib.sha256(url.encode()).hexdigest()[:8]}.json"


def _write_json(path: Path, payload: Any) -> None:
    # Write then rename, so an interrupted run never leaves half a report.
    temporary = path.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )
    os.replace(temporary, path)


def write_site_report(report: SiteReport, run_dir: Path) -> Path:
    path = run_dir / "sites" / site_filename(report.url)
    report.report_file = f"sites/{path.name}"
    _write_json(path, report.to_dict())
    return path


def build_summary(
    reports: list[SiteReport],
    *,
    started_at: str,
    finished_at: str,
    rejected: list[str],
    interrupted: bool,
    not_run: list[str],
) -> dict[str, Any]:
    ordered = sorted(reports, key=lambda r: (r.score is None, r.score or 0, r.url))
    scores = [r.score for r in ordered if r.score is not None]
    totals = {
        severity: sum(r.severity_counts.get(severity, 0) for r in ordered)
        for severity in ("critical", "high", "medium", "low", "info")
    }
    return {
        "tool_version": __version__,
        "started_at": started_at,
        "finished_at": finished_at,
        "interrupted": interrupted,
        "sites_audited": len(ordered),
        "average_score": round(sum(scores) / len(scores)) if scores else None,
        "severity_totals": totals,
        "rejected_targets": rejected,
        "not_run": not_run,
        "sites": [
            {
                "target": r.target,
                "url": r.url,
                "final_url": r.final_url,
                "status": r.status,
                "score": r.score,
                "grade": r.grade,
                "severity_counts": r.severity_counts,
                "duration_s": r.duration_s,
                "report_file": r.report_file,
                "error": r.error,
                "checks": {
                    c.name: {"status": c.status, "error": c.error}
                    for c in r.checks.values()
                },
                "findings": [
                    {
                        "check": f.check,
                        "severity": f.severity.value,
                        "title": f.title,
                        "detail": f.detail,
                        "recommendation": f.recommendation,
                        "evidence": f.evidence,
                    }
                    for f in r.findings
                ],
            }
            for r in ordered
        ],
    }


def render_html(summary: dict[str, Any]) -> str:
    # Headers, URLs and link text all come from scanned sites, so they are
    # untrusted. Autoescaping stops a hostile site attacking whoever reads the report.
    environment = Environment(
        loader=PackageLoader("webaudit", "templates"),
        autoescape=select_autoescape(default=True, default_for_string=True),
    )
    return environment.get_template("summary.html.j2").render(**summary)


def write_summary(summary: dict[str, Any], run_dir: Path) -> Path:
    _write_json(run_dir / "summary.json", summary)
    html_path = run_dir / "summary.html"
    html_path.write_text(render_html(summary), encoding="utf-8")
    return html_path
