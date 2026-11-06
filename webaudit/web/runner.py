"""Run scans inside the server's event loop and track their live progress.

The CLI and the dashboard share one engine. This module is the dashboard's thin
wrapper around it: it starts a scan as an asyncio task, saves each site's report as
it finishes (so a report survives even if the browser closes), and publishes progress
events to any connected browsers.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from webaudit.checks import CheckSpec
from webaudit.config import AuditConfig
from webaudit.engine import Engine
from webaudit.models import SiteReport
from webaudit.reporting import (
    build_summary,
    create_run_dir,
    write_site_report,
    write_summary,
)
from webaudit.targets import Target

TERMINAL = ("completed", "interrupted", "error")


def row_from_report(report: SiteReport) -> dict:
    """The compact per-site record the results table shows while a scan runs."""
    return {
        "target": report.target,
        "url": report.url,
        "final_url": report.final_url,
        "status": report.status,
        "score": report.score,
        "grade": report.grade,
        "severity_counts": report.severity_counts,
        "duration_s": report.duration_s,
        "report_file": report.report_file,
        "error": report.error,
    }


@dataclass
class ScanJob:
    id: str
    run_dir: Path
    targets: list[Target]
    config: AuditConfig
    checks: list[CheckSpec]
    rejected: list[str]
    started_at: str
    status: str = "running"
    rows: list[dict] = field(default_factory=list)
    summary: dict | None = None
    error: str | None = None
    task: asyncio.Task | None = None
    _subscribers: set[asyncio.Queue] = field(default_factory=set)

    @property
    def total(self) -> int:
        return len(self.targets)

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    def publish(self, event: dict) -> None:
        for queue in list(self._subscribers):
            queue.put_nowait(event)

    def state(self) -> dict:
        return {
            "id": self.id,
            "status": self.status,
            "total": self.total,
            "completed": len(self.rows),
            "rows": self.rows,
            "rejected": self.rejected,
            "error": self.error,
            "summary": self.summary,
        }


class ScanManager:
    def __init__(self, reports_root: Path):
        self.reports_root = reports_root
        self.jobs: dict[str, ScanJob] = {}

    def start(
        self,
        targets: Sequence[Target],
        rejected: list[str],
        config: AuditConfig,
        checks: Sequence[CheckSpec],
    ) -> ScanJob:
        run_dir = create_run_dir(self.reports_root)
        job = ScanJob(
            id=run_dir.name,
            run_dir=run_dir,
            targets=list(targets),
            config=config,
            checks=list(checks),
            rejected=rejected,
            started_at=datetime.now(UTC).isoformat(timespec="seconds"),
        )
        self.jobs[job.id] = job
        job.task = asyncio.create_task(self._run(job))
        return job

    async def _run(self, job: ScanJob) -> None:
        def on_start(target: Target) -> None:
            job.publish({"type": "start", "url": target.url})

        def on_finish(target: Target, report: SiteReport) -> None:
            write_site_report(report, job.run_dir)  # persisted the moment it is ready
            row = row_from_report(report)
            job.rows.append(row)
            job.publish(
                {"type": "site", "row": row, "completed": len(job.rows), "total": job.total}
            )

        engine = Engine(job.config, job.checks, on_start=on_start, on_finish=on_finish)
        try:
            reports = await engine.run(job.targets)
        except Exception as exc:  # noqa: BLE001 - surfaced to the browser, not swallowed
            job.status = "error"
            job.error = f"{type(exc).__name__}: {exc}"
            job.publish({"type": "error", "error": job.error})
            return

        finished = {report.url for report in reports}
        job.summary = build_summary(
            reports,
            started_at=job.started_at,
            finished_at=datetime.now(UTC).isoformat(timespec="seconds"),
            rejected=job.rejected,
            interrupted=engine.interrupted,
            not_run=[t.url for t in job.targets if t.url not in finished],
        )
        write_summary(job.summary, job.run_dir)
        job.status = "interrupted" if engine.interrupted else "completed"
        job.publish({"type": "done", "status": job.status})

    def cancel(self, job_id: str) -> bool:
        job = self.jobs.get(job_id)
        if job and job.task and not job.task.done():
            job.task.cancel()
            return True
        return False

    def load_summary(self, job_id: str) -> dict | None:
        """Read a finished run's summary from disk, for a job no longer in memory."""
        path = self.reports_root / job_id / "summary.json"
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def history(self) -> list[dict]:
        if not self.reports_root.is_dir():
            return []
        runs = []
        for entry in self.reports_root.iterdir():
            summary = self.load_summary(entry.name) if entry.is_dir() else None
            if summary is None:
                continue
            runs.append(
                {
                    "id": entry.name,
                    "finished_at": summary.get("finished_at"),
                    "started_at": summary.get("started_at"),
                    "sites": summary.get("sites_audited"),
                    "average_score": summary.get("average_score"),
                    "interrupted": summary.get("interrupted"),
                    "severity_totals": summary.get("severity_totals", {}),
                }
            )
        runs.sort(key=lambda run: run["id"], reverse=True)
        return runs
