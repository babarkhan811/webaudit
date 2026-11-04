"""The worker pool: runs each site's checks with hard time limits."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from webaudit.checks import CheckSpec
from webaudit.config import AuditConfig
from webaudit.context import CheckSkipped, SiteContext, build_client, verifying_context
from webaudit.models import CheckResult, SiteReport
from webaudit.targets import Target

CANCEL_GRACE_S = 5.0


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


async def _run_check(spec: CheckSpec, ctx: SiteContext, result: CheckResult) -> None:
    """Run one check. Whatever goes wrong stays recorded in its own result."""
    started = time.perf_counter()
    try:
        async with asyncio.timeout(ctx.config.check_timeout):
            await spec.run(ctx, result)
    except CheckSkipped as exc:
        result.status = "skipped"
        result.error = str(exc)
    except TimeoutError:
        result.status = "timeout"
        result.error = f"exceeded {ctx.config.check_timeout:g}s check timeout"
    except asyncio.CancelledError:
        result.status = "timeout"
        result.error = "stopped by the site deadline"
        raise
    except Exception as exc:  # a bug in one check must not end the site's audit
        result.status = "error"
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        result.duration_s = round(time.perf_counter() - started, 3)


async def audit_site(
    target: Target, config: AuditConfig, checks: Sequence[CheckSpec]
) -> SiteReport:
    report = SiteReport(target=target.raw, url=target.url, started_at=_now())
    started = time.perf_counter()
    async with build_client(config) as client:
        ctx = SiteContext(target, config, client)
        report.checks = {spec.name: CheckResult(spec.name) for spec in checks}
        tasks = [
            asyncio.create_task(_run_check(spec, ctx, report.checks[spec.name]))
            for spec in checks
        ]
        try:
            _, pending = await asyncio.wait(tasks, timeout=config.site_timeout)
        finally:
            for task in tasks:
                task.cancel()
        if pending:
            await asyncio.wait(pending, timeout=CANCEL_GRACE_S)

    home = ctx.home_result
    if home is not None:
        report.reachable = home.response is not None
        report.final_url = home.response.url if home.response else None
    report.finished_at = _now()
    report.duration_s = round(time.perf_counter() - started, 3)
    report.finalize()
    return report


class Engine:
    """Drains a queue of targets with a fixed number of workers."""

    def __init__(
        self,
        config: AuditConfig,
        checks: Sequence[CheckSpec],
        on_start: Callable[[Target], None] = lambda target: None,
        on_finish: Callable[[Target, SiteReport], None] = lambda target, report: None,
    ):
        self.config = config
        self.checks = checks
        self.on_start = on_start
        self.on_finish = on_finish
        self.interrupted = False

    async def run(self, targets: Sequence[Target]) -> list[SiteReport]:
        queue: asyncio.Queue[Target] = asyncio.Queue()
        for target in targets:
            queue.put_nowait(target)

        # Slow blocking work: do it in a thread before any site's timers are running.
        await asyncio.gather(
            asyncio.to_thread(verifying_context),
            asyncio.to_thread(verifying_context, self.config.ca_bundle),
        )

        reports: list[SiteReport] = []
        workers = [
            asyncio.create_task(self._worker(queue, reports))
            for _ in range(min(self.config.concurrency, len(targets)))
        ]
        try:
            await asyncio.gather(*workers)
        except asyncio.CancelledError:
            # Ctrl-C: stop the in-flight sites and keep everything already finished.
            self.interrupted = True
            for worker in workers:
                worker.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            asyncio.current_task().uncancel()
        return reports

    async def _worker(
        self, queue: asyncio.Queue[Target], reports: list[SiteReport]
    ) -> None:
        # The queue is filled before workers start, so an empty queue means done
        # and no worker can block forever waiting for more.
        while True:
            try:
                target = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            self.on_start(target)
            try:
                report = await audit_site(target, self.config, self.checks)
            except Exception as exc:
                report = SiteReport(
                    target=target.raw,
                    url=target.url,
                    started_at=_now(),
                    finished_at=_now(),
                    status="failed",
                    error=f"{type(exc).__name__}: {exc}",
                )
                report.finalize()
            reports.append(report)
            self.on_finish(target, report)
