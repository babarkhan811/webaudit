import asyncio
import time

from conftest import audit
from webaudit.checks import REGISTRY, select_checks
from webaudit.checks.base import CheckSpec
from webaudit.config import AuditConfig
from webaudit.context import verifying_context
from webaudit.engine import Engine, audit_site
from webaudit.models import Severity
from webaudit.targets import parse_target


def _targets(count):
    return [parse_target(f"http://site-{i}.invalid/") for i in range(count)]


def test_concurrency_limit_is_respected_and_every_site_finishes():
    active = 0
    peak = 0

    async def probe(ctx, result):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.02)
        active -= 1

    engine = Engine(AuditConfig(concurrency=3), [CheckSpec("probe", "", probe)])
    reports = asyncio.run(engine.run(_targets(20)))
    assert len(reports) == 20
    assert peak == 3


def test_one_site_at_a_time_runs_sequentially():
    active = 0
    peak = 0

    async def probe(ctx, result):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1

    engine = Engine(AuditConfig(concurrency=1), [CheckSpec("probe", "", probe)])
    assert len(asyncio.run(engine.run(_targets(5)))) == 5
    assert peak == 1


def test_more_workers_than_sites():
    async def probe(ctx, result):
        pass

    engine = Engine(AuditConfig(concurrency=50), [CheckSpec("probe", "", probe)])
    assert len(asyncio.run(engine.run(_targets(2)))) == 2


def test_crashing_check_does_not_affect_other_checks():
    async def crash(ctx, result):
        raise RuntimeError("boom")

    async def healthy(ctx, result):
        result.add(Severity.LOW, "still ran")

    checks = [CheckSpec("crash", "", crash), CheckSpec("healthy", "", healthy)]
    report = asyncio.run(audit_site(_targets(1)[0], AuditConfig(), checks))
    assert report.status == "partial"
    assert report.checks["crash"].status == "error"
    assert "boom" in report.checks["crash"].error
    assert report.checks["healthy"].status == "ok"
    assert report.findings[0].title == "still ran"


def test_check_timeout_keeps_partial_data():
    async def stuck(ctx, result):
        result.data["progress"] = "halfway"
        await asyncio.sleep(60)

    config = AuditConfig(check_timeout=0.1)
    report = asyncio.run(audit_site(_targets(1)[0], config, [CheckSpec("stuck", "", stuck)]))
    assert report.status == "partial"
    assert report.checks["stuck"].status == "timeout"
    assert report.checks["stuck"].data == {"progress": "halfway"}


def test_site_deadline_stops_checks_that_outlast_it():
    async def stuck(ctx, result):
        await asyncio.sleep(60)

    config = AuditConfig(check_timeout=60, site_timeout=0.1)
    started = time.perf_counter()
    report = asyncio.run(audit_site(_targets(1)[0], config, [CheckSpec("stuck", "", stuck)]))
    assert time.perf_counter() - started < 2
    assert report.checks["stuck"].status == "timeout"
    assert report.checks["stuck"].error == "stopped by the site deadline"


def test_server_that_never_answers_cannot_hang_the_run(hanging_url):
    started = time.perf_counter()
    report = audit(
        hanging_url,
        ["routing", "headers", "links", "exposure"],
        request_timeout=0.2,
        site_timeout=5,
    )
    assert time.perf_counter() - started < 5
    assert report.status == "unreachable"
    assert report.reachable is False


def test_hanging_site_does_not_block_healthy_sites(hanging_url, make_site):
    healthy = [make_site({"/": (200, [], b"ok")}) for _ in range(3)]
    targets = [parse_target(hanging_url)] + [parse_target(s.url) for s in healthy]
    config = AuditConfig(concurrency=2, request_timeout=0.2, retries=0)
    reports = asyncio.run(Engine(config, select_checks(["routing"])).run(targets))
    assert sorted(r.status for r in reports) == ["completed"] * 3 + ["unreachable"]


def test_interrupt_keeps_finished_sites():
    async def maybe_stuck(ctx, result):
        if ctx.target.host != "site-0.invalid":
            await asyncio.sleep(60)

    async def scenario():
        engine = Engine(
            AuditConfig(concurrency=1), [CheckSpec("check", "", maybe_stuck)]
        )
        task = asyncio.create_task(engine.run(_targets(3)))
        await asyncio.sleep(0.2)
        task.cancel()
        return engine, await task

    engine, reports = asyncio.run(scenario())
    assert engine.interrupted is True
    assert [r.url for r in reports] == ["http://site-0.invalid/"]


def test_failing_finish_callback_path_reports_failed_site(monkeypatch):
    async def explode(*args):
        raise RuntimeError("client setup failed")

    monkeypatch.setattr("webaudit.engine.audit_site", explode)
    reports = asyncio.run(Engine(AuditConfig(), []).run(_targets(2)))
    assert [r.status for r in reports] == ["failed", "failed"]
    assert reports[0].grade == "-"


def test_check_selection():
    defaults = {spec.name for spec in select_checks()}
    assert defaults == set(REGISTRY) - {"traceroute"}
    assert {s.name for s in select_checks(traceroute=True)} == set(REGISTRY)
    assert [s.name for s in select_checks(only=["tls"])] == ["tls"]
    assert "exposure" not in {s.name for s in select_checks(skip=["exposure"])}


def test_tls_checks_do_not_stall_the_event_loop(make_site):
    """Stalls expire other sites' deadlines and report healthy sites as down."""
    verifying_context.cache_clear()
    sites = [make_site({"/": (200, [], b"ok")}) for _ in range(6)]
    targets = [parse_target(site.url) for site in sites]
    worst_lag = 0.0

    async def measure_lag():
        nonlocal worst_lag
        while True:
            started = time.perf_counter()
            await asyncio.sleep(0.01)
            worst_lag = max(worst_lag, time.perf_counter() - started - 0.01)

    async def scenario():
        monitor = asyncio.create_task(measure_lag())
        config = AuditConfig(concurrency=3, retries=0)
        reports = await Engine(config, select_checks(["tls", "routing"])).run(targets)
        monitor.cancel()
        return reports

    reports = asyncio.run(scenario())
    assert [r.status for r in reports] == ["completed"] * 6
    assert worst_lag < 0.5
