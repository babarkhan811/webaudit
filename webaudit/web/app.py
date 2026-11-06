"""The dashboard's ASGI application: static page plus a small JSON/SSE API."""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import AsyncIterator
from pathlib import Path

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import (
    FileResponse,
    JSONResponse,
    PlainTextResponse,
    StreamingResponse,
)
from starlette.routing import Route

from webaudit import __version__
from webaudit.checks import REGISTRY, select_checks
from webaudit.config import AuditConfig
from webaudit.targets import parse_lines
from webaudit.web.runner import TERMINAL, ScanManager

STATIC = Path(__file__).parent / "static"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
# Run folders are named by timestamp; this keeps an id from escaping the reports dir.
JOB_ID = re.compile(r"^\d{8}-\d{6}(?:-\d+)?$")


class Guard:
    """Reject non-local hosts and API calls without the session token.

    The dashboard can make the tool fetch arbitrary URLs, so it must not be drivable
    by another site in the browser or by another machine. The token is handed out only
    in the URL webaudit opens, and the host check blocks DNS-rebinding attempts.
    """

    def __init__(self, app, token: str):
        self.app = app
        self.token = token

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        host = headers.get(b"host", b"").decode("latin1").split(":")[0]
        if host not in LOCAL_HOSTS:
            await PlainTextResponse("Host not allowed", 403)(scope, receive, send)
            return
        if scope["path"].startswith("/api"):
            token = headers.get(b"x-auth-token", b"").decode("latin1")
            if not token:
                request = Request(scope, receive)
                token = request.query_params.get("token", "")
            if not secrets.compare_digest(token, self.token):
                await PlainTextResponse("Forbidden", 403)(scope, receive, send)
                return
        await self.app(scope, receive, send)


def _clamp(options: dict, key: str, default, low, high, cast):
    try:
        value = cast(options.get(key, default))
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


def config_from_options(options: dict) -> AuditConfig:
    """Build a config from browser input, clamping every value to a sane range."""
    return AuditConfig(
        concurrency=_clamp(options, "concurrency", 3, 1, 50, int),
        request_timeout=_clamp(options, "timeout", 10.0, 1.0, 120.0, float),
        site_timeout=_clamp(options, "site_timeout", 180.0, 5.0, 1800.0, float),
        check_timeout=_clamp(options, "check_timeout", 90.0, 5.0, 1800.0, float),
        per_site_requests=_clamp(options, "per_site_requests", 5, 1, 20, int),
        delay=_clamp(options, "delay", 0.0, 0.0, 10.0, float),
        max_pages=_clamp(options, "max_pages", 5, 1, 50, int),
        max_links=_clamp(options, "max_links", 100, 1, 1000, int),
    )


async def index(request: Request) -> FileResponse:
    return FileResponse(STATIC / "index.html")


async def static_file(request: Request):
    name = request.path_params["name"]
    target = (STATIC / name).resolve()
    if target.parent != STATIC.resolve() or not target.is_file():
        return PlainTextResponse("Not found", 404)
    return FileResponse(target)


async def meta(request: Request) -> JSONResponse:
    return JSONResponse(
        {
            "version": __version__,
            "checks": [
                {"name": s.name, "description": s.description, "default": s.default}
                for s in REGISTRY.values()
            ],
        }
    )


async def start_scan(request: Request) -> JSONResponse:
    manager: ScanManager = request.app.state.manager
    try:
        body = await request.json()
    except (json.JSONDecodeError, ValueError):
        return JSONResponse({"error": "invalid JSON body"}, 400)

    raw = body.get("targets", [])
    lines = raw.splitlines() if isinstance(raw, str) else list(raw)
    targets, rejected = parse_lines(lines)

    names = body.get("checks") or []
    if not names:
        return JSONResponse({"error": "No checks selected."}, 400)
    try:
        checks = select_checks(only=names, traceroute="traceroute" in names)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, 400)
    if not targets:
        return JSONResponse({"error": "No valid targets.", "rejected": rejected}, 400)

    config = config_from_options(body.get("options") or {})
    job = manager.start(targets, rejected, config, checks)
    return JSONResponse({"id": job.id, "total": job.total, "rejected": rejected})


def _valid_id(job_id: str) -> bool:
    return bool(JOB_ID.match(job_id))


async def get_scan(request: Request) -> JSONResponse:
    manager: ScanManager = request.app.state.manager
    job_id = request.path_params["job_id"]
    if not _valid_id(job_id):
        return JSONResponse({"error": "not found"}, 404)
    job = manager.jobs.get(job_id)
    if job is not None:
        return JSONResponse(job.state())
    summary = manager.load_summary(job_id)
    if summary is None:
        return JSONResponse({"error": "not found"}, 404)
    status = "interrupted" if summary.get("interrupted") else "completed"
    return JSONResponse(
        {
            "id": job_id,
            "status": status,
            "total": summary.get("sites_audited"),
            "completed": summary.get("sites_audited"),
            "rows": summary.get("sites", []),
            "rejected": summary.get("rejected_targets", []),
            "error": None,
            "summary": summary,
        }
    )


async def cancel_scan(request: Request) -> JSONResponse:
    manager: ScanManager = request.app.state.manager
    cancelled = manager.cancel(request.path_params["job_id"])
    return JSONResponse({"cancelled": cancelled})


async def history(request: Request) -> JSONResponse:
    manager: ScanManager = request.app.state.manager
    return JSONResponse({"runs": manager.history()})


async def report_html(request: Request):
    manager: ScanManager = request.app.state.manager
    job_id = request.path_params["job_id"]
    if not _valid_id(job_id):
        return PlainTextResponse("Not found", 404)
    path = manager.reports_root / job_id / "summary.html"
    if not path.is_file():
        return PlainTextResponse("Not found", 404)
    return FileResponse(path)


def _sse(event: dict) -> str:
    return f"data: {json.dumps(event)}\n\n"


async def scan_events(request: Request):
    manager: ScanManager = request.app.state.manager
    job_id = request.path_params["job_id"]
    job = manager.jobs.get(job_id)
    if job is None:
        return PlainTextResponse("Not found", 404)

    async def stream() -> AsyncIterator[str]:
        yield _sse(
            {
                "type": "init",
                "status": job.status,
                "total": job.total,
                "completed": len(job.rows),
                "rows": job.rows,
            }
        )
        if job.status in TERMINAL:
            yield _sse({"type": "done", "status": job.status})
            return
        queue = job.subscribe()
        try:
            while True:
                event = await queue.get()
                yield _sse(event)
                if event["type"] in ("done", "error"):
                    break
        finally:
            job.unsubscribe(queue)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def create_app(reports_root: Path, token: str) -> Starlette:
    reports_root = Path(reports_root)
    reports_root.mkdir(parents=True, exist_ok=True)
    routes = [
        Route("/", index),
        Route("/static/{name}", static_file),
        Route("/api/meta", meta),
        Route("/api/scans", start_scan, methods=["POST"]),
        Route("/api/scans", history, methods=["GET"]),
        Route("/api/scans/{job_id}", get_scan),
        Route("/api/scans/{job_id}/cancel", cancel_scan, methods=["POST"]),
        Route("/api/scans/{job_id}/events", scan_events),
        Route("/api/scans/{job_id}/report", report_html),
    ]
    app = Starlette(routes=routes, middleware=[Middleware(Guard, token=token)])
    app.state.manager = ScanManager(reports_root)
    app.state.token = token
    return app
