"""Start the dashboard server and open it in the browser."""

from __future__ import annotations

import secrets
import socket
import threading
import webbrowser
from pathlib import Path

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _free_port(host: str, port: int) -> int:
    """Return the chosen port, or the next free one if it is taken."""
    for candidate in range(port, port + 40):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host if host != "localhost" else "127.0.0.1", candidate))
                return candidate
            except OSError:
                continue
    return port


def run_gui(
    reports_root: Path = Path("reports"),
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = True,
) -> None:
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise SystemExit(
            "The dashboard needs extra packages. Install them with:\n"
            '    pip install -e "."'
        ) from exc

    from webaudit.web.app import create_app

    token = secrets.token_urlsafe(24)
    app = create_app(reports_root, token)
    port = _free_port(host, port)
    url = f"http://{host}:{port}/?token={token}"

    print(f"\n  webaudit dashboard  ->  {url}\n")
    if host not in LOCAL_HOSTS:
        print(
            "  WARNING: binding to a non-local address exposes this dashboard, and\n"
            "  anyone who reaches it can make this tool scan arbitrary hosts.\n"
        )
    print("  Keep this window open while you work. Press Ctrl+C to stop.\n")

    if open_browser:
        threading.Timer(0.7, lambda: webbrowser.open(url)).start()

    uvicorn.run(app, host=host, port=port, log_level="warning")
