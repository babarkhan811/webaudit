"""Run-wide settings shared by the engine and every check."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from webaudit import __version__


@dataclass(frozen=True)
class AuditConfig:
    concurrency: int = 3  # sites audited at the same time
    request_timeout: float = 10.0  # per connect/read phase of one HTTP request
    check_timeout: float = 90.0  # wall-clock budget for one check
    site_timeout: float = 180.0  # wall-clock budget for one site
    retries: int = 1  # extra attempts for the homepage fetch
    per_site_requests: int = 5  # simultaneous HTTP requests to one site
    delay: float = 0.0  # pause before each request, in seconds
    max_pages: int = 5  # same-origin pages crawled for links
    max_links: int = 100  # unique links verified per site
    max_redirects: int = 10
    max_body_bytes: int = 2_000_000
    ca_bundle: Path | None = None  # extra CA file for private PKI
    user_agent: str = f"webaudit/{__version__} (website health monitor)"

    @property
    def request_deadline(self) -> float:
        """Total time for one request; httpx timeouts alone allow a slow drip forever."""
        return self.request_timeout * 2
