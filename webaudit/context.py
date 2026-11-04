"""Per-site state: throttled HTTP, the internal-network guard and the homepage cache."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import certifi
import httpx

from webaudit.config import AuditConfig
from webaudit.targets import Target

# ValueError covers malformed URLs, which sites can put in links and redirects.
NETWORK_ERRORS = (
    httpx.HTTPError,
    httpx.InvalidURL,
    TimeoutError,
    OSError,
    ssl.SSLError,
    ValueError,
)
REDIRECT_CODES = {301, 302, 303, 307, 308}


class BlockedRequest(Exception):
    """A public site tried to steer the scanner at a private address."""


class CheckSkipped(Exception):
    """The check does not apply to this target."""


@dataclass
class Response:
    url: str
    status: int
    headers: httpx.Headers
    body: bytes
    truncated: bool
    elapsed_s: float

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


@dataclass
class Home:
    """Outcome of fetching the site's landing page, including every redirect hop."""

    response: Response | None = None
    hops: list[dict] = field(default_factory=list)
    error: str | None = None


@cache
def verifying_context(ca_bundle: Path | None = None) -> ssl.SSLContext:
    """The certificate-checking context, built once per run.

    Parsing the CA bundle takes over a second of blocking work. Doing that per site
    stalls the event loop long enough to push healthy sites past their deadlines.
    """
    context = ssl.create_default_context(cafile=certifi.where())
    # Browsers don't apply strict mode, so it would flag certificates that work.
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    if ca_bundle:
        context.load_verify_locations(cafile=str(ca_bundle))
    return context


@cache
def _scanning_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def build_client(config: AuditConfig) -> httpx.AsyncClient:
    # Not verifying is deliberate: a bad certificate must not stop the header and
    # link checks. The tls check validates the certificate separately.
    return httpx.AsyncClient(
        verify=_scanning_context(),
        follow_redirects=False,
        timeout=httpx.Timeout(config.request_timeout),
        headers={"User-Agent": config.user_agent},
    )


async def resolves_internal(host: str) -> bool:
    """True when host is, or resolves to, a non-public address."""
    host = host.strip("[]")
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(
                host, None, type=socket.SOCK_STREAM
            )
        except (OSError, UnicodeError):
            return False  # unresolvable: the request itself will fail
        addresses = [ipaddress.ip_address(info[4][0].split("%")[0]) for info in infos]
    return any(not _unmapped(addr).is_global for addr in addresses)


def _unmapped(addr):
    return getattr(addr, "ipv4_mapped", None) or addr


class SiteContext:
    def __init__(self, target: Target, config: AuditConfig, client: httpx.AsyncClient):
        self.target = target
        self.config = config
        self.client = client
        self.target_internal: bool | None = None
        self._slots = asyncio.Semaphore(config.per_site_requests)
        self._home: Home | None = None
        self._home_lock = asyncio.Lock()
        self._internal_cache: dict[str, bool] = {}

    @property
    def home_result(self) -> Home | None:
        """The homepage outcome if a check fetched it, without triggering a fetch."""
        return self._home

    async def _guard(self, url: str) -> None:
        """Stop a public site's links or redirects reaching the local network.

        Scanning an internal target on purpose stays allowed.
        """
        if self.target_internal is None:
            self.target_internal = await resolves_internal(self.target.host)
        if self.target_internal:
            return
        host = urlsplit(url).hostname or ""
        if host not in self._internal_cache:
            self._internal_cache[host] = await resolves_internal(host)
        if self._internal_cache[host]:
            raise BlockedRequest(f"{host} is a non-public address")

    async def request(
        self, url: str, *, method: str = "GET", max_bytes: int | None = None
    ) -> Response:
        """Make one request without following redirects. Bodies are size-capped."""
        await self._guard(url)
        limit = self.config.max_body_bytes if max_bytes is None else max_bytes
        async with self._slots:
            if self.config.delay:
                await asyncio.sleep(self.config.delay)
            started = time.perf_counter()
            async with asyncio.timeout(self.config.request_deadline):
                async with self.client.stream(method, url) as response:
                    body, truncated = await _read_capped(response, limit)
            return Response(
                url=str(response.url),
                status=response.status_code,
                headers=response.headers,
                body=body,
                truncated=truncated,
                elapsed_s=round(time.perf_counter() - started, 3),
            )

    async def home(self) -> Home:
        async with self._home_lock:
            if self._home is None:
                self._home = await self._load_home()
            return self._home

    async def require_home(self) -> Home:
        home = await self.home()
        if home.response is None:
            raise CheckSkipped(f"site unreachable: {home.error}")
        return home

    async def _load_home(self) -> Home:
        candidates = [self.target.url]
        if not self.target.explicit_scheme:
            candidates.append("http://" + self.target.url.removeprefix("https://"))

        error = "no response"
        for url in candidates:
            for attempt in range(self.config.retries + 1):
                try:
                    return await self._follow(url)
                except BlockedRequest as exc:
                    return Home(error=str(exc))
                except NETWORK_ERRORS as exc:
                    error = f"{type(exc).__name__}: {exc}".rstrip(": ")
                    if attempt < self.config.retries:
                        await asyncio.sleep(0.5 * (attempt + 1))
        return Home(error=error)

    async def _follow(self, url: str) -> Home:
        hops: list[dict] = []
        seen: set[str] = set()
        for _ in range(self.config.max_redirects + 1):
            if url in seen:
                return Home(hops=hops, error="redirect loop")
            seen.add(url)
            response = await self.request(url)
            location = response.headers.get("location")
            hops.append({"url": url, "status": response.status, "location": location})
            if response.status not in REDIRECT_CODES or not location:
                return Home(response, hops)
            url = urljoin(url, location)
            if urlsplit(url).scheme not in ("http", "https"):
                return Home(response, hops)
        return Home(hops=hops, error="too many redirects")


async def _read_capped(response: httpx.Response, limit: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        chunks.append(chunk)
        size += len(chunk)
        if size >= limit:
            return b"".join(chunks)[:limit], True
    return b"".join(chunks), False
