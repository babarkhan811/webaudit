"""Parse and normalise the list of sites to audit."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

_HOSTNAME = re.compile(r"^[a-z0-9_]([a-z0-9_.-]*[a-z0-9])?$")


class InvalidTarget(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    raw: str
    url: str
    scheme: str
    host: str
    port: int
    explicit_scheme: bool

    @property
    def is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            return False
        return True

    @property
    def default_port(self) -> bool:
        return self.port == (443 if self.scheme == "https" else 80)


def parse_target(line: str) -> Target:
    raw = line.strip()
    explicit = "://" in raw
    try:
        parts = urlsplit(raw if explicit else f"https://{raw}")
        port = parts.port
        host = parts.hostname or ""
    except ValueError as exc:
        raise InvalidTarget(f"{raw!r}: {exc}") from exc

    if parts.scheme not in ("http", "https"):
        raise InvalidTarget(f"{raw!r}: only http and https are supported")
    if parts.username or parts.password:
        raise InvalidTarget(f"{raw!r}: credentials in URLs are not allowed")

    host = _normalise_host(raw, host)
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    url = f"{parts.scheme}://{netloc}{parts.path or '/'}"
    if parts.query:
        url += f"?{parts.query}"

    return Target(
        raw=raw,
        url=url,
        scheme=parts.scheme,
        host=host,
        port=port or (443 if parts.scheme == "https" else 80),
        explicit_scheme=explicit,
    )


def _normalise_host(raw: str, host: str) -> str:
    if ":" in host:
        try:
            return str(ipaddress.IPv6Address(host))
        except ValueError as exc:
            raise InvalidTarget(f"{raw!r}: invalid IPv6 address") from exc
    try:
        host = host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise InvalidTarget(f"{raw!r}: invalid hostname") from exc
    # This also keeps option-like values away from the traceroute command line.
    if not _HOSTNAME.match(host):
        raise InvalidTarget(f"{raw!r}: invalid hostname")
    return host


def parse_lines(lines: list[str]) -> tuple[list[Target], list[str]]:
    """Return unique valid targets plus a message for each rejected line."""
    targets: dict[str, Target] = {}
    rejected: list[str] = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            target = parse_target(line)
        except InvalidTarget as exc:
            rejected.append(str(exc))
        else:
            targets.setdefault(target.url, target)
    return list(targets.values()), rejected


def load_targets(path: Path) -> tuple[list[Target], list[str]]:
    return parse_lines(path.read_text(encoding="utf-8-sig").splitlines())
