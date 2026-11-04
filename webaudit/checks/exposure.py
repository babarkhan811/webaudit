"""Look for configuration and backup files that should never be public.

Each probe is one unauthenticated GET. A file only counts as exposed when its
content matches a signature, so sites that answer 200 for every path don't produce
false alarms. File contents are never stored: reports list the path and size only.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

from webaudit.checks.base import register
from webaudit.context import NETWORK_ERRORS, BlockedRequest, SiteContext
from webaudit.models import CheckResult, Severity

SAMPLE_BYTES = 4096

_ENV = re.compile(rb"^[ \t]*(?:export\s+)?[A-Z][A-Z0-9_]*[ \t]*=", re.MULTILINE)
_GIT_HEAD = re.compile(rb"^(?:ref: refs/|[0-9a-f]{40}\s*$)")
_GIT_CONFIG = re.compile(rb"^\[core\]", re.MULTILINE)
_HTPASSWD = re.compile(rb"^[^\s:]+:(?:\$apr1\$|\$2[aby]\$|\{SHA\})", re.MULTILINE)
_PHP_CONFIG = re.compile(rb"<\?php.*(?:DB_|password|database)", re.DOTALL | re.IGNORECASE)
_SQL = re.compile(rb"CREATE TABLE|INSERT INTO|MySQL dump|PostgreSQL database dump")
_COMPOSE = re.compile(rb"^(?:services|version):", re.MULTILINE)
_AWS = re.compile(rb"aws_access_key_id", re.IGNORECASE)
_NPMRC = re.compile(rb"_authToken|_password")
_SVN = re.compile(rb"^(?:\d+\s|<\?xml)")
_HG = re.compile(rb"^\[paths\]", re.MULTILINE)
_SFTP = re.compile(rb'"(?:password|privateKeyPath)"\s*:')
_DS_STORE = re.compile(rb"^\x00\x00\x00\x01Bud1")
_PHPINFO = re.compile(rb"phpinfo\(\)|PHP Version")
_SERVER_STATUS = re.compile(rb"Apache Server Status")


@dataclass(frozen=True)
class Probe:
    path: str
    title: str
    severity: Severity
    signature: re.Pattern
    allow_html: bool = False


_ENV_TITLE = "Environment file is public"
_TEMPLATE_TITLE = "Environment template is public"
_BACKUP_TITLE = "Configuration backup is public"
_DUMP_TITLE = "Database dump is public"

PROBES = [
    Probe("/.env", _ENV_TITLE, Severity.CRITICAL, _ENV),
    Probe("/.env.local", _ENV_TITLE, Severity.CRITICAL, _ENV),
    Probe("/.env.production", _ENV_TITLE, Severity.CRITICAL, _ENV),
    Probe("/.env.backup", _ENV_TITLE, Severity.CRITICAL, _ENV),
    Probe("/.env.example", _TEMPLATE_TITLE, Severity.MEDIUM, _ENV),
    Probe("/.env.sample", _TEMPLATE_TITLE, Severity.MEDIUM, _ENV),
    Probe("/.git/HEAD", "Git repository is public", Severity.CRITICAL, _GIT_HEAD),
    Probe("/.git/config", "Git repository is public", Severity.CRITICAL, _GIT_CONFIG),
    Probe("/.svn/entries", "Subversion metadata is public", Severity.HIGH, _SVN),
    Probe("/.hg/hgrc", "Mercurial metadata is public", Severity.HIGH, _HG),
    Probe("/.htpasswd", "Password file is public", Severity.CRITICAL, _HTPASSWD),
    Probe("/.aws/credentials", "AWS credentials are public", Severity.CRITICAL, _AWS),
    Probe("/.npmrc", "npm credentials are public", Severity.HIGH, _NPMRC),
    Probe("/.vscode/sftp.json", "Editor deploy settings are public", Severity.HIGH, _SFTP),
    Probe("/wp-config.php.bak", _BACKUP_TITLE, Severity.CRITICAL, _PHP_CONFIG),
    Probe("/wp-config.php~", _BACKUP_TITLE, Severity.CRITICAL, _PHP_CONFIG),
    Probe("/config.php.bak", _BACKUP_TITLE, Severity.CRITICAL, _PHP_CONFIG),
    Probe("/backup.sql", _DUMP_TITLE, Severity.CRITICAL, _SQL),
    Probe("/dump.sql", _DUMP_TITLE, Severity.CRITICAL, _SQL),
    Probe("/database.sql", _DUMP_TITLE, Severity.CRITICAL, _SQL),
    Probe("/docker-compose.yml", "Docker Compose file is public", Severity.MEDIUM, _COMPOSE),
    Probe("/.DS_Store", "macOS folder metadata is public", Severity.LOW, _DS_STORE),
    Probe("/phpinfo.php", "phpinfo page is public", Severity.HIGH, _PHPINFO, allow_html=True),
    Probe("/server-status", "Apache status page is public", Severity.MEDIUM, _SERVER_STATUS, allow_html=True),
]


def _looks_like_html(body: bytes) -> bool:
    return body.lstrip()[:15].lower().startswith((b"<!doctype", b"<html"))


def matches(probe: Probe, body: bytes) -> bool:
    if not probe.allow_html and _looks_like_html(body):
        return False
    return probe.signature.search(body) is not None


async def _run_probe(ctx: SiteContext, origin: str, probe: Probe) -> dict | None:
    """Return a record for an exposed file, or None. The body is dropped here."""
    response = await ctx.request(origin + probe.path, max_bytes=SAMPLE_BYTES)
    if response.status != 200 or not matches(probe, response.body):
        return None
    return {
        "path": probe.path,
        "url": origin + probe.path,
        "title": probe.title,
        "severity": probe.severity,
        "bytes_sampled": len(response.body),
    }


@register("exposure", "Public .env, .git, backup and admin files (contents never stored)")
async def run(ctx: SiteContext, result: CheckResult) -> None:
    home = await ctx.require_home()
    parts = urlsplit(home.response.url)
    origin = f"{parts.scheme}://{parts.netloc}"

    soft_404 = None
    try:
        baseline = await ctx.request(f"{origin}/{uuid.uuid4().hex}", max_bytes=1)
        soft_404 = baseline.status == 200
    except (*NETWORK_ERRORS, BlockedRequest):
        pass

    outcomes = await asyncio.gather(
        *(_run_probe(ctx, origin, probe) for probe in PROBES),
        return_exceptions=True,
    )
    failed = [o for o in outcomes if isinstance(o, Exception)]
    exposed = [o for o in outcomes if isinstance(o, dict)]

    result.data.update(
        origin=origin,
        paths_probed=len(PROBES),
        probes_failed=len(failed),
        soft_404=soft_404,
        exposed=exposed,
    )
    for item in exposed:
        result.add(
            item["severity"],
            item["title"],
            f"{item['path']} is publicly readable. Its contents were not stored.",
            "Remove the file or block it at the web server. Rotate any secrets it held.",
            [item["url"]],
        )
    if failed:
        result.add(
            Severity.INFO,
            "Some exposure probes failed",
            f"{len(failed)} of {len(PROBES)} requests got no answer, so coverage is incomplete.",
        )
