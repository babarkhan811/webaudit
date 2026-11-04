"""Crawl a few same-origin pages and verify the links and resources they use."""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlsplit

from webaudit.checks.base import register
from webaudit.context import NETWORK_ERRORS, BlockedRequest, SiteContext
from webaudit.models import CheckResult, Severity

# Often returned to bots for links that work fine in a browser.
UNVERIFIABLE_CODES = {401, 403, 405, 429, 999}
SAMPLE_SIZE = 10

_ATTRIBUTES = {
    "a": ("href", "link"),
    "area": ("href", "link"),
    "img": ("src", "image"),
    "script": ("src", "script"),
    "iframe": ("src", "frame"),
}


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base: str | None = None
        self.found: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "base" and self.base is None:
            self.base = values.get("href")
        elif tag == "link":
            rel = (values.get("rel") or "").lower().split()
            if values.get("href") and ("stylesheet" in rel or "icon" in rel):
                self.found.append((values["href"], "stylesheet"))
        elif tag in _ATTRIBUTES:
            attribute, kind = _ATTRIBUTES[tag]
            if values.get(attribute):
                self.found.append((values[attribute], kind))


def extract_links(html: str, page_url: str) -> list[tuple[str, str]]:
    """Return absolute http(s) URLs with their kind, without fragments."""
    parser = _LinkExtractor()
    parser.feed(html)
    base = urljoin(page_url, parser.base) if parser.base else page_url

    links = []
    for raw, kind in parser.found:
        try:
            url = urldefrag(urljoin(base, raw.strip())).url
            if urlsplit(url).scheme in ("http", "https"):
                links.append((url, kind))
        except ValueError:
            continue
    return links


@dataclass
class _Link:
    url: str
    kind: str
    source: str
    internal: bool


def _origin(url: str) -> tuple[str, str]:
    parts = urlsplit(url)
    return parts.scheme, parts.netloc


async def _crawl(ctx: SiteContext, first_response) -> tuple[dict[str, _Link], int]:
    origin = _origin(first_response.url)
    found: dict[str, _Link] = {}
    seen = {first_response.url}
    queue: deque = deque([first_response])
    crawled = 0

    while queue and crawled < ctx.config.max_pages:
        page = queue.popleft()
        crawled += 1  # counted before the type check so PDFs etc. use up the budget
        if isinstance(page, str):
            try:
                page = await ctx.request(page)
            except (*NETWORK_ERRORS, BlockedRequest):
                continue
        content_type = page.headers.get("content-type", "")
        if page.status != 200 or "html" not in content_type.lower():
            continue
        for url, kind in extract_links(page.text, page.url):
            internal = _origin(url) == origin
            found.setdefault(url, _Link(url, kind, page.url, internal))
            if kind == "link" and internal and url not in seen:
                seen.add(url)
                queue.append(url)
    return found, crawled


async def _probe(ctx: SiteContext, url: str) -> tuple[int | None, str | None]:
    """Return (status, error). Blocked links come back as (None, 'blocked')."""
    status = None
    try:
        for method in ("HEAD", "GET"):  # plenty of servers mishandle HEAD
            status = (await ctx.request(url, method=method, max_bytes=1)).status
            if status < 400:
                break
    except BlockedRequest:
        return None, "blocked"
    except NETWORK_ERRORS as exc:
        if status is None:
            return None, type(exc).__name__
    return status, None


def _report(result: CheckResult, severity, title, detail, items: list[dict]) -> None:
    if items:
        evidence = [
            f"{i['url']} ({i['status'] or i['error']}) on {i['source']}"
            for i in items[:SAMPLE_SIZE]
        ]
        result.add(
            severity,
            title,
            f"{len(items)} found. {detail}",
            "Fix or remove these references.",
            evidence,
        )


@register("links", "Broken links and resources across a small same-origin crawl")
async def run(ctx: SiteContext, result: CheckResult) -> None:
    home = await ctx.require_home()
    found, crawled = await _crawl(ctx, home.response)

    # Internal links go first so that the cap drops external ones.
    links = sorted(found.values(), key=lambda link: not link.internal)
    to_check = links[: ctx.config.max_links]
    outcomes = await asyncio.gather(*(_probe(ctx, link.url) for link in to_check))

    broken, unverified, blocked = [], [], []
    for link, (status, error) in zip(to_check, outcomes):
        item = {
            "url": link.url,
            "kind": link.kind,
            "source": link.source,
            "internal": link.internal,
            "status": status,
            "error": error,
        }
        if error == "blocked":
            blocked.append(item)
        elif status in UNVERIFIABLE_CODES:
            unverified.append(item)
        elif error or status >= 400:
            broken.append(item)

    result.data.update(
        pages_crawled=crawled,
        links_found=len(found),
        links_checked=len(to_check),
        broken=broken,
        unverified=unverified,
        blocked_internal=blocked,
    )

    resources = [i for i in broken if i["kind"] != "link"]
    pages = [i for i in broken if i["kind"] == "link"]
    _report(
        result,
        Severity.MEDIUM,
        "Broken page resources",
        "Images, scripts, stylesheets or frames failed to load.",
        resources,
    )
    _report(
        result,
        Severity.MEDIUM,
        "Broken internal links",
        "Links within the site lead nowhere.",
        [i for i in pages if i["internal"]],
    )
    _report(
        result,
        Severity.LOW,
        "Broken external links",
        "Links to other sites failed.",
        [i for i in pages if not i["internal"]],
    )
    _report(
        result,
        Severity.MEDIUM,
        "Links to private network addresses",
        "A public page references non-public hosts. These were not requested.",
        blocked,
    )
