"""Helpers shared by the DNS and WHOIS checks."""

from __future__ import annotations

import tldextract

# An empty URL list means the bundled public suffix snapshot: no network, no cache.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def registrable_domain(host: str) -> str | None:
    """Return example.co.uk for www.example.co.uk, or None for e.g. localhost."""
    parts = _extract(host)
    if not parts.domain or not parts.suffix:
        return None
    return f"{parts.domain}.{parts.suffix}"
