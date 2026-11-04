"""Audit checks. Importing this package registers all of them."""

from __future__ import annotations

from collections.abc import Iterable

from webaudit.checks import (  # noqa: F401  (imported for registration)
    dns_check,
    exposure,
    headers,
    links,
    routing,
    tls,
    traceroute,
    whois,
)
from webaudit.checks.base import REGISTRY, CheckSpec

__all__ = ["REGISTRY", "CheckSpec", "select_checks"]


def select_checks(
    only: Iterable[str] = (), skip: Iterable[str] = (), traceroute: bool = False
) -> list[CheckSpec]:
    """Resolve CLI selections into check specs. Raises ValueError on unknown names."""
    only, skip = set(only), set(skip)
    unknown = (only | skip) - REGISTRY.keys()
    if unknown:
        raise ValueError(f"unknown checks: {', '.join(sorted(unknown))}")

    selected = []
    for spec in REGISTRY.values():
        wanted = spec.name in only if only else spec.default
        if traceroute and spec.name == "traceroute":
            wanted = True
        if wanted and spec.name not in skip:
            selected.append(spec)
    return selected
