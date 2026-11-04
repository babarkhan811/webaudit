"""The check registry. Adding a check means adding one decorated function."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from webaudit.context import SiteContext
from webaudit.models import CheckResult

CheckFn = Callable[[SiteContext, CheckResult], Awaitable[None]]


@dataclass(frozen=True)
class CheckSpec:
    name: str
    description: str
    run: CheckFn
    default: bool = True


REGISTRY: dict[str, CheckSpec] = {}


def register(name: str, description: str, default: bool = True):
    def decorate(fn: CheckFn) -> CheckFn:
        REGISTRY[name] = CheckSpec(name, description, fn, default)
        return fn

    return decorate
