"""Data structures that flow from checks into reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER = list(Severity)
PENALTY = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 15,
    Severity.MEDIUM: 6,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


@dataclass
class Finding:
    check: str
    severity: Severity
    title: str
    detail: str = ""
    recommendation: str = ""
    evidence: list[str] = field(default_factory=list)


@dataclass
class CheckResult:
    name: str
    status: str = "ok"  # ok | skipped | timeout | error
    duration_s: float = 0.0
    error: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    def add(
        self,
        severity: Severity,
        title: str,
        detail: str = "",
        recommendation: str = "",
        evidence: list[str] | None = None,
    ) -> None:
        self.findings.append(
            Finding(self.name, severity, title, detail, recommendation, evidence or [])
        )


@dataclass
class SiteReport:
    target: str
    url: str
    started_at: str
    finished_at: str = ""
    duration_s: float = 0.0
    status: str = "completed"  # completed | partial | unreachable | failed
    reachable: bool | None = None  # None when no selected check fetched the site
    final_url: str | None = None
    error: str | None = None
    score: int | None = None
    grade: str = "-"
    severity_counts: dict[str, int] = field(default_factory=dict)
    report_file: str = ""
    checks: dict[str, CheckResult] = field(default_factory=dict)

    @property
    def findings(self) -> list[Finding]:
        found = [f for check in self.checks.values() for f in check.findings]
        return sorted(found, key=lambda f: SEVERITY_ORDER.index(f.severity))

    def finalize(self) -> None:
        """Derive status, counts and score once all checks have ended."""
        findings = self.findings
        self.severity_counts = {
            s.value: sum(f.severity == s for f in findings) for s in Severity
        }
        if self.status == "failed":
            return
        if self.reachable is False:
            self.status = "unreachable"
        elif any(c.status in ("timeout", "error") for c in self.checks.values()):
            self.status = "partial"

        score = max(0, 100 - sum(PENALTY[f.severity] for f in findings))
        if self.severity_counts[Severity.CRITICAL]:
            score = min(score, 49)  # one critical issue always fails the site
        self.score = score
        self.grade = next(
            g for floor, g in ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F"))
            if score >= floor
        )

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["findings"] = [asdict(f) for f in self.findings]
        return result
