"""Shared types for ThreatLens analysis reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_WEIGHTS = {
    Severity.INFO: 0,
    Severity.LOW: 4,
    Severity.MEDIUM: 10,
    Severity.HIGH: 20,
    Severity.CRITICAL: 35,
}


@dataclass(frozen=True)
class Finding:
    """A traceable, non-executable indicator from a local analysis."""

    id: str
    category: str
    severity: Severity
    title: str
    evidence: str
    recommendation: str
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["references"] = list(self.references)
        return data


@dataclass
class AnalysisReport:
    """Self-contained report suitable for local history and exports."""

    target: str
    target_type: str
    analyzed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    analysis_limits: list[str] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        unique = {(finding.id, finding.category, finding.severity) for finding in self.findings}
        raw = sum(SEVERITY_WEIGHTS[severity] for _, _, severity in unique)
        return min(100, raw)

    @property
    def risk_level(self) -> str:
        score = self.risk_score
        if score >= 70:
            return "critical"
        if score >= 40:
            return "high"
        if score >= 15:
            return "medium"
        return "low"

    @property
    def category_summary(self) -> dict[str, int]:
        summary: dict[str, int] = {}
        for finding in self.findings:
            summary[finding.category] = summary.get(finding.category, 0) + 1
        return dict(sorted(summary.items()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "analyzed_at": self.analyzed_at,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "metadata": self.metadata,
            "summary": self.category_summary,
            "findings": [finding.to_dict() for finding in self.findings],
            "analysis_limits": self.analysis_limits,
        }
