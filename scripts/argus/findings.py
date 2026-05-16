"""Normalized finding model for argus-audit."""

from __future__ import annotations

import dataclasses
import enum
import time
from typing import Iterable


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_cvss(cls, score: float | None) -> "Severity":
        if score is None:
            return cls.INFO
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


@dataclasses.dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    surface: str
    target: str
    location: str = ""
    evidence: str = ""
    remediation: str = ""
    references: tuple[str, ...] = ()
    cvss: float | None = None
    epss: float | None = None
    kev: bool = False
    cwe: str = ""
    discovered_at: int = dataclasses.field(default_factory=lambda: int(time.time()))

    def rank(self) -> tuple[int, int, float]:
        """Sort key — higher tuple sorts later.

        Order: severity → KEV (known-exploited beats theoretical) → EPSS.
        Previously KEV was the last tie-breaker which buried in-the-wild
        exploits behind slightly-higher-EPSS-but-not-exploited CVEs.
        """
        return (int(self.severity), 1 if self.kev else 0, float(self.epss or 0.0))

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.name,
            "surface": self.surface,
            "target": self.target,
            "location": self.location,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": list(self.references),
            "cvss": self.cvss,
            "epss": self.epss,
            "kev": self.kev,
            "cwe": self.cwe,
            "discovered_at": self.discovered_at,
        }


@dataclasses.dataclass
class FindingSet:
    findings: list[Finding] = dataclasses.field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, batch: Iterable[Finding]) -> None:
        for f in batch:
            self.findings.append(f)

    def sorted(self) -> list[Finding]:
        return sorted(self.findings, key=Finding.rank, reverse=True)

    def by_severity(self, sev: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == sev]

    def by_surface(self, surface: str) -> list[Finding]:
        return [f for f in self.findings if f.surface == surface]

    def worst(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)

    def summary(self) -> dict[str, int]:
        out = {sev.name: 0 for sev in Severity}
        for f in self.findings:
            out[f.severity.name] += 1
        return out
