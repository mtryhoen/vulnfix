"""Unified data model for security findings across all scanners.

Every scanner adapter normalizes its output to ``Finding`` objects so the
downstream orchestrator and fixers don't have to know which tool produced
what.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        if not value:
            return cls.UNKNOWN
        v = value.strip().lower()
        mapping = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "low": cls.LOW,
            "info": cls.INFO,
            "informational": cls.INFO,
            "negligible": cls.INFO,
        }
        return mapping.get(v, cls.UNKNOWN)


class FindingKind(str, Enum):
    """What category of fix is appropriate for this finding."""
    DEPENDENCY = "dependency"         # bump a package version
    CONTAINER_BASE = "container_base" # bump a base image
    CODE = "code"                     # change source code
    SECRET = "secret"                 # rotate + scrub history
    IAC = "iac"                       # fix terraform/k8s/docker config
    UNKNOWN = "unknown"


@dataclass
class Location:
    file_path: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    snippet: Optional[str] = None


@dataclass
class FixHint:
    """Information the fixer can use. None of these are required."""
    fixed_version: Optional[str] = None     # for dependency findings
    package_name: Optional[str] = None
    package_ecosystem: Optional[str] = None # pypi, npm, maven, ...
    suggested_patch: Optional[str] = None   # diff or replacement text


@dataclass
class Finding:
    """Normalized representation of a single vulnerability finding."""
    id: str                          # stable identifier per scanner, e.g. "trivy:CVE-2024-1234:requirements.txt"
    scanner: str                     # "trivy", "bandit", "semgrep", ...
    rule_id: str                     # CVE-2024-1234, B608, ...
    title: str
    description: str
    severity: Severity
    kind: FindingKind
    location: Location = field(default_factory=Location)
    fix: FixHint = field(default_factory=FixHint)
    cwe: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)  # original scanner record for debugging

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["kind"] = self.kind.value
        return d

    @property
    def dedupe_key(self) -> str:
        """Two findings with the same key are the same vuln from different scanners.

        For dependency findings, we ignore the file path — Trivy often reports
        the same CVE against the same package twice (once for a language label
        like ``Python``, once for the lockfile). That's one finding, not two.

        For code findings, the file+line matters: the same rule firing at two
        different lines is two separate issues.
        """
        if self.fix.package_name:
            return f"{self.rule_id}|{self.fix.package_name}|{self.fix.package_ecosystem or ''}"
        loc = f"{self.location.file_path or ''}:{self.location.start_line or 0}"
        return f"{self.rule_id}|{loc}"
