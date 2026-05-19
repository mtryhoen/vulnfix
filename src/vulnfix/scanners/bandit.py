"""Bandit scanner adapter (Python SAST)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from vulnfix.models.finding import (
    Finding,
    FindingKind,
    Location,
    Severity,
)
from vulnfix.scanners.base import ScannerAdapter


# Bandit's severity scale: LOW / MEDIUM / HIGH. We treat HIGH-confidence HIGH
# severity as critical for prioritization purposes (configurable later).
_SEV_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class BanditAdapter(ScannerAdapter):
    name = "bandit"

    def parse(self, report_path: Path) -> Iterable[Finding]:
        data = json.loads(report_path.read_text(encoding="utf-8"))
        for r in data.get("results", []) or []:
            test_id = r.get("test_id", "UNKNOWN")  # e.g. B608
            filename = r.get("filename", "")
            line = r.get("line_number")

            yield Finding(
                id=f"bandit:{test_id}:{filename}:{line}",
                scanner=self.name,
                rule_id=test_id,
                title=r.get("test_name", test_id),
                description=r.get("issue_text", ""),
                severity=_SEV_MAP.get(r.get("issue_severity", "").upper(), Severity.UNKNOWN),
                kind=FindingKind.CODE,
                location=Location(
                    file_path=filename,
                    start_line=line,
                    end_line=r.get("line_range", [line, line])[-1] if r.get("line_range") else line,
                    snippet=r.get("code"),
                ),
                cwe=[r.get("issue_cwe", {}).get("id")] if r.get("issue_cwe") else [],
                references=[r.get("more_info")] if r.get("more_info") else [],
                raw=r,
            )
