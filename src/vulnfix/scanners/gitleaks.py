"""Gitleaks scanner adapter (secrets).

Gitleaks JSON output is a flat array of objects with keys like:
  Description, File, StartLine, EndLine, RuleID, Match, Secret, Commit, Author
"""
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


class GitleaksAdapter(ScannerAdapter):
    name = "gitleaks"

    def parse(self, report_path: Path) -> Iterable[Finding]:
        data = json.loads(report_path.read_text(encoding="utf-8"))
        # Gitleaks emits a top-level array (no envelope).
        if isinstance(data, dict):  # some forks wrap it
            data = data.get("findings", []) or []
        for r in data:
            rule = r.get("RuleID") or r.get("ruleID") or "SECRET"
            path = r.get("File") or r.get("file", "")
            start = r.get("StartLine") or r.get("startLine")

            yield Finding(
                id=f"gitleaks:{rule}:{path}:{start}",
                scanner=self.name,
                # Always treat detected secrets as HIGH — they're either real
                # secrets (critical) or false positives (low). User config
                # decides what to actually do.
                rule_id=rule,
                title=f"Secret detected: {rule}",
                description=r.get("Description") or r.get("description", ""),
                severity=Severity.HIGH,
                kind=FindingKind.SECRET,
                location=Location(
                    file_path=path,
                    start_line=start,
                    end_line=r.get("EndLine") or r.get("endLine"),
                    # We deliberately do NOT include the secret value in
                    # snippet — that would leak into PR descriptions.
                    snippet="<redacted secret>",
                ),
                raw={k: v for k, v in r.items() if k.lower() not in {"secret", "match"}},
            )
