"""Semgrep scanner adapter.

Semgrep's JSON output: ``{ "results": [ ... ], "errors": [ ... ] }``
Each result has ``check_id``, ``path``, ``start.line``, ``end.line``,
``extra.severity`` (ERROR/WARNING/INFO), ``extra.message``, ``extra.metadata``.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from vulnfix.models.finding import (
    Finding,
    FindingKind,
    FixHint,
    Location,
    Severity,
)
from vulnfix.scanners.base import ScannerAdapter


# Semgrep uses ERROR/WARNING/INFO; map them to our scale conservatively.
_SEV_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class SemgrepAdapter(ScannerAdapter):
    name = "semgrep"

    def parse(self, report_path: Path) -> Iterable[Finding]:
        data = json.loads(report_path.read_text(encoding="utf-8"))
        for r in data.get("results", []) or []:
            check_id = r.get("check_id", "UNKNOWN")
            path = r.get("path", "")
            start = (r.get("start") or {}).get("line")
            end = (r.get("end") or {}).get("line")
            extra = r.get("extra") or {}
            meta = extra.get("metadata") or {}

            # Metadata often carries CWE and references — use them.
            cwe = meta.get("cwe", [])
            if isinstance(cwe, str):
                cwe = [cwe]
            refs = meta.get("references") or []
            if isinstance(refs, str):
                refs = [refs]

            # Semgrep can suggest autofixes in `extra.fix`.
            suggested = extra.get("fix")

            yield Finding(
                id=f"semgrep:{check_id}:{path}:{start}",
                scanner=self.name,
                rule_id=check_id,
                title=meta.get("shortDescription") or check_id.split(".")[-1],
                description=extra.get("message", ""),
                severity=_SEV_MAP.get(extra.get("severity", "").upper(), Severity.UNKNOWN),
                kind=FindingKind.CODE,
                location=Location(
                    file_path=path,
                    start_line=start,
                    end_line=end,
                    snippet=extra.get("lines"),
                ),
                fix=FixHint(suggested_patch=suggested),
                cwe=cwe,
                references=refs,
                raw=r,
            )
