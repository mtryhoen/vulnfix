"""Grype scanner adapter (SCA).

Grype JSON output:
  {
    "matches": [
      {
        "vulnerability": { "id": "CVE-...", "severity": "...", "fix": { "versions": ["..."] } },
        "artifact": { "name": "...", "version": "...", "type": "python", "locations": [...] }
      }
    ]
  }
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


# Grype's artifact.type values mapped to our ecosystem strings.
_ECO_MAP = {
    "python": "pypi", "npm": "npm", "go-module": "go", "java-archive": "maven",
    "gem": "rubygems", "rust-crate": "cargo", "deb": "os", "apk": "os", "rpm": "os",
}


class GrypeAdapter(ScannerAdapter):
    name = "grype"

    def parse(self, report_path: Path) -> Iterable[Finding]:
        data = json.loads(report_path.read_text(encoding="utf-8"))
        for m in data.get("matches", []) or []:
            vuln = m.get("vulnerability") or {}
            art = m.get("artifact") or {}
            fix_versions = (vuln.get("fix") or {}).get("versions") or []
            fixed_version = fix_versions[0] if fix_versions else None
            locations = art.get("locations") or []
            file_path = locations[0].get("path") if locations else None
            eco = _ECO_MAP.get(art.get("type", "").lower())

            kind = FindingKind.CONTAINER_BASE if eco == "os" else FindingKind.DEPENDENCY

            yield Finding(
                id=f"grype:{vuln.get('id')}:{art.get('name')}@{art.get('version')}",
                scanner=self.name,
                rule_id=vuln.get("id", "UNKNOWN"),
                title=vuln.get("id", ""),
                description=vuln.get("description", ""),
                severity=Severity.from_string(vuln.get("severity", "")),
                kind=kind,
                location=Location(file_path=file_path),
                fix=FixHint(
                    fixed_version=fixed_version,
                    package_name=art.get("name"),
                    package_ecosystem=eco,
                ),
                references=vuln.get("urls") or [],
                raw=m,
            )
