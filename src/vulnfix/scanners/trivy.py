"""Trivy scanner adapter.

Handles Trivy's JSON format for both filesystem (code) scans and image
(container) scans. Trivy puts package vulnerabilities under ``Results[].Vulnerabilities``
and code/IaC findings under ``Results[].Misconfigurations`` or ``Results[].Secrets``.
"""
from __future__ import annotations

import json
import re
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


def _split_version(v: str) -> list[int]:
    """Parse a version like '1.3.0' or '1.3.0a2' into [1, 3, 0].

    Non-numeric suffixes (pre-release tags, build metadata) are dropped —
    we only need this for coarse-grained "are these on the same major line"
    comparisons, not strict semver compliance.
    """
    if not v:
        return []
    out: list[int] = []
    for part in re.split(r"[.\-+]", v):
        m = re.match(r"^(\d+)", part)
        if m:
            out.append(int(m.group(1)))
        else:
            break
    return out


class TrivyAdapter(ScannerAdapter):
    name = "trivy"

    def parse(self, report_path: Path) -> Iterable[Finding]:
        data = json.loads(report_path.read_text(encoding="utf-8"))

        # Trivy JSON top-level has "ArtifactName", "ArtifactType", "Results"
        artifact_type = data.get("ArtifactType", "")
        for result in data.get("Results", []) or []:
            target = result.get("Target", "")
            # The 'class' field tells us what kind of finding this is:
            # "os-pkgs" / "lang-pkgs" => dependency, "config" => IaC, "secret" => secrets
            result_class = result.get("Class", "")

            for vuln in result.get("Vulnerabilities", []) or []:
                yield self._parse_vuln(vuln, target, artifact_type, result_class)

            for misc in result.get("Misconfigurations", []) or []:
                yield self._parse_misconfig(misc, target)

            for secret in result.get("Secrets", []) or []:
                yield self._parse_secret(secret, target)

    def _parse_vuln(self, v: dict, target: str, artifact_type: str, klass: str) -> Finding:
        pkg = v.get("PkgName", "")
        installed = v.get("InstalledVersion", "")
        fixed = self._pick_fixed_version(v.get("FixedVersion"), installed)
        cve = v.get("VulnerabilityID", "UNKNOWN")

        # Decide if this is a container-base bump or a manifest dep bump
        if artifact_type == "container_image" and klass == "os-pkgs":
            kind = FindingKind.CONTAINER_BASE
        else:
            kind = FindingKind.DEPENDENCY

        ecosystem = self._ecosystem_from_target(target, klass)

        return Finding(
            id=f"trivy:{cve}:{target}:{pkg}@{installed}",
            scanner=self.name,
            rule_id=cve,
            title=v.get("Title") or cve,
            description=v.get("Description", ""),
            severity=Severity.from_string(v.get("Severity", "")),
            kind=kind,
            location=Location(file_path=target),
            fix=FixHint(
                fixed_version=fixed,
                package_name=pkg,
                package_ecosystem=ecosystem,
            ),
            cwe=v.get("CweIDs", []) or [],
            references=v.get("References", []) or [],
            raw=v,
        )

    def _parse_misconfig(self, m: dict, target: str) -> Finding:
        return Finding(
            id=f"trivy:{m.get('ID', 'MISC')}:{target}",
            scanner=self.name,
            rule_id=m.get("ID", "MISC"),
            title=m.get("Title", "Misconfiguration"),
            description=m.get("Description", ""),
            severity=Severity.from_string(m.get("Severity", "")),
            kind=FindingKind.IAC,
            location=Location(
                file_path=target,
                start_line=m.get("CauseMetadata", {}).get("StartLine"),
                end_line=m.get("CauseMetadata", {}).get("EndLine"),
            ),
            fix=FixHint(suggested_patch=m.get("Resolution")),
            references=m.get("References", []) or [],
            raw=m,
        )

    def _parse_secret(self, s: dict, target: str) -> Finding:
        return Finding(
            id=f"trivy:{s.get('RuleID', 'SECRET')}:{target}:{s.get('StartLine', 0)}",
            scanner=self.name,
            rule_id=s.get("RuleID", "SECRET"),
            title=s.get("Title", "Secret detected"),
            description=s.get("Match", ""),
            severity=Severity.from_string(s.get("Severity", "")),
            kind=FindingKind.SECRET,
            location=Location(
                file_path=target,
                start_line=s.get("StartLine"),
                end_line=s.get("EndLine"),
            ),
            raw=s,
        )

    @staticmethod
    def _pick_fixed_version(fixed_field, installed: str) -> str | None:
        """Trivy's ``FixedVersion`` can be a comma-separated list when the
        CVE is patched on multiple release lines (e.g. ``"1.3.3, 0.3.85"``
        means both 1.3.3 and 0.3.85 fix it).

        We pick the candidate that:
          1. Shares the largest leading-component prefix with the installed
             version (same major, ideally same minor), AND
          2. Is >= installed (we never downgrade).

        If nothing qualifies, fall back to the first listed version.
        """
        if not fixed_field:
            return None
        # Split on comma, semicolon, or whitespace; strip empties.
        candidates = [
            c.strip() for c in re.split(r"[,\s;]+", fixed_field) if c.strip()
        ]
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]

        installed_parts = _split_version(installed)

        def score(candidate: str) -> tuple[int, int, list[int]]:
            cand_parts = _split_version(candidate)
            # How many leading components match installed?
            shared = 0
            for a, b in zip(installed_parts, cand_parts):
                if a == b:
                    shared += 1
                else:
                    break
            not_downgrade = 1 if cand_parts >= installed_parts else 0
            # Higher shared prefix wins; prefer non-downgrades; among ties
            # prefer the lower candidate version (closer-in patch).
            return (not_downgrade, shared, [-x for x in cand_parts])

        return max(candidates, key=score)

    @staticmethod
    def _ecosystem_from_target(target: str, klass: str) -> str | None:
        """Map Trivy's `Target` + `Class` to a vulnfix ecosystem name.

        Trivy can label the target as either a file path (``requirements.txt``,
        ``uv.lock``) or just a package source name (``Python``, ``Node.js``)
        depending on how the scan was configured. Handle both.
        """
        t = target.lower()
        # File-path-based detection (most common)
        if any(t.endswith(s) for s in (
            "requirements.txt", "pyproject.toml", "poetry.lock",
            "pipfile.lock", "pipfile", "uv.lock", "pdm.lock",
        )):
            return "pypi"
        if any(t.endswith(s) for s in (
            "package-lock.json", "yarn.lock", "package.json", "pnpm-lock.yaml",
        )):
            return "npm"
        if any(t.endswith(s) for s in ("go.sum", "go.mod")):
            return "go"
        if any(t.endswith(s) for s in ("cargo.lock", "cargo.toml")):
            return "cargo"
        if t.endswith("gemfile.lock") or t.endswith("gemfile"):
            return "rubygems"
        if any(t.endswith(s) for s in ("pom.xml", "build.gradle", "build.gradle.kts")):
            return "maven"

        # Fall back to Trivy's language label when no file path is available.
        # Trivy sometimes reports e.g. Target="Python", Class="lang-pkgs".
        label_map = {
            "python": "pypi",
            "node.js": "npm",
            "go": "go",
            "rust": "cargo",
            "ruby": "rubygems",
            "java": "maven",
        }
        if klass == "lang-pkgs" and t in label_map:
            return label_map[t]

        if klass == "os-pkgs":
            return "os"
        return None
