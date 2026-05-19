"""Trivy scanner adapter.

Handles Trivy's JSON format for both filesystem (code) scans and image
(container) scans. Trivy puts package vulnerabilities under ``Results[].Vulnerabilities``
and code/IaC findings under ``Results[].Misconfigurations`` or ``Results[].Secrets``.
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
        fixed = v.get("FixedVersion") or None
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
    def _ecosystem_from_target(target: str, klass: str) -> str | None:
        t = target.lower()
        if t.endswith("requirements.txt") or t.endswith("pyproject.toml") or t.endswith("poetry.lock") or t.endswith("pipfile.lock"):
            return "pypi"
        if t.endswith("package-lock.json") or t.endswith("yarn.lock") or t.endswith("package.json"):
            return "npm"
        if t.endswith("go.sum") or t.endswith("go.mod"):
            return "go"
        if t.endswith("cargo.lock") or t.endswith("cargo.toml"):
            return "cargo"
        if t.endswith("gemfile.lock"):
            return "rubygems"
        if t.endswith("pom.xml") or t.endswith("build.gradle"):
            return "maven"
        if klass == "os-pkgs":
            return "os"
        return None
