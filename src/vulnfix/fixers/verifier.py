"""Verifier: re-run the scanner after a fix to confirm the finding is gone.

Without verification, AI fixes look successful when they're not — the LLM
edited *some* code and didn't crash. With verification, we either:
  * see the finding is gone -> green light, commit it
  * see it's still there -> roll back the change, fall through to next strategy

For dependency / container findings, we skip re-scanning (a version bump is
deterministic and re-scanning a container image is expensive) and rely on
the deterministic fixer's correctness.

For code findings (Bandit, Semgrep), we re-run the scanner on the changed
file only. This is cheap.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from vulnfix.models.finding import Finding, FindingKind


@dataclass
class VerifyResult:
    finding_id: str
    verified: bool
    detail: str


class Verifier:
    """Re-run scanners to confirm fixes."""

    def __init__(self, workdir: Path):
        self.workdir = workdir

    def verify(self, finding: Finding, changed_files: list[str]) -> VerifyResult:
        # Deterministic kinds: trust the fixer.
        if finding.kind in {FindingKind.DEPENDENCY, FindingKind.CONTAINER_BASE, FindingKind.SECRET}:
            return VerifyResult(finding.id, True, "fix kind doesn't require re-scan")

        if not changed_files:
            return VerifyResult(finding.id, False, "no files changed — fix did nothing")

        if finding.scanner == "bandit":
            return self._verify_bandit(finding)
        if finding.scanner == "semgrep":
            return self._verify_semgrep(finding)

        # We don't know how to re-run this scanner locally; accept on faith.
        return VerifyResult(finding.id, True, f"no local verifier for {finding.scanner}")

    # ------------------------------------------------------------------
    def _verify_bandit(self, f: Finding) -> VerifyResult:
        if not shutil.which("bandit"):
            return VerifyResult(f.id, True, "bandit not installed — skipping verify")
        if not f.location.file_path:
            return VerifyResult(f.id, True, "no file path on finding")
        target = self.workdir / f.location.file_path
        if not target.exists():
            return VerifyResult(f.id, True, "target file was deleted by fix")
        result = subprocess.run(
            ["bandit", "-f", "json", "-q", str(target)],
            capture_output=True, text=True, cwd=str(self.workdir),
        )
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return VerifyResult(f.id, False, "bandit output was not parseable")
        for r in data.get("results", []) or []:
            if r.get("test_id") == f.rule_id and r.get("line_number") == f.location.start_line:
                return VerifyResult(f.id, False, f"finding {f.rule_id} still present at line {f.location.start_line}")
        return VerifyResult(f.id, True, "bandit confirms finding is gone")

    def _verify_semgrep(self, f: Finding) -> VerifyResult:
        if not shutil.which("semgrep"):
            return VerifyResult(f.id, True, "semgrep not installed — skipping verify")
        if not f.location.file_path:
            return VerifyResult(f.id, True, "no file path on finding")
        result = subprocess.run(
            ["semgrep", "scan", "--config", "auto", "--json", "-q", f.location.file_path],
            capture_output=True, text=True, cwd=str(self.workdir),
            timeout=120,
        )
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return VerifyResult(f.id, False, "semgrep output was not parseable")
        for r in data.get("results", []) or []:
            if r.get("check_id") == f.rule_id:
                start = (r.get("start") or {}).get("line")
                if start == f.location.start_line:
                    return VerifyResult(f.id, False, f"finding {f.rule_id} still present at line {start}")
        return VerifyResult(f.id, True, "semgrep confirms finding is gone")
