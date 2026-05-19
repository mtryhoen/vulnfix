"""Orchestrates the end-to-end fix flow.

  1. Parse one or more scanner reports into ``Finding`` objects.
  2. Apply config filters (severity threshold, ignore rules/paths, disabled scanners).
  3. Deduplicate (same vuln found by multiple scanners = one finding).
  4. Sort by severity.
  5. For each finding:
        - Snapshot the working tree (single git stash point per run).
        - Try DeterministicFixer.
        - If that fails or doesn't apply, try ClaudeCodeFixer (when AI is on
          and the scanner's mode allows it).
        - Verify the fix actually worked. Roll back if it didn't.
        - Emit telemetry.
  6. Return a structured report for the VCS layer.
"""
from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence, Union

from vulnfix.config import Config, FixMode
from vulnfix.fixers.ai_claude_code import AIFixResult, ClaudeCodeFixer
from vulnfix.fixers.deterministic import DeterministicFixer, FixResult
from vulnfix.fixers.verifier import Verifier, VerifyResult
from vulnfix.models.finding import Finding, FindingKind, Severity
from vulnfix.scanners import parse_report
from vulnfix.telemetry import (
    FixEvent,
    RunEvent,
    TelemetryEmitter,
    new_run_id,
    now_iso,
)


_SEV_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
    Severity.UNKNOWN: 5,
}

AnyFix = Union[FixResult, AIFixResult]


@dataclass
class OrchestratorReport:
    total_findings: int = 0
    fixed: list[AnyFix] = field(default_factory=list)
    skipped: list[tuple[Finding, str]] = field(default_factory=list)
    failed: list[AnyFix] = field(default_factory=list)
    run_event: RunEvent | None = None

    @property
    def files_changed(self) -> set[str]:
        out: set[str] = set()
        for r in self.fixed:
            out.update(r.files_changed)
        return out


class Orchestrator:
    def __init__(self, workdir: Path, config: Config):
        self.workdir = workdir
        self.config = config
        self.deterministic = DeterministicFixer(workdir)
        self.verifier = Verifier(workdir)
        self.ai: ClaudeCodeFixer | None = None
        if config.ai.enabled:
            self.ai = ClaudeCodeFixer(
                workdir,
                model=config.ai.model,
                timeout=config.ai.timeout_seconds,
            )
        self.telemetry = TelemetryEmitter(config.telemetry, workdir)

    # ------------------------------------------------------------------
    def run(self, reports: Sequence[Path], repo_slug: str = "") -> OrchestratorReport:
        run_event = RunEvent(
            run_id=new_run_id(),
            repo_slug=repo_slug,
            started_at=now_iso(),
        )

        findings = list(self._collect(reports))
        findings = self._deduplicate(findings)
        findings = self._aggregate_container_base(findings)
        findings = self._apply_config_filters(findings, run_event)
        findings = self._sort_and_cap(findings)

        run_event.findings_considered = len(findings)
        report = OrchestratorReport(total_findings=len(findings))

        for f in findings:
            self._fix_one(f, report, run_event)

        run_event.finished_at = now_iso()
        report.run_event = run_event
        self.telemetry.emit(run_event)
        return report

    # ------------------------------------------------------------------
    def _collect(self, reports: Sequence[Path]):
        for path in reports:
            try:
                yield from parse_report(path)
            except Exception as e:
                print(f"[warn] failed to parse {path}: {e}")

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        seen: dict[str, Finding] = {}
        for f in findings:
            key = f.dedupe_key
            if key not in seen or _SEV_ORDER[f.severity] < _SEV_ORDER[seen[key].severity]:
                seen[key] = f
        return list(seen.values())

    @staticmethod
    def _aggregate_container_base(findings: list[Finding]) -> list[Finding]:
        """Collapse all CONTAINER_BASE findings into one synthetic finding
        per Dockerfile target.

        Why: a base image like ``debian:13.4`` typically produces dozens of
        OS-package CVEs (libncurses, libsystemd, libssl, ...). They share
        one fix — bump the base image tag — so making N LLM calls is waste.
        We pass a single aggregated finding with the full package list so
        the AI fixer can make an informed Dockerfile edit.
        """
        from vulnfix.models.finding import FindingKind, FixHint, Location

        kept: list[Finding] = []
        groups: dict[str, list[Finding]] = {}
        for f in findings:
            if f.kind == FindingKind.CONTAINER_BASE:
                # Group by the scanner's "target" (the image+OS string).
                key = f.location.file_path or "container"
                groups.setdefault(key, []).append(f)
            else:
                kept.append(f)

        for target, group in groups.items():
            # Pick the worst severity seen in the group.
            worst = min(group, key=lambda g: _SEV_ORDER[g.severity]).severity
            # Build a compact list of vulnerable packages for the prompt.
            pkgs = sorted({
                f"{f.fix.package_name}@{f.raw.get('InstalledVersion', '?')}"
                for f in group if f.fix.package_name
            })
            cves = sorted({f.rule_id for f in group})
            kept.append(Finding(
                id=f"aggregated:container_base:{target}",
                scanner="vulnfix",  # synthetic source
                rule_id="CONTAINER_BASE_BUMP",
                title=f"Update base image (affects {len(group)} CVE(s) in {len(pkgs)} package(s))",
                description=(
                    f"The base image for {target} contains vulnerable OS packages.\n\n"
                    f"CVEs: {', '.join(cves[:10])}{' ...' if len(cves) > 10 else ''}\n"
                    f"Affected packages: {', '.join(pkgs[:15])}{' ...' if len(pkgs) > 15 else ''}\n\n"
                    "Fix by bumping the FROM tag in the Dockerfile to a more recent "
                    "patched release of the same image family."
                ),
                severity=worst,
                kind=FindingKind.CONTAINER_BASE,
                location=Location(file_path="Dockerfile"),
                fix=FixHint(),
                raw={"aggregated_findings": [f.id for f in group]},
            ))
        return kept

    def _apply_config_filters(
        self, findings: list[Finding], run_event: RunEvent
    ) -> list[Finding]:
        kept: list[Finding] = []
        for f in findings:
            # Config skips: disabled scanner, ignored rule/path
            skip, reason = self.config.should_skip(f)
            if skip:
                run_event.skipped.append({"finding_id": f.id, "reason": reason})
                continue
            # Severity threshold (per-scanner override > global)
            threshold = self.config.effective_min_severity(f.scanner)
            if _SEV_ORDER[f.severity] > _SEV_ORDER[threshold]:
                run_event.skipped.append({
                    "finding_id": f.id,
                    "reason": f"below severity threshold {threshold.value}",
                })
                continue
            kept.append(f)
        return kept

    def _sort_and_cap(self, findings: list[Finding]) -> list[Finding]:
        findings.sort(key=lambda f: (_SEV_ORDER[f.severity], f.kind.value, f.id))
        return findings[: self.config.max_findings]

    # ------------------------------------------------------------------
    def _fix_one(
        self, f: Finding, report: OrchestratorReport, run_event: RunEvent
    ) -> None:
        mode = self.config.effective_mode(f.scanner)
        if mode == FixMode.COMMENT_ONLY:
            report.skipped.append((f, f"scanner {f.scanner} is in comment_only mode"))
            run_event.skipped.append({"finding_id": f.id, "reason": "comment_only"})
            return

        start = time.monotonic()

        # 1. Try deterministic first
        det_result = self.deterministic.fix(f)
        if det_result and det_result.success:
            self._handle_result(f, det_result, "deterministic", start, report, run_event)
            return

        # 2. Fall back to AI for code-level kinds (if AI enabled and scanner allows)
        if (
            self.ai is not None
            and f.kind in {FindingKind.CODE, FindingKind.IAC, FindingKind.CONTAINER_BASE}
        ):
            ai_result = self.ai.fix(f)
            self._handle_result(f, ai_result, "ai_claude_code", start, report, run_event)
            return

        # 3. Nothing applies
        reason = det_result.summary if det_result else "no fixer available"
        report.skipped.append((f, reason))
        run_event.skipped.append({"finding_id": f.id, "reason": reason})

    def _handle_result(
        self,
        finding: Finding,
        result: AnyFix,
        strategy: str,
        started_monotonic: float,
        report: OrchestratorReport,
        run_event: RunEvent,
    ) -> None:
        duration_ms = int((time.monotonic() - started_monotonic) * 1000)
        verified = False
        verify: VerifyResult | None = None

        if result.success and result.files_changed:
            verify = self.verifier.verify(finding, result.files_changed)
            verified = verify.verified
            if not verified:
                # Roll back the changes — the fix didn't work.
                self._git_checkout_files(result.files_changed)
                result.success = False
                result.summary = (
                    f"{result.summary} [rolled back: {verify.detail}]"
                )

        if result.success:
            report.fixed.append(result)
        else:
            report.failed.append(result)

        run_event.fixes.append(FixEvent(
            finding_id=finding.id,
            scanner=finding.scanner,
            rule_id=finding.rule_id,
            severity=finding.severity.value,
            kind=finding.kind.value,
            strategy=strategy,
            success=result.success,
            verified=verified,
            files_changed=list(result.files_changed),
            duration_ms=duration_ms,
            summary=result.summary,
        ))

    def _git_checkout_files(self, files: list[str]) -> None:
        """Roll back unverified changes via git."""
        if not files:
            return
        try:
            subprocess.run(
                ["git", "checkout", "--", *files],
                cwd=str(self.workdir),
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            print(f"[warn] rollback failed for {files}: {e.stderr.decode(errors='replace')}")
