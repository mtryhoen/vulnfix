"""AI-based fixer using Claude Code (headless mode).

We shell out to the ``claude`` CLI with ``--print`` for non-interactive
execution. Claude Code does its own file reading, editing, and (if we ask)
test running, so the prompt is the main lever for fix quality.

Why Claude Code over a raw API call:
  * It already has the agent loop (read file -> edit -> verify).
  * Multi-file refactors work without us writing edit logic.
  * It's easy to swap to a custom agent later for cost control.

Required env var: ANTHROPIC_API_KEY (set in GitHub Secrets).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import textwrap
from dataclasses import dataclass
from pathlib import Path

from vulnfix.models.finding import Finding, FindingKind


@dataclass
class AIFixResult:
    finding_id: str
    success: bool
    summary: str
    files_changed: list[str]
    raw_output: str = ""


class ClaudeCodeFixer:
    """Drive Claude Code in headless mode to fix one finding at a time."""

    def __init__(self, workdir: Path, model: str = "claude-opus-4-7", timeout: int = 300):
        self.workdir = workdir
        self.model = model
        self.timeout = timeout

        if not shutil.which("claude"):
            raise RuntimeError(
                "claude CLI not found on PATH. Install with: "
                "npm install -g @anthropic-ai/claude-code"
            )
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError("ANTHROPIC_API_KEY env var is required")

    def fix(self, finding: Finding) -> AIFixResult:
        prompt = self._build_prompt(finding)

        # Detect which files were modified by snapshotting mtimes before/after.
        before = self._snapshot_mtimes()

        try:
            result = subprocess.run(
                [
                    "claude",
                    "--print",                   # non-interactive
                    "--output-format", "json",   # structured response
                    "--model", self.model,
                    # Only allow tools we actually want it to use during fixes:
                    "--allowedTools", "Read,Edit,Write,Grep,Glob,Bash(pytest:*),Bash(npm test:*)",
                    prompt,
                ],
                cwd=str(self.workdir),
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            return AIFixResult(finding.id, False, "claude timed out", [])

        after = self._snapshot_mtimes()
        changed = sorted(p for p, m in after.items() if before.get(p) != m)

        if result.returncode != 0:
            return AIFixResult(
                finding.id, False,
                f"claude exited {result.returncode}: {result.stderr[:200]}",
                changed,
                raw_output=result.stdout,
            )

        # Parse the JSON output. Claude Code returns a structured result with
        # a 'result' field containing the final text answer.
        summary = "AI fix applied"
        try:
            payload = json.loads(result.stdout)
            summary = payload.get("result", summary)[:500]
        except (json.JSONDecodeError, AttributeError):
            pass

        return AIFixResult(
            finding.id,
            success=bool(changed),
            summary=summary,
            files_changed=changed,
            raw_output=result.stdout,
        )

    # ------------------------------------------------------------------
    def _build_prompt(self, f: Finding) -> str:
        loc = f.location
        loc_str = (
            f"{loc.file_path}:{loc.start_line}" if loc.file_path and loc.start_line
            else loc.file_path or "unknown"
        )
        snippet = f"\nCode snippet:\n```\n{loc.snippet}\n```\n" if loc.snippet else ""

        kind_guidance = {
            FindingKind.CODE: (
                "Modify the source code to remove the vulnerability while preserving "
                "behavior. Keep the diff minimal."
            ),
            FindingKind.SECRET: (
                "Remove the leaked secret from the file. Replace with an environment "
                "variable reference. Do NOT rotate the secret (that's a separate task)."
            ),
            FindingKind.IAC: (
                "Adjust the IaC configuration to satisfy the security rule. Do not "
                "introduce new resources."
            ),
            FindingKind.CONTAINER_BASE: (
                "Update the Dockerfile base image to a patched version (prefer the "
                "latest LTS/stable tag from the same image family)."
            ),
            FindingKind.DEPENDENCY: (
                "Update the dependency manifest to the fixed version. If the fix "
                "requires code changes (API breaks), apply those too."
            ),
        }.get(f.kind, "Fix the issue.")

        return textwrap.dedent(f"""
            You are fixing a single security finding in this repository.

            Finding:
              Scanner: {f.scanner}
              Rule: {f.rule_id}
              Title: {f.title}
              Severity: {f.severity.value}
              Location: {loc_str}
              CWE: {', '.join(f.cwe) if f.cwe else 'n/a'}

            Description:
            {f.description.strip()}
            {snippet}
            Task: {kind_guidance}

            Constraints:
              - Touch the minimum number of files.
              - Do not add commentary, TODOs, or unrelated refactors.
              - If a test file exists for the touched code, run it after the fix.
              - If you cannot fix safely (e.g. requires major refactor), say so and make no changes.

            When done, output a short summary (1-2 sentences) of what you changed and why.
        """).strip()

    def _snapshot_mtimes(self) -> dict[str, float]:
        out: dict[str, float] = {}
        for p in self.workdir.rglob("*"):
            if p.is_file() and ".git" not in p.parts and "node_modules" not in p.parts:
                try:
                    out[str(p.relative_to(self.workdir))] = p.stat().st_mtime
                except (OSError, ValueError):
                    pass
        return out
