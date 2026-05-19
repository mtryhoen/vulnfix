"""vulnfix CLI.

Reads ``vulnfix.yml`` (or ``vulnfix.json``) at the repo root by default.
CLI flags override config values for one-off runs.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
from pathlib import Path

from vulnfix.config import Config, FixMode
from vulnfix.models.finding import Severity
from vulnfix.orchestrator import Orchestrator, OrchestratorReport
from vulnfix.scanners import registered_scanners


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vulnfix",
        description="AI-powered auto-remediation for security scanner findings.",
    )
    parser.add_argument("--reports", nargs="+", required=True, type=Path,
                        help="Scanner report files")
    parser.add_argument("--workdir", type=Path, default=Path("."),
                        help="Repository root")
    parser.add_argument("--config", type=Path, default=None,
                        help="Path to vulnfix.yml (default: <workdir>/vulnfix.yml)")
    parser.add_argument("--min-severity",
                        choices=["critical", "high", "medium", "low"],
                        help="Override min severity from config")
    parser.add_argument("--max-findings", type=int,
                        help="Override max findings from config")
    parser.add_argument("--no-ai", action="store_true",
                        help="Disable AI fixer regardless of config")
    parser.add_argument("--open-pr", action="store_true",
                        help="Push branch and open PR with the fixes")
    parser.add_argument("--base-branch", default="main")
    parser.add_argument("--dry-run", action="store_true",
                        help="Parse and prioritize, don't apply fixes")
    parser.add_argument("--list-scanners", action="store_true",
                        help="List supported scanners and exit")
    args = parser.parse_args(argv)

    if args.list_scanners:
        for s in registered_scanners():
            print(s)
        return 0

    # Load config and apply CLI overrides
    config_path = args.config or args.workdir / "vulnfix.yml"
    if not config_path.exists():
        config_path = args.workdir / "vulnfix.json"
    config = Config.load(config_path if config_path.exists() else None)

    if args.min_severity:
        config.min_severity = Severity.from_string(args.min_severity)
    if args.max_findings is not None:
        config.max_findings = args.max_findings
    if args.no_ai:
        config.ai.enabled = False

    if args.dry_run:
        return _dry_run(args.reports, config)

    orch = Orchestrator(workdir=args.workdir, config=config)
    repo_slug = os.environ.get("GITHUB_REPOSITORY", "")
    report: OrchestratorReport = orch.run(args.reports, repo_slug=repo_slug)
    _print_summary(report, config)

    if args.open_pr and report.fixed:
        _open_pr(args.workdir, args.base_branch, report)
    return 0


def _dry_run(reports, config: Config) -> int:
    from vulnfix.scanners import parse_report
    findings = []
    for r in reports:
        findings.extend(list(parse_report(r)))
    print(f"Parsed {len(findings)} findings from {len(reports)} report(s).")
    for f in findings[:50]:
        skip, reason = config.should_skip(f)
        marker = "SKIP" if skip else f"FIX[{config.effective_mode(f.scanner).value}]"
        print(f"  [{f.severity.value:8}] {marker:18} {f.scanner}:{f.rule_id} -> {f.title[:60]}")
        if skip:
            print(f"           reason: {reason}")
    return 0


def _print_summary(report: OrchestratorReport, config: Config) -> None:
    print(f"Findings considered: {report.total_findings}")
    print(f"Fixed:    {len(report.fixed)}")
    print(f"Skipped:  {len(report.skipped)}")
    print(f"Failed:   {len(report.failed)}")
    print()
    for r in report.fixed:
        print(f"  [fix]  {r.finding_id}")
        print(f"         {r.summary}")
    for fr in report.failed:
        print(f"  [fail] {fr.finding_id}")
        print(f"         {fr.summary}")
    for f, reason in report.skipped:
        print(f"  [skip] {f.id}: {reason}")


def _open_pr(workdir: Path, base: str, report: OrchestratorReport) -> None:
    from vulnfix.vcs import auto_adapter
    vcs = auto_adapter(workdir)
    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    branch = f"vulnfix/{ts}"
    body = _pr_body(report)
    vcs.create_branch_commit_push(
        branch=branch,
        message=f"vulnfix: auto-remediate {len(report.fixed)} findings",
        files=sorted(report.files_changed),
    )
    pr = vcs.open_pull_request(branch, base, "vulnfix: automated security fixes", body)
    print(f"Opened PR: {pr.url}")


def _pr_body(report: OrchestratorReport) -> str:
    verified_fixes = [
        e for e in (report.run_event.fixes if report.run_event else [])
        if e.success and e.verified
    ]
    unverified = [
        e for e in (report.run_event.fixes if report.run_event else [])
        if e.success and not e.verified
    ]

    lines = [
        "## Automated security fixes",
        "",
        f"This PR was generated by **vulnfix**. {len(report.fixed)} fix(es) "
        f"applied, of which **{len(verified_fixes)} were re-scanned and confirmed**.",
        "",
        "### ✅ Verified fixes",
    ]
    for e in verified_fixes:
        files = ", ".join(f"`{f}`" for f in e.files_changed) or "(no files)"
        lines.append(f"- **`{e.scanner}:{e.rule_id}`** ({e.severity}) — {e.summary[:120]}  \n  {files}")

    if unverified:
        lines += ["", "### ⚠️ Applied but not re-verified", ""]
        for e in unverified:
            lines.append(f"- `{e.scanner}:{e.rule_id}` ({e.severity}) — {e.summary[:120]}")

    if report.skipped:
        lines += ["", "<details><summary>Skipped findings</summary>", ""]
        for f, reason in report.skipped[:20]:
            lines.append(f"- `{f.id}` ({f.severity.value}): {reason}")
        lines += ["", "</details>"]
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
