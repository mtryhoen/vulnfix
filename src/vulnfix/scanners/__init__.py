"""Scanner registry & auto-detection.

Adding a new scanner = import it here and add it to ``_REGISTRY``.
``detect()`` uses structural heuristics on the JSON to identify which
scanner produced a report — robust to filenames.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from vulnfix.models.finding import Finding
from vulnfix.scanners.base import ScannerAdapter
from vulnfix.scanners.bandit import BanditAdapter
from vulnfix.scanners.gitleaks import GitleaksAdapter
from vulnfix.scanners.grype import GrypeAdapter
from vulnfix.scanners.semgrep import SemgrepAdapter
from vulnfix.scanners.trivy import TrivyAdapter


_REGISTRY: dict[str, ScannerAdapter] = {
    "trivy": TrivyAdapter(),
    "bandit": BanditAdapter(),
    "semgrep": SemgrepAdapter(),
    "gitleaks": GitleaksAdapter(),
    "grype": GrypeAdapter(),
}


def detect(report_path: Path) -> ScannerAdapter | None:
    """Best-effort guess at which scanner produced a report.

    Inspects the JSON structure, not the filename — users can name files
    whatever they want.
    """
    if report_path.suffix.lower() not in {".json", ".sarif"}:
        return None
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None

    # Gitleaks emits a top-level array of objects with RuleID.
    if isinstance(data, list):
        if data and isinstance(data[0], dict) and ("RuleID" in data[0] or "ruleID" in data[0]):
            return _REGISTRY["gitleaks"]
        return None

    if not isinstance(data, dict):
        return None

    # Order matters — check the most distinctive markers first.
    if "SchemaVersion" in data and "Results" in data:
        return _REGISTRY["trivy"]
    if "matches" in data and "source" in data:
        return _REGISTRY["grype"]
    if "results" in data and "metrics" in data and "errors" in data:
        return _REGISTRY["bandit"]
    if "results" in data and isinstance(data.get("results"), list):
        results = data["results"]
        if not results or (isinstance(results[0], dict) and "check_id" in results[0]):
            return _REGISTRY["semgrep"]
    return None


def parse_report(report_path: Path, scanner: str | None = None) -> Iterable[Finding]:
    """Parse a report, optionally with an explicit scanner override."""
    if scanner:
        if scanner not in _REGISTRY:
            raise ValueError(
                f"Unknown scanner {scanner!r}. Available: {', '.join(sorted(_REGISTRY))}"
            )
        adapter = _REGISTRY[scanner]
    else:
        adapter = detect(report_path)
    if adapter is None:
        raise ValueError(
            f"Could not detect scanner for {report_path}. "
            f"Pass --scanner explicitly. Available: {', '.join(sorted(_REGISTRY))}"
        )
    yield from adapter.parse(report_path)


def registered_scanners() -> list[str]:
    return sorted(_REGISTRY.keys())
