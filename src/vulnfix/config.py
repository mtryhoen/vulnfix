"""vulnfix.yml — per-repo configuration.

Design principles:
  * Every field has a sane default so config is optional.
  * Per-scanner and per-rule overrides so users can dial in noisy rules
    without nuking the whole scanner.
  * The same schema is consumed by the SaaS layer — central policies in
    SaaS override repo-local config, but the field names are identical.

Example vulnfix.yml at repo root:

    version: 1
    defaults:
      min_severity: high
      mode: pr            # pr | auto_merge | comment_only | disabled
      max_findings: 25

    scanners:
      bandit:
        mode: pr
        ignore_rules: [B101]   # don't fix assert statements
      trivy:
        mode: auto_merge       # we trust version bumps
      gitleaks:
        mode: comment_only     # never auto-rotate secrets

    paths:
      ignore:
        - "tests/**"
        - "vendor/**"

    ai:
      enabled: true
      model: claude-opus-4-7
      timeout_seconds: 300

    telemetry:
      # vulnfix Cloud (SaaS) endpoint — optional
      endpoint: https://api.vulnfix.io/v1/events
      api_key_env: VULNFIX_API_KEY
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from vulnfix.models.finding import Finding, Severity


class FixMode(str, Enum):
    DISABLED = "disabled"          # skip this scanner entirely
    COMMENT_ONLY = "comment_only"  # report findings, don't fix
    PR = "pr"                      # apply fix, open PR for human review
    AUTO_MERGE = "auto_merge"      # apply fix and merge if tests pass


@dataclass
class ScannerConfig:
    mode: Optional[FixMode] = None
    min_severity: Optional[Severity] = None
    ignore_rules: list[str] = field(default_factory=list)


@dataclass
class AIConfig:
    enabled: bool = True
    model: str = "claude-opus-4-7"
    timeout_seconds: int = 300


@dataclass
class TelemetryConfig:
    endpoint: Optional[str] = None
    api_key_env: str = "VULNFIX_API_KEY"
    anonymous: bool = True


@dataclass
class Config:
    """Resolved configuration. All fields have defaults; missing yml = defaults."""
    version: int = 1
    min_severity: Severity = Severity.MEDIUM
    mode: FixMode = FixMode.PR
    max_findings: int = 50
    scanners: dict[str, ScannerConfig] = field(default_factory=dict)
    ignore_paths: list[str] = field(default_factory=list)
    ai: AIConfig = field(default_factory=AIConfig)
    telemetry: TelemetryConfig = field(default_factory=TelemetryConfig)

    # ------------------------------------------------------------------
    @classmethod
    def load(cls, path: Path | None) -> "Config":
        if path is None or not path.exists():
            return cls()
        # We avoid a hard dep on PyYAML so the package stays zero-dep.
        # If users have YAML config, they install pyyaml; otherwise JSON works.
        text = path.read_text(encoding="utf-8")
        data = _parse_yaml_or_json(text, path.suffix)
        return cls._from_dict(data or {})

    @classmethod
    def _from_dict(cls, data: dict) -> "Config":
        defaults = data.get("defaults", {})
        scanners = {}
        for name, sc in (data.get("scanners") or {}).items():
            scanners[name] = ScannerConfig(
                mode=FixMode(sc["mode"]) if sc.get("mode") else None,
                min_severity=Severity.from_string(sc["min_severity"]) if sc.get("min_severity") else None,
                ignore_rules=sc.get("ignore_rules") or [],
            )
        ai = data.get("ai") or {}
        tel = data.get("telemetry") or {}
        return cls(
            version=int(data.get("version", 1)),
            min_severity=Severity.from_string(defaults.get("min_severity", "medium")),
            mode=FixMode(defaults.get("mode", "pr")),
            max_findings=int(defaults.get("max_findings", 50)),
            scanners=scanners,
            ignore_paths=(data.get("paths") or {}).get("ignore", []) or [],
            ai=AIConfig(
                enabled=ai.get("enabled", True),
                model=ai.get("model", "claude-opus-4-7"),
                timeout_seconds=int(ai.get("timeout_seconds", 300)),
            ),
            telemetry=TelemetryConfig(
                endpoint=tel.get("endpoint"),
                api_key_env=tel.get("api_key_env", "VULNFIX_API_KEY"),
                anonymous=bool(tel.get("anonymous", True)),
            ),
        )

    # ------------------------------------------------------------------
    def effective_mode(self, scanner: str) -> FixMode:
        sc = self.scanners.get(scanner)
        if sc and sc.mode is not None:
            return sc.mode
        return self.mode

    def effective_min_severity(self, scanner: str) -> Severity:
        sc = self.scanners.get(scanner)
        if sc and sc.min_severity is not None:
            return sc.min_severity
        return self.min_severity

    def should_skip(self, finding: Finding) -> tuple[bool, str]:
        """Return (skip, reason). Centralized so the orchestrator doesn't
        sprout config-handling code."""
        # 1. Scanner disabled
        if self.effective_mode(finding.scanner) == FixMode.DISABLED:
            return True, f"scanner {finding.scanner} is disabled"

        # 2. Rule explicitly ignored
        sc = self.scanners.get(finding.scanner)
        if sc and finding.rule_id in sc.ignore_rules:
            return True, f"rule {finding.rule_id} is in ignore_rules"

        # 3. Path ignored
        if finding.location.file_path and self._path_matches(finding.location.file_path):
            return True, f"path matches ignore pattern"

        return False, ""

    def _path_matches(self, file_path: str) -> bool:
        from fnmatch import fnmatch
        return any(fnmatch(file_path, pattern) for pattern in self.ignore_paths)


def _parse_yaml_or_json(text: str, suffix: str) -> dict:
    if suffix.lower() in {".json"}:
        import json
        return json.loads(text)
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text) or {}
    except ImportError:
        raise RuntimeError(
            "vulnfix.yml requires PyYAML. Install with: pip install pyyaml. "
            "Alternatively use vulnfix.json with the same schema."
        )
