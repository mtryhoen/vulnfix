"""Deterministic fixer: handles cases that don't need an LLM.

This is the cheap, reliable path. Most CVE findings just need a version
bump — no point burning AI tokens on that. The fixer modifies files in
place on the working tree.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from vulnfix.models.finding import Finding, FindingKind


@dataclass
class FixResult:
    finding_id: str
    success: bool
    summary: str
    files_changed: list[str]


class DeterministicFixer:
    """Apply mechanical fixes that don't need an LLM."""

    def __init__(self, workdir: Path):
        self.workdir = workdir

    def fix(self, finding: Finding) -> FixResult | None:
        """Return a FixResult if this fixer handled the finding, else None."""
        if finding.kind == FindingKind.DEPENDENCY:
            return self._fix_dependency(finding)
        if finding.kind == FindingKind.CONTAINER_BASE:
            return self._fix_container_base(finding)
        return None

    # ------------------------------------------------------------------
    # Dependency bumps
    # ------------------------------------------------------------------
    def _fix_dependency(self, f: Finding) -> FixResult | None:
        pkg = f.fix.package_name
        fixed_version = f.fix.fixed_version
        if not pkg or not fixed_version:
            return FixResult(f.id, False, "missing package name or fixed version", [])

        eco = (f.fix.package_ecosystem or "").lower()
        if eco == "pypi":
            return self._bump_pypi(f, pkg, fixed_version)
        if eco == "npm":
            return self._bump_npm(f, pkg, fixed_version)
        # other ecosystems: leave to the AI fixer for now
        return FixResult(f.id, False, f"no deterministic fixer for ecosystem {eco}", [])

    def _bump_pypi(self, f: Finding, pkg: str, version: str) -> FixResult:
        changed: list[str] = []
        # We try the most common manifests; users can extend this list.
        candidates = ["requirements.txt", "requirements/base.txt", "pyproject.toml"]
        for rel in candidates:
            path = self.workdir / rel
            if not path.exists():
                continue
            text = path.read_text(encoding="utf-8")
            new_text = self._rewrite_pypi_requirement(text, pkg, version)
            if new_text != text:
                path.write_text(new_text, encoding="utf-8")
                changed.append(rel)
        if changed:
            return FixResult(f.id, True, f"bumped {pkg} to {version}", changed)
        return FixResult(f.id, False, f"could not find {pkg} in known manifests", [])

    @staticmethod
    def _rewrite_pypi_requirement(text: str, pkg: str, version: str) -> str:
        # Handles forms like:  pkg==1.2.3   pkg>=1.0,<2.0   pkg
        # We deliberately pin to the fixed version with ==. Users who want
        # range bumps can configure this later.
        pattern = re.compile(
            rf"^(\s*){re.escape(pkg)}\s*([<>=!~]=?[^#\s]*(?:\s*,\s*[<>=!~]=?[^#\s]*)*)?",
            re.IGNORECASE | re.MULTILINE,
        )
        return pattern.sub(rf"\g<1>{pkg}=={version}", text)

    def _bump_npm(self, f: Finding, pkg: str, version: str) -> FixResult:
        # For npm we only touch package.json deterministically. Lockfiles
        # need `npm install` to regenerate properly.
        path = self.workdir / "package.json"
        if not path.exists():
            return FixResult(f.id, False, "no package.json found", [])
        import json as _json
        data = _json.loads(path.read_text(encoding="utf-8"))
        changed = False
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            if section in data and pkg in data[section]:
                data[section][pkg] = f"^{version}"
                changed = True
        if not changed:
            return FixResult(f.id, False, f"{pkg} not in package.json", [])
        path.write_text(_json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return FixResult(f.id, True, f"bumped {pkg} to ^{version} (run npm install)", ["package.json"])

    # ------------------------------------------------------------------
    # Container base image bumps
    # ------------------------------------------------------------------
    def _fix_container_base(self, f: Finding) -> FixResult | None:
        """Container OS-package CVEs are fixed by updating the base image
        tag in the Dockerfile, not by editing OS packages directly.

        Since we don't have a registry to look up the latest patched tag,
        we hand off to the AI fixer with a clear instruction. The AI fixer
        is given a single aggregated finding (see orchestrator) so we
        don't burn N calls on the same Dockerfile change.
        """
        dockerfile = self.workdir / "Dockerfile"
        if not dockerfile.exists():
            return FixResult(f.id, False, "no Dockerfile at repo root", [])
        # We deliberately return None so the orchestrator falls through to
        # the AI fixer. Bumping a base image without checking the registry
        # for an existing tag would break the build.
        return None
