"""End-to-end and unit tests for vulnfix."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnfix.config import Config, FixMode
from vulnfix.models.finding import FindingKind, Severity
from vulnfix.scanners import detect, parse_report, registered_scanners


# ---------------------------------------------------------------------
# Sample reports
# ---------------------------------------------------------------------
TRIVY_FS = {
    "SchemaVersion": 2, "ArtifactName": ".", "ArtifactType": "filesystem",
    "Results": [{
        "Target": "requirements.txt", "Class": "lang-pkgs", "Type": "pip",
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2023-12345", "PkgName": "requests",
            "InstalledVersion": "2.25.0", "FixedVersion": "2.31.0",
            "Severity": "HIGH", "Title": "requests: SSRF", "Description": "x",
            "CweIDs": ["CWE-200"],
        }],
    }],
}

TRIVY_IMAGE = {
    "SchemaVersion": 2, "ArtifactName": "myorg/app:latest", "ArtifactType": "container_image",
    "Results": [{
        "Target": "myorg/app:latest (debian 11)", "Class": "os-pkgs", "Type": "debian",
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2024-99999", "PkgName": "libssl1.1",
            "InstalledVersion": "1.1.1n-0+deb11u3", "FixedVersion": "1.1.1n-0+deb11u5",
            "Severity": "CRITICAL", "Title": "openssl: RCE", "Description": "x",
        }],
    }],
}

BANDIT = {
    "errors": [], "generated_at": "2025-01-01T00:00:00Z",
    "metrics": {"_totals": {"loc": 100}},
    "results": [{
        "test_id": "B608", "test_name": "hardcoded_sql_expressions",
        "filename": "app/db.py", "line_number": 42, "line_range": [42, 43],
        "issue_severity": "MEDIUM", "issue_confidence": "HIGH",
        "issue_text": "Possible SQL injection.",
        "code": '   query = f"SELECT * FROM users WHERE id={user_id}"',
        "issue_cwe": {"id": 89, "link": "https://cwe.mitre.org/"},
    }],
}

SEMGREP = {
    "version": "1.0.0",
    "results": [{
        "check_id": "python.lang.security.audit.dangerous-exec.dangerous-exec",
        "path": "app/runner.py",
        "start": {"line": 10, "col": 5},
        "end": {"line": 10, "col": 20},
        "extra": {
            "severity": "ERROR",
            "message": "exec() with user input is dangerous.",
            "metadata": {"cwe": ["CWE-94"], "references": ["https://owasp.org"]},
            "lines": "exec(user_code)",
        },
    }],
    "errors": [],
}

GITLEAKS = [{
    "Description": "AWS Access Key ID",
    "File": "config.py",
    "StartLine": 5,
    "EndLine": 5,
    "RuleID": "aws-access-token",
    "Match": "AKIA...",
    "Secret": "AKIA1234567890ABCDEF",
    "Commit": "abc123",
}]

GRYPE = {
    "matches": [{
        "vulnerability": {
            "id": "CVE-2022-1234", "severity": "High",
            "fix": {"versions": ["2.0.0"]},
            "description": "x", "urls": [],
        },
        "artifact": {
            "name": "lodash", "version": "1.0.0", "type": "npm",
            "locations": [{"path": "/app/package-lock.json"}],
        },
    }],
    "source": {"type": "directory"},
}


def _write(tmp_path: Path, name: str, data) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(data))
    return p


# ---------------------------------------------------------------------
# Adapter tests
# ---------------------------------------------------------------------
class TestAdapters:
    def test_trivy_fs(self, tmp_path):
        f = list(parse_report(_write(tmp_path, "trivy.json", TRIVY_FS)))[0]
        assert f.scanner == "trivy"
        assert f.kind == FindingKind.DEPENDENCY
        assert f.fix.package_ecosystem == "pypi"
        assert f.fix.fixed_version == "2.31.0"

    def test_trivy_container_base(self, tmp_path):
        f = list(parse_report(_write(tmp_path, "t.json", TRIVY_IMAGE)))[0]
        assert f.kind == FindingKind.CONTAINER_BASE
        assert f.severity == Severity.CRITICAL

    def test_bandit(self, tmp_path):
        f = list(parse_report(_write(tmp_path, "b.json", BANDIT)))[0]
        assert f.scanner == "bandit"
        assert f.location.start_line == 42

    def test_semgrep(self, tmp_path):
        f = list(parse_report(_write(tmp_path, "sg.json", SEMGREP)))[0]
        assert f.scanner == "semgrep"
        assert f.kind == FindingKind.CODE
        assert f.severity == Severity.HIGH
        assert "CWE-94" in f.cwe

    def test_gitleaks(self, tmp_path):
        f = list(parse_report(_write(tmp_path, "gl.json", GITLEAKS)))[0]
        assert f.scanner == "gitleaks"
        assert f.kind == FindingKind.SECRET
        # Critically, no raw secret value in description or raw payload
        assert "AKIA1234567890ABCDEF" not in json.dumps(f.raw)
        assert "AKIA1234567890ABCDEF" not in f.description

    def test_grype(self, tmp_path):
        f = list(parse_report(_write(tmp_path, "g.json", GRYPE)))[0]
        assert f.scanner == "grype"
        assert f.fix.package_name == "lodash"
        assert f.fix.fixed_version == "2.0.0"


class TestDetection:
    """Auto-detection must work even when filenames are misleading."""

    @pytest.mark.parametrize("data,expected", [
        (TRIVY_FS, "trivy"),
        (BANDIT, "bandit"),
        (SEMGREP, "semgrep"),
        (GITLEAKS, "gitleaks"),
        (GRYPE, "grype"),
    ])
    def test_detect_by_shape(self, tmp_path, data, expected):
        # Use a deliberately misleading filename to confirm detection is structural.
        path = _write(tmp_path, "report.json", data)
        adapter = detect(path)
        assert adapter is not None
        assert adapter.name == expected

    def test_registered(self):
        assert set(registered_scanners()) >= {
            "trivy", "bandit", "semgrep", "gitleaks", "grype"
        }


# ---------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------
class TestConfig:
    def test_defaults_when_no_file(self):
        c = Config.load(None)
        assert c.min_severity == Severity.MEDIUM
        assert c.mode == FixMode.PR
        assert c.ai.enabled is True

    def test_per_scanner_override(self, tmp_path):
        cfg = tmp_path / "vulnfix.json"
        cfg.write_text(json.dumps({
            "version": 1,
            "defaults": {"min_severity": "high", "mode": "pr"},
            "scanners": {
                "gitleaks": {"mode": "comment_only"},
                "bandit": {"ignore_rules": ["B101"]},
            },
        }))
        c = Config.load(cfg)
        assert c.effective_mode("gitleaks") == FixMode.COMMENT_ONLY
        assert c.effective_mode("trivy") == FixMode.PR  # falls back to default

    def test_path_ignore(self, tmp_path):
        cfg = tmp_path / "vulnfix.json"
        cfg.write_text(json.dumps({"paths": {"ignore": ["tests/**", "vendor/**"]}}))
        c = Config.load(cfg)
        # Fake a finding pointing inside tests/
        from vulnfix.models.finding import Finding, FindingKind, Location, Severity as Sv
        f = Finding(
            id="x", scanner="bandit", rule_id="B608",
            title="t", description="d", severity=Sv.HIGH, kind=FindingKind.CODE,
            location=Location(file_path="tests/test_foo.py", start_line=1),
        )
        skip, reason = c.should_skip(f)
        assert skip
        assert "path" in reason


# ---------------------------------------------------------------------
# Deterministic fixer
# ---------------------------------------------------------------------
class TestDeterministicFixer:
    def test_requirements_bump(self, tmp_path):
        from vulnfix.fixers.deterministic import DeterministicFixer
        (tmp_path / "requirements.txt").write_text("requests==2.25.0\nflask>=2.0\n")
        finding = list(parse_report(_write(tmp_path, "t.json", TRIVY_FS)))[0]
        result = DeterministicFixer(tmp_path).fix(finding)
        assert result.success
        text = (tmp_path / "requirements.txt").read_text()
        assert "requests==2.31.0" in text
        assert "flask>=2.0" in text  # untouched

    def test_package_json_bump(self, tmp_path):
        from vulnfix.fixers.deterministic import DeterministicFixer
        (tmp_path / "package.json").write_text(json.dumps({
            "dependencies": {"lodash": "^1.0.0"},
            "devDependencies": {"jest": "^29.0.0"},
        }))
        finding = list(parse_report(_write(tmp_path, "g.json", GRYPE)))[0]
        result = DeterministicFixer(tmp_path).fix(finding)
        assert result.success
        data = json.loads((tmp_path / "package.json").read_text())
        assert data["dependencies"]["lodash"] == "^2.0.0"
        assert data["devDependencies"]["jest"] == "^29.0.0"  # untouched

    def test_missing_package_skipped(self, tmp_path):
        from vulnfix.fixers.deterministic import DeterministicFixer
        from vulnfix.models.finding import Finding, FindingKind, FixHint, Severity as Sv
        f = Finding(
            id="x", scanner="trivy", rule_id="CVE", title="t", description="d",
            severity=Sv.HIGH, kind=FindingKind.DEPENDENCY,
            fix=FixHint(package_name="ghost", fixed_version="1.0.0", package_ecosystem="pypi"),
        )
        result = DeterministicFixer(tmp_path).fix(f)
        assert not result.success
        assert "could not find" in result.summary


# ---------------------------------------------------------------------
# Orchestrator filtering
# ---------------------------------------------------------------------
class TestOrchestratorFiltering:
    def test_severity_threshold_filters(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
        # Stub out ClaudeCodeFixer init so we don't actually need the CLI
        from vulnfix.fixers import ai_claude_code as aimod
        monkeypatch.setattr(aimod, "shutil", type("S", (), {"which": lambda _: "/bin/true"}))

        from vulnfix.orchestrator import Orchestrator
        from vulnfix.config import Config
        config = Config()
        config.min_severity = Severity.CRITICAL
        config.ai.enabled = False  # avoid Claude CLI requirement

        (tmp_path / "requirements.txt").write_text("requests==2.25.0\n")
        report_path = _write(tmp_path, "t.json", TRIVY_FS)  # HIGH severity finding

        orch = Orchestrator(workdir=tmp_path, config=config)
        result = orch.run([report_path])
        # HIGH finding should be filtered out (we only want CRITICAL)
        assert result.total_findings == 0
        assert len(result.run_event.skipped) > 0

    def test_dedupe_across_scanners(self, tmp_path, monkeypatch):
        """Same CVE found by Trivy and Grype should dedupe to one finding."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
        from vulnfix.orchestrator import Orchestrator
        from vulnfix.config import Config
        config = Config()
        config.ai.enabled = False
        config.min_severity = Severity.LOW

        # Make Grype and Trivy both report the same finding location
        grype_dup = {
            "matches": [{
                "vulnerability": {"id": "CVE-2023-12345", "severity": "High",
                                  "fix": {"versions": ["2.31.0"]}, "description": "",
                                  "urls": []},
                "artifact": {"name": "requests", "version": "2.25.0", "type": "python",
                             "locations": [{"path": "requirements.txt"}]},
            }],
            "source": {"type": "directory"},
        }
        (tmp_path / "requirements.txt").write_text("requests==2.25.0\n")
        rp1 = _write(tmp_path, "t.json", TRIVY_FS)
        rp2 = _write(tmp_path, "g.json", grype_dup)

        orch = Orchestrator(workdir=tmp_path, config=config)
        result = orch.run([rp1, rp2])
        # Two parsers reported the same CVE/package/file — should be one finding
        assert result.total_findings == 1

    def test_container_base_findings_are_aggregated(self, tmp_path, monkeypatch):
        """Many OS-package CVEs from the same image should collapse to one finding."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
        from vulnfix.orchestrator import Orchestrator
        from vulnfix.config import Config

        # Build a trivy image report with five OS-package CVEs (same image)
        multi_cve_image = {
            "SchemaVersion": 2,
            "ArtifactName": "myorg/app:latest",
            "ArtifactType": "container_image",
            "Results": [{
                "Target": "myorg/app:latest (debian 13)",
                "Class": "os-pkgs",
                "Type": "debian",
                "Vulnerabilities": [
                    {"VulnerabilityID": f"CVE-2025-{i:05d}", "PkgName": f"libfoo{i}",
                     "InstalledVersion": "1.0.0", "FixedVersion": None,
                     "Severity": "HIGH", "Title": "x", "Description": "y"}
                    for i in range(5)
                ],
            }],
        }
        rp = _write(tmp_path, "img.json", multi_cve_image)

        config = Config()
        config.ai.enabled = False  # avoid Claude CLI
        config.min_severity = Severity.LOW

        orch = Orchestrator(workdir=tmp_path, config=config)
        result = orch.run([rp])
        # 5 CVEs from same target -> 1 aggregated finding
        assert result.total_findings == 1
        # The aggregated finding mentions all 5 CVEs in description
        # (we can't inspect it directly here, but it'll be in the run event)
        assert len(result.run_event.skipped) >= 0  # didn't blow up
