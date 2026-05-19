# vulnfix

**AI-powered auto-remediation for security scanner findings.** Plug in your existing scanners (Trivy, Bandit, Semgrep, gitleaks, Grype), and vulnfix opens pull requests with real fixes - version bumps for dependencies, code refactors for SAST findings, **all re-scanned to confirm the vulnerability is actually gone before committing**.

## Why this exists

Dependabot and Renovate bump versions. GitHub Advanced Security flags issues. Neither rewrites your `cursor.execute(f"…{user_input}…")` into a parameterized query. vulnfix uses Claude Code to do the actual remediation, **then re-runs the scanner to verify the fix worked** - if it didn't, the change is rolled back, not committed.

## Supported scanners (v0.1.2)

| Scanner | Finding kinds | Status |
| --- | --- | --- |
| Trivy (fs, image, IaC, secrets) | deps, container, IaC, secrets | ✅ |
| Bandit | code | ✅ |
| Semgrep | code | ✅ |
| gitleaks | secrets | ✅ |
| Grype | deps, container | ✅ |
| Snyk | _planned_ | 🟡 |
| Checkov / KICS | _planned_ | 🟡 |

## Quick start

**1.** Drop `vulnfix.yml` in your repo root (see `examples/vulnfix.yml` - every field optional):

```yaml
version: 1
defaults:
  min_severity: high
  mode: pr
scanners:
  trivy: { mode: auto_merge }
  gitleaks: { mode: comment_only }
paths:
  ignore: ["tests/**", "vendor/**"]
```

**2.** Add a workflow that runs your scanners and calls vulnfix:

```yaml
- uses: aquasecurity/trivy-action@master
  with: { scan-type: 'fs', format: 'json', output: 'trivy.json' }
- run: pip install bandit semgrep && bandit -r . -f json -o bandit.json || true
- uses: your-org/vulnfix@v0.1.2
  with:
    reports: 'trivy.json bandit.json'
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## What's new

### v0.1.2

- **uv-managed Python projects**: Trivy reports against `uv.lock` or `Python` labels are now recognized, and the deterministic fixer calls `uv lock --upgrade-package` to update lockfiles correctly (no manual lockfile editing).
- **Poetry support**: same idea via `poetry update <pkg>`.
- **Smarter cross-target dedup**: same CVE reported under both `Python` and `uv.lock` collapses to one finding.
- **Container-base aggregation**: when an image has dozens of OS-package CVEs (libncurses, libsystemd, ...), they now collapse to one Dockerfile-bump finding instead of N separate AI calls.
- **AI refusal handling**: when Claude correctly decides no safe fix is possible (e.g. rolling base-image tags), the result is classified as a principled skip with the AI's reasoning, not a failure.
- **Prompt delivery**: prompts are now sent to Claude Code via stdin instead of positional args (more robust across CLI versions).

### v0.1.1

- Fixed `--print` argument handling for Claude Code
- Added container-base finding aggregation

### v0.1.0

- Per-repo config (`vulnfix.yml`) with per-scanner overrides for mode, severity threshold, ignored rules
- Verification loop: every code fix is re-scanned; unverified changes roll back automatically
- Cross-scanner dedup: same CVE reported by Trivy and Grype = one finding, one fix
- Initial scanner support: Trivy, Bandit, Semgrep, gitleaks, Grype
- Telemetry hook for the upcoming vulnfix Cloud dashboard (off by default, anonymized when on)

## Architecture

```
reports -> adapters -> Finding model -> config filter -> dedupe -> sort
                                                                    |
                                                                    v
                                              +- deterministic fixer (version bumps)
                                              |
                                              +- AI fixer (Claude Code, sandboxed)
                                              |
                                              v
                                          verifier (re-scan)
                                              |
                                              +- verified -> commit + PR
                                              |
                                              +- not verified -> git checkout (rollback)
                                              |
                                              v
                                         telemetry event
                                          /          \
                                  local JSON      vulnfix Cloud
```

Every layer is pluggable. Add a scanner: subclass `ScannerAdapter`. Add a VCS: subclass `VCSAdapter`. Add a fixer: drop a class in `fixers/`.

## Configuration reference

See `examples/vulnfix.yml`. Highlights:

- `defaults.mode`: `disabled` | `comment_only` | `pr` | `auto_merge`
- `scanners.<name>.mode`: per-scanner override (e.g. trust Trivy on auto_merge, force gitleaks to comment_only)
- `scanners.<name>.ignore_rules`: silence noisy rules without disabling the scanner
- `paths.ignore`: glob patterns; matching findings are skipped
- `ai.enabled`: turn off the AI fixer for pure deterministic mode
- `telemetry.endpoint`: SaaS endpoint (BYOK)

## CLI

```bash
vulnfix --reports trivy.json bandit.json --min-severity high --open-pr
vulnfix --reports trivy.json --dry-run        # show what would be fixed
vulnfix --list-scanners                        # show supported scanners
```

## Roadmap

- [ ] GitLab CI / MR support (adapter stub in place)
- [ ] Snyk + Checkov adapters
- [ ] vulnfix Cloud dashboard: cross-repo aggregation, MTTR, fix success rate
- [ ] BYO-LLM: route to OpenAI/Aider as a fallback
- [ ] SARIF output (for GitHub code scanning integration)

## License

Apache-2.0
