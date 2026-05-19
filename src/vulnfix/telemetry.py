"""Telemetry — structured fix events.

This is the boundary the SaaS sits behind. Local runs always write a JSON
event file. If ``telemetry.endpoint`` is configured AND a ``VULNFIX_API_KEY``
secret is available, we also POST to the SaaS.

Event schema is intentionally stable and forward-compatible — the SaaS
ingestion code will pin to this shape.
"""
from __future__ import annotations

import json
import os
import platform
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from vulnfix import __version__
from vulnfix.config import TelemetryConfig


@dataclass
class FixEvent:
    """Single fix attempt. Multiple per run."""
    finding_id: str
    scanner: str
    rule_id: str
    severity: str
    kind: str
    strategy: str        # "deterministic" | "ai_claude_code"
    success: bool
    verified: bool
    files_changed: list[str]
    duration_ms: int
    summary: str


@dataclass
class RunEvent:
    """One vulnfix run = one of these, with N FixEvents inside."""
    schema_version: int = 1
    run_id: str = ""
    repo_slug: str = ""
    started_at: str = ""
    finished_at: str = ""
    vulnfix_version: str = __version__
    platform: str = field(default_factory=lambda: platform.platform())
    findings_considered: int = 0
    fixes: list[FixEvent] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


class TelemetryEmitter:
    def __init__(self, config: TelemetryConfig, workdir: Path):
        self.config = config
        self.workdir = workdir
        self.api_key = os.environ.get(config.api_key_env) if config.endpoint else None

    def emit(self, event: RunEvent) -> None:
        # Always write the local file so users can debug.
        local_path = self.workdir / ".vulnfix" / "last-run.json"
        local_path.parent.mkdir(exist_ok=True)
        local_path.write_text(json.dumps(event.to_dict(), indent=2), encoding="utf-8")

        # SaaS POST is opt-in: requires endpoint + key.
        if self.config.endpoint and self.api_key:
            self._post(event)

    def _post(self, event: RunEvent) -> None:
        payload = event.to_dict()
        if self.config.anonymous:
            # Strip identifying info — repo slug becomes a hash.
            import hashlib
            payload["repo_slug"] = hashlib.sha256(payload["repo_slug"].encode()).hexdigest()[:16]

        req = urllib.request.Request(
            self.config.endpoint,
            data=json.dumps(payload).encode(),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "User-Agent": f"vulnfix/{__version__}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10):
                pass
        except (urllib.error.URLError, TimeoutError) as e:
            # Never fail a run because telemetry didn't post.
            print(f"[telemetry] failed to post: {e}")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_run_id() -> str:
    import uuid
    return uuid.uuid4().hex[:12]
