"""VCS adapter — abstract over GitHub / GitLab / Bitbucket.

Only the methods listed here are needed for vulnfix. Keep this surface
small so adding a new provider is a few hundred lines, not thousands.
"""
from __future__ import annotations

import os
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class PullRequest:
    url: str
    number: int
    branch: str


class VCSAdapter(ABC):
    @abstractmethod
    def create_branch_commit_push(self, branch: str, message: str, files: list[str]) -> None: ...

    @abstractmethod
    def open_pull_request(
        self, branch: str, base: str, title: str, body: str
    ) -> PullRequest: ...

    @abstractmethod
    def repo_slug(self) -> str: ...


def _run(args: list[str], cwd: Path) -> str:
    return subprocess.run(args, cwd=str(cwd), check=True, capture_output=True, text=True).stdout


class GitHubAdapter(VCSAdapter):
    """Uses the `gh` CLI when available, falling back to the REST API.

    Auth: ``GITHUB_TOKEN`` env var (auto-set by GitHub Actions).
    """

    def __init__(self, workdir: Path, token: Optional[str] = None):
        self.workdir = workdir
        self.token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if not self.token:
            raise RuntimeError("GITHUB_TOKEN is required for GitHub VCS adapter")

    def repo_slug(self) -> str:
        # When run inside a GitHub Action, GITHUB_REPOSITORY is "owner/repo".
        slug = os.environ.get("GITHUB_REPOSITORY")
        if slug:
            return slug
        # Fall back to git remote parsing
        url = _run(["git", "remote", "get-url", "origin"], self.workdir).strip()
        if url.startswith("git@github.com:"):
            return url.removeprefix("git@github.com:").removesuffix(".git")
        if "github.com/" in url:
            return url.split("github.com/")[1].removesuffix(".git")
        raise RuntimeError(f"could not parse repo slug from {url!r}")

    def create_branch_commit_push(self, branch: str, message: str, files: list[str]) -> None:
        _run(["git", "config", "user.email", "vulnfix-bot@users.noreply.github.com"], self.workdir)
        _run(["git", "config", "user.name", "vulnfix-bot"], self.workdir)
        _run(["git", "checkout", "-b", branch], self.workdir)
        if files:
            _run(["git", "add", *files], self.workdir)
        else:
            _run(["git", "add", "-A"], self.workdir)
        _run(["git", "commit", "-m", message], self.workdir)
        # Use token in URL for push auth in Actions environment
        slug = self.repo_slug()
        push_url = f"https://x-access-token:{self.token}@github.com/{slug}.git"
        _run(["git", "push", push_url, branch], self.workdir)

    def open_pull_request(self, branch: str, base: str, title: str, body: str) -> PullRequest:
        import json
        import urllib.request

        slug = self.repo_slug()
        req = urllib.request.Request(
            f"https://api.github.com/repos/{slug}/pulls",
            data=json.dumps({"title": title, "head": branch, "base": base, "body": body}).encode(),
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "User-Agent": "vulnfix",
            },
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
        return PullRequest(url=data["html_url"], number=data["number"], branch=branch)
