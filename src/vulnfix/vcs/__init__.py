"""VCS package — pick an adapter based on environment."""
from __future__ import annotations

import os
from pathlib import Path

from vulnfix.vcs.github import GitHubAdapter, VCSAdapter


def auto_adapter(workdir: Path) -> VCSAdapter:
    """Pick GitHub or GitLab based on CI env. GitLab adapter is TODO."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return GitHubAdapter(workdir)
    if os.environ.get("GITLAB_CI") == "true":
        raise NotImplementedError(
            "GitLab adapter not yet implemented. See ROADMAP.md."
        )
    # Default to GitHub if we have a token; users can override.
    if os.environ.get("GITHUB_TOKEN"):
        return GitHubAdapter(workdir)
    raise RuntimeError(
        "Could not detect VCS environment. Set GITHUB_ACTIONS=true or GITLAB_CI=true."
    )


__all__ = ["auto_adapter", "GitHubAdapter", "VCSAdapter"]
