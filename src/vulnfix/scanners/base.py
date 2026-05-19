"""Base class for all scanner adapters.

To add a new scanner, subclass ``ScannerAdapter`` and implement ``parse``.
Register the new class in ``vulnfix.scanners.__init__`` so the CLI sees it.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable

from vulnfix.models.finding import Finding


class ScannerAdapter(ABC):
    """Parse a scanner's output file into normalized ``Finding`` objects."""

    name: str = "unknown"

    @abstractmethod
    def parse(self, report_path: Path) -> Iterable[Finding]:
        """Yield findings from a report file produced by this scanner."""
        ...

    def supports(self, report_path: Path) -> bool:
        """Heuristic check that this adapter can handle the file. Override
        for stricter detection (e.g. inspect JSON top-level keys)."""
        return report_path.suffix.lower() in {".json", ".sarif"}
