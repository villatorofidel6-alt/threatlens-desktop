"""Application service that dispatches analysis and persists local history."""

from __future__ import annotations

from pathlib import Path

from threatlens.analyzers.file_analyzer import analyze_file
from threatlens.analyzers.url_analyzer import analyze_url
from threatlens.history import HistoryStore
from threatlens.models import AnalysisReport


class AnalysisService:
    def __init__(self, history: HistoryStore | None = None) -> None:
        self.history = history or HistoryStore()

    def analyze_file(self, target: str | Path) -> AnalysisReport:
        report = analyze_file(target)
        self.history.save(report)
        return report

    def analyze_url(self, target: str) -> AnalysisReport:
        report = analyze_url(target)
        self.history.save(report)
        return report
