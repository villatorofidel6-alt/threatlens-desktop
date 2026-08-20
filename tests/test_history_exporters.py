from __future__ import annotations

import json
from pathlib import Path

from threatlens.exporters import as_html, as_json, as_text, write_report
from threatlens.history import HistoryStore
from threatlens.models import AnalysisReport, Finding, Severity


def _report() -> AnalysisReport:
    return AnalysisReport(
        target="/safe/fixture.bin",
        target_type="file",
        metadata={"hashes": {"sha256": "a" * 64}, "filename": "fixture.bin"},
        findings=[
            Finding(
                id="fixture.indicator",
                category="test",
                severity=Severity.MEDIUM,
                title="Fixture indicator",
                evidence="A safe test marker was found.",
                recommendation="Review the fixture context.",
            )
        ],
        analysis_limits=["No executable fixture was used."],
    )


def test_history_persists_and_searches_by_hash_and_name(tmp_path: Path) -> None:
    store = HistoryStore(tmp_path / "history.sqlite3")
    report = _report()
    record_id = store.save(report)

    by_hash = store.search("a" * 24)
    by_name = store.search("fixture")

    assert record_id > 0
    assert by_hash[0]["target"] == report.target
    assert by_name[0]["risk_score"] == report.risk_score
    assert by_name[0]["report"]["findings"][0]["id"] == "fixture.indicator"


def test_exporters_generate_json_html_and_text(tmp_path: Path) -> None:
    report = _report()
    json_text = as_json(report)
    html_text = as_html(report)
    plain_text = as_text(report)
    destination = tmp_path / "report.html"

    assert json.loads(json_text)["risk_score"] == report.risk_score
    assert "ThreatLens Desktop" in html_text
    assert "Fixture indicator" in plain_text
    write_report(report, destination, "html")
    assert "Fixture indicator" in destination.read_text(encoding="utf-8")
