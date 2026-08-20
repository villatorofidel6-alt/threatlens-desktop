"""Optional YARA integration using only bundled local rules."""

from __future__ import annotations

from importlib import resources
from pathlib import Path

from threatlens.models import Finding, Severity


def scan_bundled_rules(path: Path) -> tuple[list[Finding], str | None]:
    """Run local bundled YARA rules if yara-python is installed; no remote rule feed is used."""
    try:
        import yara  # type: ignore[import-not-found]
    except ImportError:
        return [], "YARA support is optional; install threatlens-desktop[rules] to enable bundled YARA scanning."
    try:
        source = resources.files("threatlens.resources").joinpath("basic_rules.yar")
        rules = yara.compile(filepath=str(source))
        matches = rules.match(str(path), timeout=20)
    except Exception as exc:
        return [], f"Bundled YARA scanning did not complete: {type(exc).__name__}."
    findings = [
        Finding(
            id=f"yara.{match.rule.lower()}",
            category="yara",
            severity=Severity.MEDIUM,
            title=f"Bundled YARA rule matched: {match.rule}",
            evidence="A local built-in YARA-compatible signature matched the file.",
            recommendation="Treat the match as an investigation lead; confirm context and file provenance before taking action.",
        )
        for match in matches
    ]
    return findings, None
