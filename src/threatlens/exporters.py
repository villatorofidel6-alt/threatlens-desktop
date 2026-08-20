"""Portable local report exporters."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from threatlens.models import AnalysisReport


def as_json(report: AnalysisReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"


def as_text(report: AnalysisReport) -> str:
    lines = [
        "ThreatLens Desktop — Static Analysis Report",
        f"Target: {report.target}",
        f"Target type: {report.target_type}",
        f"Analyzed at: {report.analyzed_at}",
        f"Risk: {report.risk_score}/100 ({report.risk_level.upper()})",
        "",
        "Category summary:",
    ]
    lines.extend(f"  - {category}: {count}" for category, count in report.category_summary.items())
    lines.append("\nFindings:")
    if not report.findings:
        lines.append("  No findings were produced by the enabled static checks.")
    for finding in report.findings:
        lines.extend(
            [
                f"  [{finding.severity.value.upper()}] {finding.title}",
                f"    Category: {finding.category} | ID: {finding.id}",
                f"    Evidence: {finding.evidence}",
                f"    Recommendation: {finding.recommendation}",
            ]
        )
    lines.extend(["", "Analysis limits:"])
    lines.extend(f"  - {limit}" for limit in report.analysis_limits)
    lines.extend(["", "Credits: Created and founded by Lumen AI. GitHub: @villatorofidel6-alt. Discord: px1j."])
    return "\n".join(lines) + "\n"


def as_html(report: AnalysisReport) -> str:
    details = html.escape(json.dumps(report.metadata, indent=2, ensure_ascii=False))
    finding_rows = "".join(
        "<tr>"
        f"<td><span class='severity {html.escape(finding.severity.value)}'>{html.escape(finding.severity.value)}</span></td>"
        f"<td>{html.escape(finding.category)}</td>"
        f"<td><strong>{html.escape(finding.title)}</strong><br><small>{html.escape(finding.id)}</small></td>"
        f"<td>{html.escape(finding.evidence)}</td>"
        f"<td>{html.escape(finding.recommendation)}</td>"
        "</tr>"
        for finding in report.findings
    ) or "<tr><td colspan='5'>No findings were produced by the enabled static checks.</td></tr>"
    summary_rows = "".join(
        f"<li><strong>{html.escape(category)}</strong>: {count}</li>" for category, count in report.category_summary.items()
    ) or "<li>No categorized findings.</li>"
    limit_rows = "".join(f"<li>{html.escape(limit)}</li>" for limit in report.analysis_limits)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>ThreatLens report</title>
<style>
body {{ background:#0a101b;color:#d7e0ea;font:15px/1.5 system-ui,sans-serif;margin:0;padding:32px; }}
main {{ max-width:1200px;margin:auto; }} h1 {{ color:#92d7ff; }} .score {{ font-size:2.2rem;font-weight:700;color:#f9c74f; }}
section {{ background:#101b2c;border:1px solid #243552;border-radius:12px;padding:20px;margin:16px 0; }}
table {{ border-collapse:collapse;width:100%; }} th,td {{ text-align:left;padding:10px;border-bottom:1px solid #263955;vertical-align:top; }}
.severity {{ display:inline-block;padding:2px 8px;border-radius:99px;font-size:.75rem;font-weight:700;text-transform:uppercase; }}
.critical,.high {{ background:#5b1721;color:#ffd7db; }} .medium {{ background:#5b4715;color:#fff0ad; }} .low,.info {{ background:#153e55;color:#b9e7ff; }}
pre {{ white-space:pre-wrap;overflow-wrap:anywhere; }} footer {{ color:#9badc2;margin-top:26px; }}
</style></head><body><main>
<h1>ThreatLens Desktop</h1><p>Local-first defensive static analysis report.</p>
<section><div class="score">{report.risk_score}/100 · {html.escape(report.risk_level.upper())}</div>
<p><strong>Target:</strong> {html.escape(report.target)}<br><strong>Analyzed:</strong> {html.escape(report.analyzed_at)}</p></section>
<section><h2>Summary</h2><ul>{summary_rows}</ul></section>
<section><h2>Findings</h2><table><thead><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Evidence</th><th>Recommendation</th></tr></thead><tbody>{finding_rows}</tbody></table></section>
<section><h2>Metadata</h2><pre>{details}</pre></section>
<section><h2>Analysis limits</h2><ul>{limit_rows}</ul></section>
<footer>Created and founded by Lumen AI · GitHub: @villatorofidel6-alt · Discord: px1j</footer>
</main></body></html>"""


def write_report(report: AnalysisReport, destination: Path, format_name: str) -> None:
    renderers = {"json": as_json, "text": as_text, "html": as_html}
    if format_name not in renderers:
        raise ValueError(f"Unsupported report format: {format_name}")
    destination.write_text(renderers[format_name](report), encoding="utf-8")
