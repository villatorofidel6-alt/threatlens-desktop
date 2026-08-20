from __future__ import annotations

from pathlib import Path

import pytest

from threatlens.analyzers.file_analyzer import analyze_file, shannon_entropy


def test_entropy_distinguishes_repetitive_data() -> None:
    assert shannon_entropy(b"A" * 1024) == 0.0
    assert shannon_entropy(bytes(range(256)) * 4) > 7.9


def test_file_analysis_hashes_and_type(tmp_path: Path) -> None:
    target = tmp_path / "sample.pdf"
    target.write_bytes(b"%PDF-1.7\nhello\n")

    report = analyze_file(target)

    assert report.metadata["format"] == "PDF document"
    assert report.metadata["hashes"]["sha256"]
    assert report.metadata["size_bytes"] == target.stat().st_size
    assert report.target_type == "file"


def test_packer_and_macro_indicators_are_reported(tmp_path: Path) -> None:
    target = tmp_path / "suspicious.bin"
    target.write_bytes(b"MZ" + b"UPX0" + b" AutoOpen Shell(\"cmd\") ")

    report = analyze_file(target)
    ids = {finding.id for finding in report.findings}

    assert "packer.upx" in ids
    assert "macro.autoexec" in ids
    assert report.risk_score >= 30


def test_symlinks_are_rejected(tmp_path: Path) -> None:
    real_file = tmp_path / "real.bin"
    real_file.write_bytes(b"safe")
    link = tmp_path / "link.bin"
    link.symlink_to(real_file)

    with pytest.raises(ValueError, match="non-symlink"):
        analyze_file(link)


def test_report_never_executes_target(tmp_path: Path) -> None:
    target = tmp_path / "untrusted.py"
    target.write_text("raise RuntimeError('this must not run')", encoding="utf-8")

    report = analyze_file(target)

    assert report.metadata["filename"] == "untrusted.py"
    assert "never executed" in report.analysis_limits[0]
