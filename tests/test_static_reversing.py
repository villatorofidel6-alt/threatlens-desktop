from __future__ import annotations

import zipfile
from pathlib import Path

from threatlens.analyzers.file_analyzer import analyze_file
from threatlens.analyzers.yara_scanner import scan_bundled_rules


def test_zip_metadata_is_static_and_lists_entries(tmp_path: Path) -> None:
    target = tmp_path / "sample.zip"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("notes.txt", "safe test content")

    report = analyze_file(target)

    assert report.metadata["reversing"]["format"] == "ZIP"
    assert report.metadata["reversing"]["entries"] == ["notes.txt"]


def test_pdf_structural_markers_produce_findings(tmp_path: Path) -> None:
    target = tmp_path / "document.pdf"
    target.write_bytes(b"%PDF-1.7\n1 0 obj << /OpenAction 2 0 R /JavaScript (noop) >> endobj")

    report = analyze_file(target)
    ids = {finding.id for finding in report.findings}

    assert "pdf.open-action" in ids
    assert "pdf.javascript" in ids


def test_elf_header_returns_static_metadata(tmp_path: Path) -> None:
    target = tmp_path / "program.elf"
    target.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x02\x00\x3e\x00" + b"\x00" * 44)

    report = analyze_file(target)

    assert report.metadata["reversing"]["format"] == "ELF"
    assert report.metadata["reversing"]["class"] == "64-bit"


def test_bundled_yara_rules_match_local_fixture(tmp_path: Path) -> None:
    target = tmp_path / "marker.bin"
    target.write_bytes(b"inert fixture: UPX0")

    findings, limitation = scan_bundled_rules(target)

    assert limitation is None
    assert any(finding.id == "yara.threatlens_upx_packer" for finding in findings)
