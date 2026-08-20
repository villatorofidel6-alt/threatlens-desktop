"""Static format inspection. This module never maps, loads, or executes targets."""

from __future__ import annotations

import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from threatlens.analyzers.entropy import shannon_entropy
from threatlens.models import Finding, Severity


@dataclass
class StructureResult:
    metadata: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    limits: list[str] = field(default_factory=list)


SUSPICIOUS_IMPORTS = {
    "virtualalloc": Severity.MEDIUM,
    "virtualprotect": Severity.MEDIUM,
    "writeprocessmemory": Severity.HIGH,
    "createremotethread": Severity.HIGH,
    "queueuserapc": Severity.HIGH,
    "urldownloadtofile": Severity.MEDIUM,
    "winexec": Severity.MEDIUM,
    "shellexecute": Severity.LOW,
}


def _parse_pe(path: Path) -> StructureResult:
    result = StructureResult(metadata={"format": "PE"})
    try:
        import pefile  # type: ignore[import-not-found]
    except ImportError:
        result.limits.append("PE import/export analysis is available after installing the optional 'pe' dependency.")
        return result
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            ]
        )
        sections: list[dict[str, Any]] = []
        for section in pe.sections:
            raw = section.get_data()[:2 * 1024 * 1024]
            name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            entropy = round(shannon_entropy(raw), 4)
            sections.append(
                {
                    "name": name,
                    "virtual_size": int(section.Misc_VirtualSize),
                    "raw_size": int(section.SizeOfRawData),
                    "entropy": entropy,
                }
            )
            if entropy >= 7.4:
                result.findings.append(
                    Finding(
                        id="pe.high-entropy-section",
                        category="reversing",
                        severity=Severity.MEDIUM,
                        title="High-entropy PE section",
                        evidence=f"Section {name or '<unnamed>'} has entropy {entropy:.2f}.",
                        recommendation="High entropy can indicate packing, encryption, or compressed resources. Verify the file origin and inspect only in an authorized isolated workflow.",
                    )
                )
        imports: list[str] = []
        for library in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            library_name = library.dll.decode("ascii", errors="replace")
            for entry in library.imports:
                symbol = entry.name.decode("ascii", errors="replace") if entry.name else f"ordinal:{entry.ordinal}"
                imports.append(f"{library_name}!{symbol}")
                severity = SUSPICIOUS_IMPORTS.get(symbol.lower())
                if severity:
                    result.findings.append(
                        Finding(
                            id=f"pe.import.{symbol.lower()}",
                            category="imports",
                            severity=severity,
                            title="Security-sensitive PE import",
                            evidence=f"The import table includes {library_name}!{symbol}.",
                            recommendation="Review the imported function in context. It can be legitimate, but it is commonly relevant to process injection, dynamic loading, or network retrieval investigations.",
                        )
                    )
        exports = [
            symbol.name.decode("ascii", errors="replace") if symbol.name else f"ordinal:{symbol.ordinal}"
            for symbol in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])
        ]
        result.metadata.update(
            {
                "machine": int(pe.FILE_HEADER.Machine),
                "timestamp": int(pe.FILE_HEADER.TimeDateStamp),
                "is_dll": bool(pe.is_dll()),
                "imphash": pe.get_imphash(),
                "sections": sections,
                "imports": imports[:250],
                "exports": exports[:250],
            }
        )
    except Exception as exc:  # malformed PEs are normal in triage
        result.limits.append(f"PE parsing did not complete: {type(exc).__name__}.")
    return result


def _parse_elf(path: Path) -> StructureResult:
    result = StructureResult(metadata={"format": "ELF"})
    try:
        header = path.read_bytes()[:64]
        if len(header) < 20:
            raise ValueError("truncated ELF header")
        elf_class = {1: "32-bit", 2: "64-bit"}.get(header[4], "unknown")
        byte_order = "little" if header[5] == 1 else "big" if header[5] == 2 else "unknown"
        if byte_order == "unknown":
            raise ValueError("unknown ELF byte order")
        result.metadata.update(
            {
                "class": elf_class,
                "byte_order": byte_order,
                "type": int.from_bytes(header[16:18], byte_order),
                "machine": int.from_bytes(header[18:20], byte_order),
            }
        )
    except (OSError, ValueError) as exc:
        result.limits.append(f"ELF header parsing did not complete: {type(exc).__name__}.")
    return result


def _parse_zip(path: Path) -> StructureResult:
    result = StructureResult(metadata={"format": "ZIP"})
    try:
        with zipfile.ZipFile(path) as archive:
            items = archive.infolist()
            encrypted = [entry.filename for entry in items if entry.flag_bits & 0x1]
            uncompressed = sum(entry.file_size for entry in items)
            compressed = sum(entry.compress_size for entry in items)
            ratio = round(uncompressed / compressed, 2) if compressed else None
            result.metadata.update(
                {
                    "entries": [entry.filename[:300] for entry in items[:250]],
                    "entry_count": len(items),
                    "total_uncompressed_bytes": uncompressed,
                    "total_compressed_bytes": compressed,
                    "compression_ratio": ratio,
                    "encrypted_entries": encrypted[:100],
                }
            )
            if encrypted:
                result.findings.append(
                    Finding(
                        id="zip.encrypted-content",
                        category="encryption",
                        severity=Severity.LOW,
                        title="Encrypted ZIP entries",
                        evidence=f"{len(encrypted)} archive entry or entries require a password to inspect.",
                        recommendation="Request authorization and a password from the file owner. ThreatLens does not attempt password recovery or decryption.",
                    )
                )
            if ratio and ratio > 100:
                result.findings.append(
                    Finding(
                        id="zip.high-compression-ratio",
                        category="archive",
                        severity=Severity.MEDIUM,
                        title="Unusually high ZIP compression ratio",
                        evidence=f"The archive claims a compression ratio of {ratio}:1.",
                        recommendation="Do not extract automatically. Validate the archive in a controlled environment with resource limits.",
                    )
                )
    except (OSError, zipfile.BadZipFile) as exc:
        result.limits.append(f"ZIP central-directory parsing did not complete: {type(exc).__name__}.")
    return result


def _parse_pdf(evidence: bytes) -> StructureResult:
    result = StructureResult(metadata={"format": "PDF"})
    indicators = {
        b"/JavaScript": ("pdf.javascript", Severity.HIGH, "Embedded PDF JavaScript"),
        b"/OpenAction": ("pdf.open-action", Severity.MEDIUM, "Automatic PDF open action"),
        b"/Launch": ("pdf.launch-action", Severity.HIGH, "PDF launch action"),
        b"/EmbeddedFile": ("pdf.embedded-file", Severity.MEDIUM, "Embedded PDF file object"),
        b"/Encrypt": ("pdf.encrypted", Severity.LOW, "Encrypted PDF marker"),
    }
    found = []
    for marker, (id_, severity, title) in indicators.items():
        if marker in evidence:
            found.append(marker.decode("ascii"))
            recommendation = (
                "Request a password from the owner; ThreatLens reports encryption but does not attempt decryption."
                if id_ == "pdf.encrypted"
                else "Validate the document origin and inspect it only with document protections enabled."
            )
            result.findings.append(
                Finding(
                    id=id_,
                    category="document",
                    severity=severity,
                    title=title,
                    evidence=f"The PDF byte stream contains {marker.decode('ascii')}.",
                    recommendation=recommendation,
                )
            )
    result.metadata["structural_markers"] = found
    return result


def analyze_static_structure(path: Path, evidence: bytes, format_label: str) -> StructureResult:
    """Inspect supported file structures without changing or executing the target."""
    if format_label == "PE executable":
        return _parse_pe(path)
    if format_label == "ELF executable":
        return _parse_elf(path)
    if format_label == "ZIP archive":
        return _parse_zip(path)
    if format_label == "PDF document":
        return _parse_pdf(evidence)
    return StructureResult(metadata={"format": format_label})
