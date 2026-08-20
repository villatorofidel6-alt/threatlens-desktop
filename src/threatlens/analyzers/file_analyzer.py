"""Streaming, non-executing static file analysis."""

from __future__ import annotations

import hashlib
import mimetypes
import re
from pathlib import Path
from typing import Iterable

from threatlens.analyzers.entropy import shannon_entropy
from threatlens.analyzers.rules import match_basic_rules
from threatlens.analyzers.static_reversing import analyze_static_structure
from threatlens.analyzers.yara_scanner import scan_bundled_rules
from threatlens.models import AnalysisReport, Finding, Severity


BLOCK_SIZE = 65_536
MAX_FILE_SIZE = 250 * 1024 * 1024
MAX_STRING_BYTES = 16 * 1024 * 1024
MAX_STRINGS = 250
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024

MAGIC_TYPES: tuple[tuple[bytes, str, str], ...] = (
    (b"MZ", "application/vnd.microsoft.portable-executable", "PE executable"),
    (b"\x7fELF", "application/x-elf", "ELF executable"),
    (b"PK\x03\x04", "application/zip", "ZIP archive"),
    (b"%PDF-", "application/pdf", "PDF document"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage", "OLE compound document"),
    (b"\x1f\x8b", "application/gzip", "GZip archive"),
    (b"\x89PNG\r\n\x1a\n", "image/png", "PNG image"),
    (b"\xff\xd8\xff", "image/jpeg", "JPEG image"),
)

STRING_PATTERNS: tuple[re.Pattern[bytes], ...] = (
    re.compile(rb"[\x20-\x7e]{4,}"),
    re.compile(rb"(?:[\x20-\x7e]\x00){4,}"),
)

TEXT_INDICATORS: tuple[tuple[str, str, Severity, re.Pattern[str], str, str], ...] = (
    (
        "backdoor.powershell-encoded",
        "execution",
        Severity.HIGH,
        re.compile(r"(?is)powershell.{0,96}-(?:enc|encodedcommand)\b"),
        "PowerShell invocation with an encoded command switch found in extracted strings.",
        "Review the decoded content only in an approved isolated workflow; validate the source before execution.",
    ),
    (
        "persistence.scheduler-registry",
        "persistence",
        Severity.MEDIUM,
        re.compile(r"(?i)\b(?:reg add|schtasks(?:\.exe)?|crontab\s+-e|systemctl\s+enable)\b"),
        "A persistence-related command pattern was found in extracted strings.",
        "Verify whether the command is expected. If not, isolate the file and inspect host persistence mechanisms.",
    ),
    (
        "network.c2-pattern",
        "network",
        Severity.MEDIUM,
        re.compile(r"(?i)\b(?:ngrok|discord(?:app)?\.com/api/webhooks|pastebin\.com|/gate\.php|/panel\.php)\b"),
        "A string associated with common command-and-control or staging patterns was found.",
        "Validate destination ownership and block unapproved outbound connections while the file is investigated.",
    ),
    (
        "macro.autoexec",
        "macro",
        Severity.HIGH,
        re.compile(r"(?i)\b(?:autoopen|document_open|workbook_open|shell\s*\()\b"),
        "An Office macro auto-execution or command-launch pattern was found.",
        "Keep macros disabled, verify document provenance, and inspect in a controlled document-analysis process.",
    ),
    (
        "obfuscation.base64-blob",
        "obfuscation",
        Severity.LOW,
        re.compile(r"(?:[A-Za-z0-9+/]{96,}={0,2})"),
        "A long Base64-like string was found.",
        "Review the context; long encoded blobs can be legitimate resources but warrant validation in scripts and documents.",
    ),
)


def detect_type(header: bytes, filename: str) -> tuple[str, str]:
    for magic, mime, label in MAGIC_TYPES:
        if header.startswith(magic):
            return mime, label
    guessed, _ = mimetypes.guess_type(filename)
    return guessed or "application/octet-stream", "Unknown binary or text"


def extract_strings(data: bytes) -> list[str]:
    """Extract a bounded selection of printable strings for investigation."""
    values: list[str] = []
    seen: set[str] = set()
    for pattern in STRING_PATTERNS:
        for match in pattern.finditer(data):
            raw = match.group()
            if b"\x00" in raw:
                value = raw.decode("utf-16le", errors="ignore")
            else:
                value = raw.decode("ascii", errors="ignore")
            value = value.strip()
            if value and value not in seen:
                seen.add(value)
                values.append(value[:300])
                if len(values) >= MAX_STRINGS:
                    return values
    return values


def _entropy_summary(path: Path) -> tuple[dict[str, object], bytes]:
    hashers = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256")}
    blocks: list[tuple[int, float]] = []
    evidence = bytearray()
    size = 0
    with path.open("rb") as handle:
        offset = 0
        while chunk := handle.read(BLOCK_SIZE):
            size += len(chunk)
            if size > MAX_FILE_SIZE:
                raise ValueError(f"File exceeds the {MAX_FILE_SIZE // (1024 * 1024)} MiB analysis limit")
            for hasher in hashers.values():
                hasher.update(chunk)
            entropy = round(shannon_entropy(chunk), 4)
            blocks.append((offset, entropy))
            offset += len(chunk)
            if len(evidence) < MAX_EVIDENCE_BYTES:
                evidence.extend(chunk[: MAX_EVIDENCE_BYTES - len(evidence)])
    values = [entropy for _, entropy in blocks]
    high_entropy = [
        {"offset": offset, "entropy": entropy}
        for offset, entropy in blocks
        if entropy >= 7.4
    ][:20]
    return {
        "size_bytes": size,
        "hashes": {name: hasher.hexdigest() for name, hasher in hashers.items()},
        "entropy": {
            "block_size": BLOCK_SIZE,
            "block_count": len(blocks),
            "average": round(sum(values) / len(values), 4) if values else 0.0,
            "maximum": max(values, default=0.0),
            "high_entropy_blocks": high_entropy,
        },
    }, bytes(evidence)


def _indicator_findings(strings: Iterable[str], evidence: bytes, entropy: dict[str, object]) -> list[Finding]:
    findings = match_basic_rules(evidence)
    joined = "\n".join(strings)
    for id_, category, severity, pattern, evidence_text, recommendation in TEXT_INDICATORS:
        if pattern.search(joined):
            findings.append(
                Finding(
                    id=id_,
                    category=category,
                    severity=severity,
                    title=id_.replace(".", " ").replace("-", " ").title(),
                    evidence=evidence_text,
                    recommendation=recommendation,
                )
            )
    maximum = float(entropy.get("maximum", 0.0))
    high_blocks = entropy.get("high_entropy_blocks", [])
    if maximum >= 7.8 and high_blocks:
        findings.append(
            Finding(
                id="entropy.high",
                category="obfuscation",
                severity=Severity.MEDIUM,
                title="High-entropy content",
                evidence=f"At least one {BLOCK_SIZE}-byte block reached entropy {maximum:.2f}.",
                recommendation="High entropy may indicate compression, encryption, or packing. Confirm file provenance and inspect structure without execution.",
            )
        )
    return findings


def analyze_file(path_value: str | Path) -> AnalysisReport:
    """Analyze a regular file as bytes only; never execute, import, or open it."""
    path = Path(path_value).expanduser()
    if path.is_symlink() or not path.is_file():
        raise ValueError("Select a regular, non-symlink file for analysis")
    path = path.resolve()
    metadata, evidence = _entropy_summary(path)
    header = evidence[:32]
    mime, format_label = detect_type(header, path.name)
    string_bytes = evidence[:MAX_STRING_BYTES]
    strings = extract_strings(string_bytes)
    metadata.update(
        {
            "filename": path.name,
            "mime_type": mime,
            "format": format_label,
            "strings": strings,
            "strings_extracted": len(strings),
        }
    )
    limits = [
        "The target was treated as bytes and never executed, imported, opened, or decrypted.",
        f"String and signature evidence is limited to the first {MAX_EVIDENCE_BYTES // (1024 * 1024)} MiB.",
    ]
    if metadata["size_bytes"] > MAX_STRING_BYTES:
        limits.append("String extraction is bounded and may omit strings outside the inspected evidence window.")
    findings = _indicator_findings(strings, evidence, metadata["entropy"])
    structure = analyze_static_structure(path, evidence, format_label)
    metadata["reversing"] = structure.metadata
    findings.extend(structure.findings)
    limits.extend(structure.limits)
    yara_findings, yara_limit = scan_bundled_rules(path)
    findings.extend(yara_findings)
    if yara_limit:
        limits.append(yara_limit)
    return AnalysisReport(
        target=str(path),
        target_type="file",
        metadata=metadata,
        findings=findings,
        analysis_limits=limits,
    )
