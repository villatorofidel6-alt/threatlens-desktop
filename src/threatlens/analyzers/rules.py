"""Small, explainable built-in signature rules.

These are intentionally conservative triage indicators, not malware verdicts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from threatlens.models import Finding, Severity


@dataclass(frozen=True)
class BasicRule:
    id: str
    category: str
    severity: Severity
    title: str
    byte_markers: tuple[bytes, ...]
    evidence: str
    recommendation: str
    match_all: bool = False


BASIC_RULES: tuple[BasicRule, ...] = (
    BasicRule(
        id="packer.upx",
        category="packing",
        severity=Severity.MEDIUM,
        title="UPX packing marker",
        byte_markers=(b"UPX0", b"UPX1", b"UPX!"),
        evidence="UPX-related marker found in the inspected byte range.",
        recommendation="Treat packed code as higher-risk until unpacked and reviewed in an isolated, authorized environment.",
    ),
    BasicRule(
        id="packer.mpress",
        category="packing",
        severity=Severity.MEDIUM,
        title="MPRESS packing marker",
        byte_markers=(b"MPRESS1", b"MPRESS2"),
        evidence="MPRESS-related marker found in the inspected byte range.",
        recommendation="Confirm the file provenance and inspect only through approved static-analysis procedures.",
    ),
    BasicRule(
        id="shellcode.common-prologue",
        category="shellcode",
        severity=Severity.HIGH,
        title="Common shellcode byte sequence",
        byte_markers=(b"\xfc\xe8\x82\x00\x00\x00", b"\x31\xc0\x50\x68"),
        evidence="A byte sequence commonly seen in position-independent shellcode was detected.",
        recommendation="Do not execute the file. Preserve the hash and review the surrounding bytes in an authorized isolated workflow.",
    ),
)


def match_basic_rules(data: bytes) -> list[Finding]:
    """Match byte markers without executing or transforming the target."""
    findings: list[Finding] = []
    for rule in BASIC_RULES:
        matches = [marker in data for marker in rule.byte_markers]
        matched = all(matches) if rule.match_all else any(matches)
        if matched:
            findings.append(
                Finding(
                    id=rule.id,
                    category=rule.category,
                    severity=rule.severity,
                    title=rule.title,
                    evidence=rule.evidence,
                    recommendation=rule.recommendation,
                )
            )
    return findings


def yara_style_source() -> str:
    """Return an auditable YARA-compatible representation of basic rules."""
    return """rule ThreatLens_UPX_Packer {
  strings:
    $upx0 = \"UPX0\"
    $upx1 = \"UPX1\"
    $upx = \"UPX!\"
  condition:
    any of them
}

rule ThreatLens_MPRESS_Packer {
  strings:
    $mpress1 = \"MPRESS1\"
    $mpress2 = \"MPRESS2\"
  condition:
    any of them
}
"""
