# ThreatLens Desktop

> **A local desktop application for defensive static triage of files, URLs, and domains.**

[Documentación en español](README.md) · [Architecture](ARCHITECTURE.md) · [Responsible use](docs/USO-RESPONSABLE.md)

ThreatLens Desktop gathers reviewable technical evidence without executing samples or relying on a browser. It reads files as bytes, inspects public URLs through bounded HTTP requests, and presents risk scoring, categorized findings, evidence, and remediation guidance. It does not replace an isolated analysis lab, digital forensics workflow, or professional incident response.

## Core capabilities

| Area | Capability |
|---|---|
| Files | MD5, SHA-1, SHA-256, size, magic-based type, block entropy, and ASCII/UTF-16LE string extraction. |
| Indicators | Explainable UPX/MPRESS, shellcode, persistence, macro, obfuscation, C2, and local bundled YARA signals. |
| Static reversing | PE, ELF, ZIP, and PDF inspection; PE can expose sections, imports, exports, and imphash through optional `pefile`. |
| URLs and domains | Bounded HTTP, redirects, selected headers, static HTML, inline scripts, hidden iframes, external forms, and staging/C2 patterns. |
| Results | A 0–100 risk score, severity, categorized findings, remediation guidance, and analysis boundaries. |
| Privacy | Local SQLite history plus local JSON, HTML, and plain-text export. |

## Safety boundaries

ThreatLens does **not execute, load, import, open with the operating system, automatically extract, emulate, or decrypt** an analyzed file. URL inspection uses no browser or JavaScript engine, limits bodies to 512 KiB, permits at most five redirects, and blocks local/private/loopback/special-use network targets. Findings are investigation signals, not malware verdicts.

## Install and run

Python 3.11+ is required for source installs. The core engine uses the standard library; `pefile` and YARA are optional extras.

```bash
git clone https://github.com/villatorofidel6-alt/threatlens-desktop.git
cd threatlens-desktop
python -m venv .venv
# Activate the environment for your operating system, then:
python -m pip install -e ".[pe,rules]"
threatlens gui
```

CLI examples:

```bash
threatlens scan-file ./untrusted.bin --format html --output report.html
threatlens scan-url https://example.org --format json --output report.json
threatlens history "hash-prefix"
```

## Native packages

GitHub Actions builds native Windows, Linux, and macOS artifacts using PyInstaller. PyInstaller bundles a Python application and dependencies, but native artifacts must be built on their target operating system; the repository uses a platform matrix for that reason. [1]

## Credits

**Creator and founder:** Lumen AI  
**GitHub:** [@villatorofidel6-alt](https://github.com/villatorofidel6-alt)  
**Discord:** `px1j`

## References

[1] [PyInstaller Manual](https://www.pyinstaller.org/)

[2] [YARA Documentation](https://yara.readthedocs.io/)

[3] [pefile documentation](https://pefile.readthedocs.io/en/latest/modules/pefile.html)
