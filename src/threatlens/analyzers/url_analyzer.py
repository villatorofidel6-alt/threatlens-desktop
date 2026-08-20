"""Passive, bounded HTTP and HTML inspection without a browser or JavaScript."""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import Iterable

from threatlens.models import AnalysisReport, Finding, Severity


MAX_REDIRECTS = 5
MAX_BODY_BYTES = 512 * 1024
REQUEST_TIMEOUT = 8
USER_AGENT = "ThreatLens-Desktop/0.1 passive-static-analysis"


class UrlAnalysisError(ValueError):
    """Raised when a URL is unsuitable for safe passive analysis."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class _DocumentInspector(HTMLParser):
    """Collect only structural facts from parsed markup; never render or execute it."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.inline_scripts: list[str] = []
        self.iframes: list[dict[str, str]] = []
        self.forms: list[dict[str, str]] = []
        self._in_script = False
        self._script_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): (value or "") for key, value in attrs}
        if tag.lower() == "script" and not values.get("src"):
            self._in_script = True
            self._script_parts = []
        elif tag.lower() == "iframe":
            self.iframes.append(values)
        elif tag.lower() == "form":
            self.forms.append(values)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._in_script:
            self.inline_scripts.append("".join(self._script_parts)[:20_000])
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_parts.append(data)


def _is_public_host(host: str) -> bool:
    """Reject loopback, private, link-local and special-use targets to prevent SSRF."""
    try:
        addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UrlAnalysisError(f"Could not resolve hostname: {host}") from exc
    for _, _, _, _, sockaddr in addresses:
        address = ipaddress.ip_address(sockaddr[0])
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        ):
            return False
    return True


def validate_url(value: str) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(value.strip())
    if parsed.scheme not in {"http", "https"}:
        raise UrlAnalysisError("Only http and https URLs are accepted")
    if not parsed.hostname:
        raise UrlAnalysisError("A hostname is required")
    if parsed.username or parsed.password:
        raise UrlAnalysisError("Credential-bearing URLs are not accepted")
    if not _is_public_host(parsed.hostname):
        raise UrlAnalysisError("Local, private, or special-use network targets are not allowed")
    return parsed


def _safe_headers(headers: object) -> dict[str, str]:
    allowed = ("content-type", "content-length", "server", "last-modified", "location")
    return {
        key: value
        for key, value in getattr(headers, "items")()
        if key.lower() in allowed
    }


def _fetch(url: str) -> tuple[str, int, dict[str, str], bytes, list[dict[str, object]]]:
    opener = urllib.request.build_opener(_NoRedirect)
    chain: list[dict[str, object]] = []
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        parsed = validate_url(current)
        request = urllib.request.Request(current, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1"})
        try:
            response = opener.open(request, timeout=REQUEST_TIMEOUT)
        except urllib.error.HTTPError as error:
            response = error
        except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
            raise UrlAnalysisError(f"Network request failed: {type(exc).__name__}") from exc
        status = int(getattr(response, "status", response.getcode()))
        headers = _safe_headers(response.headers)
        location = response.headers.get("Location")
        chain.append({"url": current, "status": status, "headers": headers})
        if status in {301, 302, 303, 307, 308} and location:
            current = urllib.parse.urljoin(current, location)
            continue
        body = response.read(MAX_BODY_BYTES + 1)
        if len(body) > MAX_BODY_BYTES:
            body = body[:MAX_BODY_BYTES]
            chain[-1]["body_truncated"] = True
        return current, status, headers, body, chain
    raise UrlAnalysisError(f"Redirect limit exceeded ({MAX_REDIRECTS})")


def inspect_html(html: str, hostname: str) -> list[Finding]:
    inspector = _DocumentInspector()
    inspector.feed(html)
    findings: list[Finding] = []

    if hostname.lower().startswith("xn--") or ".xn--" in hostname.lower():
        findings.append(
            Finding(
                id="domain.idn-punycode",
                category="domain",
                severity=Severity.LOW,
                title="Internationalized domain encoding",
                evidence="The hostname contains an xn-- Punycode label.",
                recommendation="Verify the intended domain carefully; encoded internationalized domains can resemble trusted brands.",
            )
        )

    suspicious_scripts = re.compile(r"(?is)\b(?:eval\s*\(|atob\s*\(|fromcharcode|unescape\s*\(|document\.write|settimeout\s*\(\s*['\"])")
    if any(suspicious_scripts.search(script) for script in inspector.inline_scripts):
        findings.append(
            Finding(
                id="web.obfuscated-inline-script",
                category="web-content",
                severity=Severity.MEDIUM,
                title="Potentially obfuscated inline JavaScript",
                evidence="An inline script contains a dynamic execution or decoding pattern.",
                recommendation="Review the script source and origin. Do not execute untrusted content in a browser profile with sensitive sessions.",
            )
        )

    hidden = 0
    for iframe in inspector.iframes:
        style = iframe.get("style", "").lower().replace(" ", "")
        width = iframe.get("width", "")
        height = iframe.get("height", "")
        if "display:none" in style or "visibility:hidden" in style or width == "0" or height == "0":
            hidden += 1
    if hidden:
        findings.append(
            Finding(
                id="web.hidden-iframe",
                category="web-content",
                severity=Severity.MEDIUM,
                title="Hidden iframe detected",
                evidence=f"{hidden} iframe element(s) use hidden styling or zero dimensions.",
                recommendation="Inspect iframe destinations and confirm they are necessary before trusting the page.",
            )
        )

    external_forms = 0
    for form in inspector.forms:
        action = form.get("action", "")
        if not action:
            continue
        destination = urllib.parse.urlparse(urllib.parse.urljoin(f"https://{hostname}", action)).hostname
        if destination and destination.lower() != hostname.lower():
            external_forms += 1
    if external_forms:
        findings.append(
            Finding(
                id="web.external-form-action",
                category="phishing",
                severity=Severity.HIGH,
                title="Form posts to another domain",
                evidence=f"{external_forms} form(s) submit to a domain different from the analyzed host.",
                recommendation="Verify the receiving domain and avoid entering credentials until the relationship is confirmed.",
            )
        )

    c2_markers = re.compile(r"(?i)\b(?:discord(?:app)?\.com/api/webhooks|ngrok|pastebin\.com|/gate\.php|/panel\.php)\b")
    if c2_markers.search(html):
        findings.append(
            Finding(
                id="web.c2-pattern",
                category="network",
                severity=Severity.MEDIUM,
                title="Potential command-and-control or staging pattern",
                evidence="The static HTML contains a string associated with common staging or C2 patterns.",
                recommendation="Validate the endpoint's purpose and block unapproved destinations during investigation.",
            )
        )
    return findings


def analyze_url(url: str) -> AnalysisReport:
    """Fetch a bounded public HTTP resource and inspect only its static response data."""
    initial = validate_url(url)
    final_url, status, headers, body, redirects = _fetch(url)
    final = urllib.parse.urlparse(final_url)
    content_type = headers.get("Content-Type", headers.get("content-type", ""))
    text = body.decode("utf-8", errors="replace") if "html" in content_type.lower() or b"<html" in body[:1024].lower() else ""
    findings = inspect_html(text, final.hostname or initial.hostname or "") if text else []
    if len(redirects) > 1:
        findings.append(
            Finding(
                id="web.redirect-chain",
                category="network",
                severity=Severity.LOW,
                title="Redirect chain observed",
                evidence=f"The URL produced {len(redirects) - 1} redirect(s) before the final response.",
                recommendation="Confirm that each redirect domain is expected and belongs to the intended service.",
            )
        )
    return AnalysisReport(
        target=url,
        target_type="url",
        metadata={
            "final_url": final_url,
            "status": status,
            "response_headers": headers,
            "redirect_chain": redirects,
            "body_bytes_inspected": len(body),
            "html_inspected": bool(text),
        },
        findings=findings,
        analysis_limits=[
            "No browser, JavaScript engine, plug-in, or downloaded file execution was used.",
            f"HTTP response bodies are limited to {MAX_BODY_BYTES // 1024} KiB and redirect chains to {MAX_REDIRECTS} hops.",
            "Local, private, loopback, link-local, and special-use network destinations are rejected.",
        ],
    )
