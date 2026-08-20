from __future__ import annotations

import pytest

from threatlens.analyzers.url_analyzer import UrlAnalysisError, inspect_html, validate_url


def test_html_detects_hidden_iframe_external_form_and_script() -> None:
    html = """
    <iframe width='0' height='0' src='https://cdn.example'></iframe>
    <form action='https://collect.example/submit'><input name='password'></form>
    <script>eval(atob('ZGF0YQ=='))</script>
    """
    findings = inspect_html(html, "trusted.example")
    ids = {finding.id for finding in findings}
    assert {"web.hidden-iframe", "web.external-form-action", "web.obfuscated-inline-script"} <= ids


def test_html_detects_punycode_and_c2_marker() -> None:
    findings = inspect_html("<p>ngrok tunnel</p>", "xn--example-9db.test")
    ids = {finding.id for finding in findings}
    assert "domain.idn-punycode" in ids
    assert "web.c2-pattern" in ids


def test_private_url_is_rejected() -> None:
    with pytest.raises(UrlAnalysisError, match="Local, private"):
        validate_url("http://127.0.0.1:8080")
