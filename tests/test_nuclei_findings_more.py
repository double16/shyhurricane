import json

import shyhurricane.nuclei_findings as nf


def finding(**overrides):
    base = {
        "template-id": "tpl",
        "template-url": "https://templates.example/tpl",
        "template-path": "/templates/tpl.yaml",
        "type": "http",
        "matched-at": "https://example.com/path",
        "url": "https://example.com/path",
        "host": "example.com",
        "ip": "127.0.0.1",
        "port": "443",
        "scheme": "https",
        "timestamp": "2025-08-06T12:03:55Z",
        "matcher-name": "body",
        "matcher-status": True,
        "curl-command": "curl https://example.com/path",
        "request": "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "response": "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n\x00\x01",
        "extracted-results": ["secret", 123],
        "info": {
            "name": "Example Finding",
            "severity": "critical",
            "author": ["a", "b"],
            "tags": ["xss", "cve"],
            "description": "Description",
            "reference": ["https://ref.example"],
            "classification": {
                "cve-id": ["CVE-2025-0001", "CVE-2025-0002"],
                "cwe-id": ["CWE-79", "bad"],
                "cvss-score": "9.8",
                "cvss-metrics": "AV:N",
                "epss-score": 0.5,
                "epss-percentile": 0.9,
                "cisa-known-exploited": "true",
                "cpe": ["cpe:/a:test"],
                "references": ["https://class.example"],
            },
            "metadata": {
                "shodan-query": "http.title:test",
                "github-query": "secret",
            },
        },
    }
    base.update(overrides)
    return base


def test_loading_splitting_formatting_and_basic_helpers():
    raw = json.dumps({"a": 1}) + "\nnot-json\n" + json.dumps({"b": 2})

    assert nf.load_findings("") == []
    assert nf.load_findings('{"a":1}') == [{"a": 1}]
    assert nf.load_findings('[{"a":1}, 2, {"b":2}]') == [{"a": 1}, {"b": 2}]
    assert nf.load_findings(raw) == [{"a": 1}, {"b": 2}]
    assert nf.split_http_message("h\n\nb") == ("h", "b")
    assert nf.split_http_message("only headers") == ("only headers", "")
    assert nf.parse_headers("A: b\nBad\nA: c") == {"a": "c"}
    assert nf.is_probably_text("application/x-yaml") is True
    assert nf.is_probably_text("application/octet-stream") is False
    assert nf.clip("abcdef", 3).endswith("[truncated]")
    assert nf.bullets(["a", "", "b"]) == "- a\n- b"
    assert nf.md_code_block("```inside```").startswith("~~~")
    assert nf.md_kv("Label", None) == "**Label:** -"
    assert nf.norm({"a": 1}, "a", "b") is None


def test_classification_discovery_poc_remediation_references_and_markdown():
    data = finding()

    classification = nf.classification_lines(data)
    markdown = nf.finding_to_markdown(data, max_chars=5, show_binary=False)
    converted = nf.nuclei_finding_to_markdown(data, max_chars=5, show_binary=True)

    assert any("CVE-2025-0001" in line for line in classification)
    assert any("CWE-79" in line for line in classification)
    assert "Intel:" in nf.discovery_method(data)
    assert "> (binary content suppressed)" in markdown
    assert "### Response body" in converted["markdown"]
    assert "Prioritize remediation" in nf.remediation(data)
    assert "https://templates.example/tpl" in nf.references(data)
    assert converted["targets"] == ["https://example.com/path"]
    assert converted["title"] == "Example Finding on https://example.com/path"


def test_reproduction_and_remediation_protocol_variants():
    assert "dig dns.example any" in nf.reproduction_steps(finding(type="dns", host="dns.example", url=None,
                                                                  **{"matched-at": None}))
    assert "nc -v tcp.example 22" in nf.reproduction_steps(finding(type="tcp", host="tcp.example", port="22",
                                                                    url=None, **{"matched-at": None}))
    assert "nc -v udp.example 53" in nf.reproduction_steps(finding(type="udp", host="udp.example", port="53",
                                                                    url=None, **{"matched-at": None}))
    assert "openssl s_client" in nf.reproduction_steps(finding(type="ssl", host="ssl.example", port="443",
                                                               url=None, **{"matched-at": None}))
    assert "Trigger the check" in nf.reproduction_steps(finding(type="other", host=None, port=None, url=None,
                                                                **{"matched-at": None}))
    assert "modern TLS config" in nf.remediation(finding(type="tls", info={"severity": "low"}))
    assert "Harden DNS" in nf.remediation(finding(type="dns", info={"severity": "info"}))
    assert nf.remediation(finding(info={"remediation": "Fix one\nFix two"})) == "- Fix one\n- Fix two"


def test_extract_targets_from_parts_headers_and_empty_cases():
    assert nf.extract_targets(finding(url=None, **{"matched-at": None}, scheme="https", host="example.com",
                                      port="8443", ip="10.0.0.1")) == [
        "https://example.com:8443",
        "example.com:8443",
        "example.com",
        "10.0.0.1:8443",
        "10.0.0.1",
    ]
    assert nf.extract_targets({"scheme": "http", "request": "GET / HTTP/1.1\r\nHost: header.example:8080\r\n\r\n"}) == [
        "header.example:8080",
        "http://header.example:8080",
    ]
    assert nf.extract_targets({}) == []
    assert nf._default_port_for_scheme("ftp") is None
    assert nf._hostport(None, "80") is None
    assert nf.is_nuclei_finding({"template-id": "x", "info": {}, "host": "example.com"}) is True
    assert nf.is_nuclei_finding({"template-id": "x"}) is False
