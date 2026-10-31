"""Burp issue conversion and routing contract tests."""

import base64
import io

import pytest
from lxml import etree

from shyhurricane.burp_issues_xml import burp_xml_records


def issue(extra="", severity="High", confidence="Certain"):
    return (f"<issue><name>Test</name><host>https://example.com:8443</host><path>/a?q=1</path>"
            f"<severity>{severity}</severity><confidence>{confidence}</confidence>"
            "<type>42</type><serialNumber>123</serialNumber>" + extra + "</issue>")


def pair(encoded=False, response=True, path="/a?q=1"):
    request = f"POST {path} HTTP/1.1\r\nSecret: hidden\r\n\r\n" + "q" * 1100
    reply = "HTTP/1.1 200 OK\r\nSecret: hidden\r\n\r\n" + "r" * 1100
    def element(tag, value):
        if encoded:
            return f'<{tag} base64="true">{base64.b64encode(value.encode()).decode()}</{tag}>'
        return f'<{tag} base64="false"><![CDATA[{value}]]></{tag}>'
    return "<requestresponse>" + element("request", request) + (
        element("response", reply) if response else "") + "</requestresponse>"


def parse(content, time="2026-06-02T00:00:00Z"):
    return list(burp_xml_records(io.BytesIO(
        f'<issues exportTime="{time}">{content}</issues>'.encode())))


@pytest.mark.parametrize("encoded", [False, True])
def test_evidence_and_metadata(encoded):
    records = parse(issue(pair(encoded) + pair(path="/b%20c?x=2") +
                          '<vulnerabilityClassifications>CWE-79</vulnerabilityClassifications>' +
                          '<references>reference</references><issueDetailItems><issueDetailItem>detail'
                          '</issueDetailItem></issueDetailItems>'))
    findings = [value for kind, value in records if kind == "finding"]
    exchanges = [value for kind, value in records if kind == "exchange"]
    assert len(findings) == len(exchanges) == 2
    assert findings[1]["target"] == "https://example.com:8443/b%20c?x=2"
    finding = findings[0]
    assert finding["title"] == "Test at https://example.com:8443/a?q=1"
    assert finding["metadata"]["affected_method"] == "POST"
    assert finding["metadata"]["source_finding_id"] == "123"
    assert finding["metadata"]["cwe_ids"] == ["CWE-79"]
    assert finding["metadata"]["verification_status"] == "unverified"
    assert "q" * 1024 in finding["markdown"]
    assert "q" * 1025 not in finding["markdown"]
    assert "Secret" not in finding["markdown"]
    assert "detail" in finding["markdown"]
    assert len(exchanges[0].request_body) == 1100
    assert len(exchanges[0].response_body) == 1100


@pytest.mark.parametrize("severity,expected", [("Information", "informational"), ("Informational", "informational"),
                                              ("High", "high"), ("Medium", "medium"), ("Low", "low"),
                                              ("new", "unknown")])
@pytest.mark.parametrize("confidence,expected_confidence", [("Certain", "high"), ("Firm", "medium"),
                                                         ("Tentative", "low"), ("new", "unknown")])
def test_labels(severity, expected, confidence, expected_confidence):
    metadata = parse(issue(severity=severity, confidence=confidence))[0][1]["metadata"]
    assert metadata["severity"] == expected
    assert metadata["confidence"] == expected_confidence
    assert metadata["native_severity"] == severity


@pytest.mark.parametrize("extra", ["", pair(response=False), '<requestresponse><request base64="true">!'
                                  '</request></requestresponse>',
                                  '<requestresponse><request>invalid</request></requestresponse>'])
def test_sparse_evidence(extra):
    records = parse(issue(extra), time="invalid")
    assert len(records) == 1
    assert records[0][0] == "finding"


@pytest.mark.parametrize("content", ['<issue/>', issue().replace('https://example.com:8443', 'invalid'),
                                    issue().replace('<name>Test</name>', ''),
                                    issue('<issueDetail>&secret;</issueDetail>')])
def test_invalid_issue_continues(content, capsys):
    xml = '<!DOCTYPE issues [<!ENTITY secret "value">]><issues>' + content + issue() + '</issues>'
    records = list(burp_xml_records(io.BytesIO(xml.encode())))
    assert len(records) == 1
    assert "Skipping XML issue" in capsys.readouterr().err


@pytest.mark.parametrize("xml", [b"", b"<wrong/>", b"<issues><issue>", b"<issues/>garbage"])
def test_invalid_xml(xml):
    with pytest.raises((ValueError, etree.XMLSyntaxError)):
        list(burp_xml_records(io.BytesIO(xml)))


def test_empty_and_unknown_child():
    assert parse("") == []
    assert parse("<unknown/>") == []


def test_binary_control_bytes_are_indexed():
    request = base64.b64encode(b"POST / HTTP/1.1\r\n\r\n\x00\xff").decode()
    records = parse(issue('<requestresponse><request base64="true">' + request +
                          '</request><response>HTTP/1.1 200 OK\n\n</response></requestresponse>'))
    assert [kind for kind, _ in records] == ["finding", "exchange"]
    assert records[1][1].request_body == "\x00\ufffd"


def test_bad_response_retains_finding(capsys):
    records = parse(issue(pair().replace('HTTP/1.1 200 OK', 'invalid')))
    assert len(records) == 1
    assert "Skipping issue exchange" in capsys.readouterr().err


def test_missing_labels_and_cwe_link():
    xml = issue('<vulnerabilityClassifications><![CDATA[<a href="https://cwe.mitre.org/data/definitions/79.html">'
                'classification</a>]]></vulnerabilityClassifications>', severity="", confidence="")
    metadata = parse(xml)[0][1]["metadata"]
    assert "severity" not in metadata
    assert metadata["cwe_ids"] == ["CWE-79"]


@pytest.mark.parametrize("destination", ["ftp://example.com/a", "http://", "/a"])
def test_invalid_evidence_does_not_lose_issue(destination):
    evidence = pair(path=destination)
    if destination == "/a":
        evidence = evidence.replace("POST /a", "BAD() /a")
    records = parse(issue(evidence))
    assert len(records) == 1
    assert "affected_method" not in records[0][1]["metadata"]


def test_response_only_and_mixed_encoding():
    request = base64.b64encode(b"GET / HTTP/1.1\r\n\r\n").decode()
    records = parse(issue('<requestresponse><request base64="true">' + request +
                          '</request><response>HTTP/1.1 204 No Content\n\n</response></requestresponse>' +
                          '<requestresponse><response>HTTP/1.1 200 OK\n\nbody</response></requestresponse>'))
    assert len(records) == 2


def test_no_headers_or_bodies():
    records = parse(issue('<requestresponse><request>GET / HTTP/2</request>'
                          '<response>HTTP/2 200</response></requestresponse>'))
    assert records[0][0] == "finding"
