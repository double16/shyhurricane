import json

from shyhurricane.cleaners import normalize_html, normalize_json, normalize_xml


def test_normalize_xml_and_json5_stabilize_output():
    xml = normalize_xml("<root><child>value</child><empty /></root>")
    assert xml.startswith(b"<?xml")
    assert b"<child>value</child>" in xml

    assert normalize_json("{b: 2, a: [1,],}") == json.dumps({"a": [1], "b": 2}, sort_keys=True, separators=(",", ":"))


def test_normalize_html_removes_dynamic_attributes_and_tokens():
    html = """
    <!doctype html><DIV data-reactroot="x" nonce="abc" id="main">
      2025-08-06 12:03:55 0123456789abcdef0123456789abcdef
    </DIV>
    """

    normalized = normalize_html(html)

    assert "data-reactroot" not in normalized
    assert "nonce" not in normalized
    assert normalized.count("<NUMERIC_TOKEN>") == 2
    assert "<div id=\"main\">" in normalized
