import json

import pytest
from lxml import etree

from shyhurricane.cleaners import normalize_html, normalize_json, normalize_xml


def test_normalize_xml_and_json5_stabilize_output():
    xml = normalize_xml("<root><child>value</child><empty /></root>")
    assert isinstance(xml, str)
    assert xml.startswith("<?xml")
    assert "<child>value</child>" in xml

    assert normalize_json("{b: 2, a: [1,],}") == json.dumps({"a": [1], "b": 2}, sort_keys=True, separators=(",", ":"))


def test_normalize_svg_preserves_namespace_attributes_and_unicode():
    normalized = normalize_xml(
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><title>Café</title></svg>'
    )

    assert isinstance(normalized, str)
    assert normalized.startswith("<?xml")
    root = etree.fromstring(normalized.encode("utf-8"))
    assert root.tag == "{http://www.w3.org/2000/svg}svg"
    assert root.attrib["viewBox"] == "0 0 10 10"
    assert root[0].text == "Café"


def test_normalize_xml_rejects_unrecoverable_input():
    with pytest.raises(etree.XMLSyntaxError):
        normalize_xml("")


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


@pytest.mark.parametrize("encoding", ["UTF-8", "ISO-8859-1", "UTF-16"])
@pytest.mark.parametrize("quote", ["'", '"'])
@pytest.mark.parametrize("prefix", ["", "\ufeff", " \n"])
def test_normalize_xml_handles_decoded_unicode_encoding_labels(encoding, quote, prefix):
    content = f"{prefix}<?xml version={quote}1.0{quote} encoding={quote}{encoding}{quote}?>"
    content += '<?xml-stylesheet href="style.css"?><root><text>Café 漢字 🙂</text></root>'
    normalized = normalize_xml(content)
    parsed = etree.fromstring(normalized.encode("utf-8"))
    assert parsed[0].text == "Café 漢字 🙂"
    assert 'encoding=\'utf-8\'' in normalized
    assert '<?xml-stylesheet href="style.css"?>' in normalized
    assert parsed.getroottree().docinfo.xml_version == "1.0"


def test_normalize_xml_preserves_unrelated_processing_instructions():
    normalized = normalize_xml('<?xml-stylesheet href="x.css"?><root><?encoding label="ISO-8859-1"?>é</root>')
    assert '<?xml-stylesheet href="x.css"?>' in normalized
    assert '<?encoding label="ISO-8859-1"?>' in normalized
    assert "é" in normalized


def test_normalize_xml_retains_xml_version_1_1():
    normalized = normalize_xml('<?xml version="1.1" encoding="UTF-16"?><root>é</root>')
    parsed = etree.fromstring(normalized.encode("utf-8"))
    assert parsed.getroottree().docinfo.xml_version == "1.1"
    assert parsed.text == "é"
