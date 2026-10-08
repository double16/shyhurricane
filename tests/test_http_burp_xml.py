import base64
import io
import json

import pytest
from lxml import etree

from shyhurricane.http_burp_xml import http_burp_xml_generator

REQUEST = "POST /submit HTTP/1.1\r\nHost: example.com\r\nAccept: text/plain\r\nAccept: */*\r\n\r\nhello"
RESPONSE = "HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\n\r\ncreated"


def item(request=REQUEST, response=RESPONSE, encoded=True, time="Tue Jun 02 12:34:56 CDT 2026"):
    def element(name, text):
        if encoded:
            text = base64.b64encode(text.encode()).decode()
            text = "\n".join(text[index:index + 40] for index in range(0, len(text), 40))
        attribute = ' base64="true"' if encoded else ""
        return f"<{name}{attribute}><![CDATA[{text}]]></{name}>"

    return (
        f"<item><time>{time}</time><url>https://example.com/submit</url>"
        f"{element('request', request)}{element('response', response)}</item>"
    )


def parse(text):
    return list(http_burp_xml_generator(io.BytesIO(text.encode())))


@pytest.mark.parametrize("encoded", [True, False])
def test_synthetic_export(encoded):
    xml = '<?xml version="1.0"?><!DOCTYPE items [<!ELEMENT items (item*)>]><items>'
    records = parse(xml + item(encoded=encoded) * 2 + "</items>")
    assert len(records) == 2
    payload = json.loads(records[0].to_katana())
    assert payload == {
        "timestamp": "2026-06-02T12:34:56-05:00",
        "request": {
            "endpoint": "https://example.com/submit", "method": "POST",
            "headers": {"Host": "example.com", "Accept": "text/plain, */*"}, "body": "hello",
        },
        "response": {"status_code": 201, "headers": {"Content-Type": "text/plain"}, "body": "created"},
    }


def test_mixed_encoding_and_invalid_utf8():
    xml = item(encoded=False).replace(
        f"<response><![CDATA[{RESPONSE}]]></response>",
        '<response base64="true">' + base64.b64encode(b"HTTP/1.1 200 OK\r\n\r\n\xff").decode() + "</response>",
    )
    assert parse("<items>" + xml + "</items>")[0].response_body == "\ufffd"


def test_empty_headers_bodies_and_explicit_false():
    xml = item("GET / HTTP/2\n\n", "HTTP/2 204\n\n", encoded=False, time="2026-06-02T17:34:56Z")
    xml = xml.replace("<request>", '<request base64="false">')
    record = parse("<items>" + xml + "</items>")[0]
    assert record.request_headers == record.response_headers == {}
    assert record.request_body == record.response_body == ""
    assert record.timestamp.endswith("+00:00")


@pytest.mark.parametrize("bad", [
    "<item/>",
    item().replace("https://example.com/submit", "invalid"),
    item(time="invalid"),
    item(time="Tue Jun 02 12:34:56 XYZ 2026"),
    item(request="invalid"),
    item(request="GET / INVALID"),
    item(response="invalid"),
    item(response="HTTP/1.1 999 Nope"),
    item().replace('base64="true"', 'base64="wrong"', 1),
    item().replace("<request base64=\"true\">", '<request base64="true">!'),
    item().replace("<request base64=\"true\">", '<missing base64="true">').replace("</request>", "</missing>"),
])
def test_skips_invalid_item_and_continues(bad, capsys):
    records = parse("<items>" + bad + item() + "</items>")
    assert len(records) == 1
    assert "Skipping XML item 1" in capsys.readouterr().err


@pytest.mark.parametrize("xml", ["<wrong/>", "<items><item>", "", "<items></items>garbage"])
def test_invalid_documents_raise(xml):
    with pytest.raises((ValueError, etree.XMLSyntaxError)):
        parse(xml)


def test_empty_export():
    assert parse("<items/>") == []


@pytest.mark.parametrize("declaration", [
    '<!ENTITY secret SYSTEM "file:///etc/passwd">',
    '<!ENTITY secret SYSTEM "https://example.com/secret">',
    '<!ENTITY secret "expanded">',
])
def test_entities_are_rejected(declaration, capsys):
    bad = item(encoded=False).replace("hello", "&secret;")
    # CDATA intentionally replaced so this is an actual entity reference.
    bad = bad.replace(f"<![CDATA[{REQUEST.replace('hello', '&secret;')}]]>", REQUEST.replace("hello", "&secret;"))
    records = parse(f"<!DOCTYPE items [{declaration}]><items>{bad}{item()}</items>")
    assert len(records) == 1
    assert "Unsupported XML entity" in capsys.readouterr().err
