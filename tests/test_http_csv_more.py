import base64

import pytest

from shyhurricane.http_csv import http_csv_generator, is_http_csv, parse_headers


def test_is_http_csv_detection_edges():
    assert is_http_csv("Time,Request.Headers,Response.Headers", None) is True
    assert is_http_csv("", None) is False
    assert is_http_csv("", '{"request": true}') is False
    assert is_http_csv("", "a,b,c,d,e") is True


def test_parse_headers_combines_duplicates_and_rejects_bad_names():
    headers = parse_headers("Host: example.com\nAccept: text/html\nAccept: application/json\n")

    assert headers == {"Host": "example.com", "Accept": "text/html, application/json"}

    with pytest.raises(ValueError, match="Invalid HTTP header"):
        parse_headers("Bad Header: value")


def test_http_csv_generator_parses_base64_request_and_response():
    request = base64.b64encode(
        b"POST /submit HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\nAccept: */*\r\n\r\nbody"
    ).decode()
    response = base64.b64encode(
        b"HTTP/1.1 201 Created\r\nDate: Sun, 29 Jun 2025 03:44:52 GMT\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"
    ).decode()
    rows = [
        "URL,Request,Response,Response.RTT\n",
        f"https://example.com/submit,{request},{response},0.25\n",
    ]

    results = list(http_csv_generator(rows))

    assert len(results) == 1
    result = results[0]
    assert result.url == "https://example.com/submit"
    assert result.method == "POST"
    assert result.response_code == 201
    assert result.request_body == "body"
    assert result.response_body == "ok"
    assert result.response_rtt == 0.25


def test_http_csv_generator_skips_incomplete_rows():
    assert list(http_csv_generator(["https://example.com,GET\n"])) == []
