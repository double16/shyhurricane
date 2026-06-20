import json

from shyhurricane.index.input_documents import HarDocument, HttpRawDocument, KatanaDocument, IngestableRequestResponse


def test_ingestable_request_response_to_katana_includes_optional_fields():
    rr = IngestableRequestResponse(
        url="https://example.com/",
        timestamp="2025-08-06T12:03:55Z",
        method="POST",
        request_headers={"X-Test": "yes"},
        request_body="body",
        response_code=201,
        response_headers={"Content-Type": "text/plain"},
        response_body="ok",
        response_rtt=0.25,
        technologies=["nginx"],
        forms=[{"action": "/login"}],
    )

    data = json.loads(rr.to_katana())

    assert data["request"]["method"] == "POST"
    assert data["response"]["rtt"] == 0.25
    assert data["response"]["technologies"] == ["nginx"]
    assert data["response"]["forms"] == [{"action": "/login"}]


def test_har_document_invalid_missing_and_header_edges():
    parser = HarDocument()

    assert parser.run("not-json")["request_responses"] == []
    assert parser.run({})["request_responses"] == []
    assert parser.run({"log": {"entries": [{"request": {}}, {"request": {"url": "bad"}, "response": {}}]}})[
               "request_responses"] == []
    assert parser.parse_headers([
        {"name": "accept", "value": "text/html"},
        {"name": "Accept", "value": "application/json"},
        {"name": "", "value": "ignored"},
    ]) == {"Accept": "text/html;application/json"}


def test_har_document_defaults_timestamp_and_handles_missing_time():
    result = HarDocument().run({"log": {"entries": [{
        "request": {"url": "https://example.com/", "method": "get", "headers": []},
        "response": {"status": 204, "headers": []},
    }]}})["request_responses"][0]

    assert result.url == "https://example.com/"
    assert result.method == "GET"
    assert result.response_code == 204
    assert result.response_rtt is None


def test_http_raw_document_bytes_absolute_url_missing_host_and_bad_response():
    parser = HttpRawDocument()
    absolute = (
        b"GET https://example.com/path HTTP/1.1\r\nHost: ignored\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"
    )
    no_host = "GET /path HTTP/1.1\r\n\r\nHTTP/1.1 200 OK\r\n\r\nok"
    bad_response = "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\nnot http"

    result = parser.run(absolute)["request_responses"][0]

    assert result.url == "https://example.com/path"
    assert parser.run(no_host)["request_responses"] == []
    assert parser.run(bad_response)["request_responses"] == []


def test_katana_document_dict_multiline_invalid_and_missing_fields():
    parser = KatanaDocument()
    entry = {
        "timestamp": "2025-08-06T12:03:55Z",
        "request": {"endpoint": "https://example.com/", "method": "post",
                    "headers": {"user_agent": "agent", "raw": "remove"}},
        "response": {"status_code": 200, "headers": {"content_type": "text/html", "raw": "remove"},
                     "body": "ok", "technologies": "nginx"},
    }

    parsed = parser.run(entry)["request_responses"][0]
    multiline = parser.run(json.dumps(entry, indent=2))["request_responses"][0]

    assert parsed.method == "POST"
    assert parsed.request_headers == {"User-Agent": "agent"}
    assert parsed.response_headers == {"Content-Type": "text/html"}
    assert parsed.technologies == ["nginx"]
    assert multiline.url == "https://example.com/"
    assert parser.run('{"request": bad')["request_responses"] == []
    assert parser.run({"response": {}})["request_responses"] == []
    assert parser.run({"request": {}, "response": {}})["request_responses"] == []
    assert parser.run({"request": {"endpoint": "https://example.com/"}, "response": {}})["request_responses"] == []
    assert parser.run({"timestamp": "now", "request": {"endpoint": "not a url"}, "response": {"status_code": 200}})[
               "request_responses"] == []
