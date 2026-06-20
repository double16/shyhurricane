import asyncio
import logging

import pytest
from haystack import Document

import shyhurricane.utils as utils


def test_url_domain_http_and_sort_helpers():
    parsed = utils.urlparse_ext("https://[::1]/path?q=1")
    assert parsed.netloc == "[::1]:443"
    assert utils.extract_domain("127.0.0.1") == ""
    assert utils.extract_domain("internal") == "internal"

    request = "POST /x HTTP/1.1\nHost: example.com\nAccept: a\nAccept: b\n\nbody\nHTTP/1.1 201 Created\nX: y\n\nok"
    method, path, version, headers, body, response = utils.parse_http_request(request)
    status, response_headers, response_body = utils.parse_http_response("HTTP/1.1 200 OK\nSet-Cookie: a\nSet-Cookie: b\n\nbody")

    assert (method, path, version) == ("POST", "/x", "HTTP/1.1")
    assert headers["Accept"] == "a, b"
    assert body == "body"
    assert response.startswith("HTTP/1.1 201")
    assert status == 200
    assert response_headers["Set-Cookie"] == "a, b"
    assert response_body == "body"

    docs = [
        Document(content="a", meta={"url": "u", "http_method": "GET"}, score=0.1),
        Document(content="b", meta={"url": "u", "http_method": "GET"}, score=0.9),
        Document(content="c", meta={"url": "v", "http_method": "POST"}, score=0.2),
    ]
    assert [doc.content for doc in utils.documents_sort_unique(docs, limit=1)] == ["b"]


def test_soup_filter_path_and_encoding_helpers(monkeypatch, tmp_path):
    html = """
    <html><head>
      <meta property="og:title" content="OG title">
      <meta name="twitter:description" content="Twitter desc">
    </head></html>
    """
    title, description = utils.BeautifulSoupExtractor().extract(html)

    monkeypatch.setattr(utils.os.path, "exists", lambda path: False)
    state_path = utils.get_state_path("db:name", "state")

    assert title == "OG title"
    assert description == "Twitter desc"
    assert utils.remove_unencodable("a\udcffb") == "ab"
    assert str(state_path).endswith("db_name/state")
    assert utils.get_log_path("db:name", "log.txt").name == "log.txt"
    assert utils.b64(b"ok") == "b2s="


def test_time_hosts_networks_stream_and_query_edges():
    assert utils.parse_to_iso8601("Sat Jul 19 08:23:11 CDT 2025")[0].endswith("-05:00")
    assert utils.parse_to_iso8601("Sat, 19 Jul 2025 13:23:10 GMT")[0].endswith("+00:00")
    with pytest.raises(ValueError):
        utils.parse_to_iso8601("not a time")

    assert utils.filter_hosts_and_addresses(["localhost", "example.com", "127.0.0.1", "bad host"]) == [
        "localhost", "example.com", "127.0.0.1"]
    assert utils.filter_ip_networks(["127.0.0.1", "192.168.0.0/24", "example.com"]) == [
        "127.0.0.1", "192.168.0.0/24"]

    async def chunks():
        yield b"one\nt"
        yield b"wo\nthree"

    assert asyncio.run(_collect(utils.stream_lines(chunks()))) == ["one", "two", "three"]
    assert utils.query_to_netloc("example.com:8443") == ("example.com", 8443)
    assert utils.query_to_netloc("not a host") == ("not a host", None)


async def _collect(agen):
    return [item async for item in agen]


def test_logging_hardware_and_coerce_fallbacks(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    class Cuda:
        @staticmethod
        def is_available():
            return True

        @staticmethod
        def device_count():
            return 1

        @staticmethod
        def get_device_name(index):
            return "GPU"

        @staticmethod
        def mem_get_info(index):
            return 1024, 2048

        @staticmethod
        def memory_allocated(index):
            return 512

        @staticmethod
        def memory_reserved(index):
            return 256

    monkeypatch.setattr(utils.torch, "cuda", Cuda())
    utils.log_gpu_memory_summary()
    assert "CUDA Devices" in caplog.text

    monkeypatch.setattr(utils.os, "process_cpu_count", lambda: (_ for _ in ()).throw(RuntimeError()), raising=False)
    monkeypatch.setattr(utils.os, "sched_getaffinity", lambda pid: {1, 2, 3}, raising=False)
    assert utils.process_cpu_count() == 3
    monkeypatch.setattr(utils.os, "sched_getaffinity", lambda pid: (_ for _ in ()).throw(RuntimeError()), raising=False)
    monkeypatch.setattr(utils.os, "cpu_count", lambda: 7)
    assert utils.process_cpu_count() == 7

    assert utils.coerce_to_list((1, 2), int) == [1, 2]
    assert utils.coerce_to_list(5, int) == [5]
    assert utils.coerce_to_dict(["a", "1", "b"]) == {"a": "1", "b": None}
    assert utils.coerce_to_dict("a:1,b:2") == {"a": "1", "b": "2"}
