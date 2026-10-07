import base64
import io
import json
import runpy
from pathlib import Path
from unittest.mock import Mock

import pytest

import ingest


def setup_cli(monkeypatch, text):
    monkeypatch.setattr(ingest.sys, "stdin", io.TextIOWrapper(io.BytesIO(text.encode())))
    post = Mock()
    monkeypatch.setattr(ingest.requests, "post", post)
    return post


def xml_item():
    return (
        "<item><url>https://example.com/</url><time>2026-06-02T00:00:00Z</time>"
        "<request><![CDATA[GET / HTTP/1.1\nHost: example.com\n\n]]></request>"
        "<response><![CDATA[HTTP/1.1 200 OK\n\nhello]]></response></item>"
    )


@pytest.mark.parametrize("url", ["http://localhost:8000", "http://localhost:8000/"])
def test_xml_posts_katana(monkeypatch, url):
    post = setup_cli(monkeypatch, "<items>" + xml_item() * 2 + "</items>")
    assert ingest.main(["--mcp-url", url, "--burp-xml"]) == 0
    assert post.call_count == 3
    assert post.call_args_list[0].args == ("http://localhost:8000/index",)
    assert post.call_args_list[0].kwargs == {"data": "{}"}
    payload = json.loads(post.call_args.kwargs["data"])
    assert payload["request"]["endpoint"] == "https://example.com/"
    assert payload["response"]["body"] == "hello"


def test_skips_bad_item_and_post_failure(monkeypatch, capsys):
    post = setup_cli(monkeypatch, "<items><item/>" + xml_item() * 2 + "</items>")
    post.side_effect = [Mock(), RuntimeError("unavailable"), Mock()]
    assert ingest.main(["--mcp-url", "http://localhost", "--burp-xml"]) == 0
    assert post.call_count == 3
    stderr = capsys.readouterr().err
    assert "Skipping XML item 1" in stderr
    assert "unavailable" in stderr
    assert "Queued for indexing" in stderr


def test_verification_failure(monkeypatch):
    post = setup_cli(monkeypatch, "<items/>")
    post.return_value.raise_for_status.side_effect = RuntimeError("failed")
    assert ingest.main(["--mcp-url", "http://localhost", "--burp-xml"]) == 1
    assert post.call_count == 1


def test_bad_xml(monkeypatch, capsys):
    setup_cli(monkeypatch, "<wrong/>")
    assert ingest.main(["--mcp-url", "http://localhost", "--burp-xml"]) == 1
    assert "Error reading input" in capsys.readouterr().err


@pytest.mark.parametrize("flags", [[], ["--burp-xml", "--csv"], ["--burp-xml", "--katana"]])
def test_format_validation(monkeypatch, flags):
    post = setup_cli(monkeypatch, "")
    with pytest.raises(SystemExit) as error:
        ingest.main(["--mcp-url", "http://localhost", *flags])
    assert error.value.code == 2
    post.assert_not_called()


def test_katana_regression(monkeypatch):
    payload = json.dumps({"request": {"endpoint": "https://example.com/"}})
    post = setup_cli(monkeypatch, "invalid\n" + payload + "\n")
    assert ingest.main(["--mcp-url", "http://localhost", "--katana"]) == 0
    assert post.call_count == 2
    assert post.call_args.kwargs["data"] == payload


def test_csv_regression(monkeypatch):
    request = base64.b64encode(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").decode()
    response = base64.b64encode(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello").decode()
    post = setup_cli(monkeypatch, f"https://example.com/,2026-06-02T00:00:00Z,{request},{response}\n")
    assert ingest.main(["--mcp-url", "http://localhost", "--csv"]) == 0
    assert post.call_count == 2
    assert json.loads(post.call_args.kwargs["data"])["response"]["body"] == "hello"


@pytest.mark.parametrize("outside_repository", [False, True])
def test_script_entrypoint(monkeypatch, tmp_path, outside_repository):
    script_path = Path(ingest.__file__).resolve()
    monkeypatch.chdir(tmp_path if outside_repository else script_path.parent)
    setup_cli(monkeypatch, "<items/>")
    monkeypatch.setattr(ingest.sys, "argv", ["ingest.py", "--mcp-url", "http://localhost", "--burp-xml"])
    with pytest.raises(SystemExit) as error:
        runpy.run_path(str(script_path), run_name="__main__")
    assert error.value.code == 0
