"""Source-map URL variants and transport preservation."""

import httpx
import pytest

from shyhurricane import source_maps


@pytest.mark.parametrize("suffix", [".map", ".MAP", "%2Emap", "%2EMAP"])
def test_candidates_round_trip_and_transport(suffix, monkeypatch):
    bundle = "https://example.com/a%20b.js?v=1#section"
    url = f"https://example.com/a%20b.js{suffix}?v=1#section"
    assert url in source_maps.source_map_candidates(bundle)
    assert source_maps.javascript_url_from_map(url) == bundle
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(200, text='{"version":3,"sources":[]}')

    client = httpx.Client(transport=httpx.MockTransport(respond))
    client_options = []
    monkeypatch.setattr(
        source_maps.httpx,
        "Client",
        lambda **kwargs: client_options.append(kwargs) or client,
    )
    assert source_maps._valid_map(source_maps._fetch_map(url, {}))
    assert requests[0].url.raw_path == f"/a%20b.js{suffix}?v=1".encode()
    assert client_options == [{"timeout": 5, "follow_redirects": False, "verify": False}]


@pytest.mark.parametrize("url", ["https://example.com/a.css", "file:///a.js"])
def test_unsupported_candidates(url):
    assert source_maps.source_map_candidates(url) == []
    assert source_maps.javascript_url_from_map(url) is None
