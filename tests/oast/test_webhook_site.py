from types import SimpleNamespace

import httpx
import pytest
import respx

from shyhurricane.oast import Endpoints, PollOutput, HealthOutput
from shyhurricane.oast.webhook_site import WebhookSiteProvider
from shyhurricane.server_config import set_server_config


@pytest.fixture
def cfg_with_api_key():
    # get_server_config() returns an object with .oast.webhook_api_key
    return SimpleNamespace(oast=SimpleNamespace(webhook_api_key="SECRET-KEY"))


@pytest.fixture
def cfg_without_api_key():
    return SimpleNamespace(oast=SimpleNamespace(webhook_api_key=None))


@pytest.fixture
def provider():
    return WebhookSiteProvider()


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """
    Safety: ensure no real network calls slip through.
    """
    # httpx will go through respx; disallow anything unmatched
    with respx.mock(assert_all_called=True) as router:
        yield router


def _patch_config(monkeypatch, cfg):
    set_server_config(cfg)


@pytest.mark.asyncio
async def test_headers_with_and_without_api_key(monkeypatch, provider, cfg_with_api_key, cfg_without_api_key):
    _patch_config(monkeypatch, cfg_with_api_key)
    h = provider._headers()
    assert h["Accept"] == "application/json"
    assert h["Content-Type"] == "application/json"
    assert h.get("Api-Key") == "SECRET-KEY"

    _patch_config(monkeypatch, cfg_without_api_key)
    h2 = provider._headers()
    assert "Api-Key" not in h2


@pytest.mark.asyncio
@respx.mock
async def test_health_ok(provider):
    route = respx.get("https://webhook.site").mock(return_value=httpx.Response(200))
    out: HealthOutput = await provider.health()
    assert route.called
    assert out.status == "ok"
    assert out.detail is None


@pytest.mark.asyncio
@respx.mock
async def test_health_error(provider):
    route = respx.get("https://webhook.site").mock(return_value=httpx.Response(503))
    out: HealthOutput = await provider.health()
    assert route.called
    assert out.status == "error"
    assert "HTTP 503" in (out.detail or "")


@pytest.mark.asyncio
@respx.mock
async def test_init_creates_token_and_returns_endpoints(monkeypatch, provider, cfg_with_api_key):
    _patch_config(monkeypatch, cfg_with_api_key)

    captured_headers = {}

    def _capture_headers(request):
        nonlocal captured_headers
        captured_headers = dict(request.headers)
        body = {"uuid": "11111111-2222-3333-4444-555555555555"}
        return httpx.Response(200, json=body)

    post_route = respx.post("https://webhook.site/token").mock(side_effect=_capture_headers)

    # init() returns Endpoints via endpoints()
    eps: Endpoints = await provider.init()
    assert post_route.called
    assert provider.inited is True
    assert provider.webhook_token_id == "11111111-2222-3333-4444-555555555555"

    # spot-check resulting endpoints
    tid = provider.webhook_token_id
    assert eps.http == f"http://webhook.site/{tid}"
    assert eps.https == f"https://webhook.site/{tid}"
    assert eps.dns == f"{tid}.dnshook.site"
    assert eps.smtp == f"{tid}@emailhook.site"
    assert eps.extras["http_subdomain"] == f"https://{tid}.webhook.site"
    assert eps.extras["token_id"] == tid


@pytest.mark.asyncio
@respx.mock
async def test_endpoints_after_init(provider):
    # Set the state as if already initialized
    provider.inited = True
    provider.webhook_token_id = "abc-123"
    eps = await provider.endpoints()
    assert eps.http.endswith("/abc-123")
    assert eps.https.endswith("/abc-123")
    assert eps.dns == "abc-123.dnshook.site"
    assert eps.smtp == "abc-123@emailhook.site"
    assert eps.extras["http_subdomain"] == "https://abc-123.webhook.site"
    assert eps.extras["token_id"] == "abc-123"


@pytest.mark.asyncio
@respx.mock
async def test_poll_new_filters_seen_and_appends_new(monkeypatch, provider, cfg_with_api_key):
    _patch_config(monkeypatch, cfg_with_api_key)
    provider.inited = True
    provider.webhook_token_id = "abc-123"
    provider.seen_ids = {"seen-1"}

    # newest-first list with 3 entries, including a previously seen uuid
    payload = {
        "data": [
            {"uuid": "seen-1", "k": "old"},
            {"uuid": "new-1", "k": "A"},
            {"uuid": "new-2", "k": "B"},
        ]
    }

    captured_headers = {}

    def _handler(request):
        nonlocal captured_headers
        captured_headers = dict(request.headers)
        return httpx.Response(200, json=payload)

    route = respx.get("https://webhook.site/token/abc-123/requests").mock(side_effect=_handler)

    out: PollOutput = await provider.poll_new()
    assert route.called
    assert "api-key" in captured_headers  # header propagation check
    # Should exclude seen-1, keep new-1 and new-2, and update seen_ids
    assert [i["uuid"] for i in out.interactions] == ["new-1", "new-2"]
    assert "new-1" in provider.seen_ids and "new-2" in provider.seen_ids
    assert "seen-1" in provider.seen_ids  # still present


@pytest.mark.asyncio
@respx.mock
async def test_poll_new_handles_empty(monkeypatch, provider, cfg_with_api_key):
    _patch_config(monkeypatch, cfg_with_api_key)
    provider.inited = True
    provider.webhook_token_id = "abc-123"
    provider.seen_ids = set()

    route = respx.get("https://webhook.site/token/abc-123/requests").mock(
        return_value=httpx.Response(200, json={})
    )
    out: PollOutput = await provider.poll_new()
    assert route.called
    assert out.interactions == []


@pytest.mark.asyncio
@respx.mock
async def test_deregister_noop_when_not_inited(provider):
    # inited False => should not call delete
    route = respx.delete("https://webhook.site/token/whatever").mock(
        return_value=httpx.Response(204)
    )
    await provider.deregister()
    assert not route.called


@pytest.mark.asyncio
@respx.mock
async def test_deregister_calls_delete(monkeypatch, provider, cfg_with_api_key):
    _patch_config(monkeypatch, cfg_with_api_key)
    provider.inited = True
    provider.webhook_token_id = "abc-123"

    captured = {}

    def _delete_handler(request):
        captured["headers"] = dict(request.headers)
        captured["url"] = str(request.url)
        captured["params"] = dict(request.url.params)
        return httpx.Response(204)

    route = respx.delete("https://webhook.site/token/abc-123").mock(side_effect=_delete_handler)
    await provider.deregister()
    assert route.called
    assert captured["url"] == "https://webhook.site/token/abc-123?password="
    # API expects ?password= (empty) param per implementation
    assert captured["params"].get("password", None) == ""
