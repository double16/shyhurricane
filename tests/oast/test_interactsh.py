import base64
import json
import os
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import pytest
import httpx

from shyhurricane.oast.interactsh import InteractProvider

pytest.importorskip("Crypto")  # skip all tests if pycryptodome isn't installed
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


# ---------- Test Utilities ----------

class FakeResponse:
    def __init__(self, *, status_code: int = 200, json_body: Optional[Dict[str, Any]] = None, url: str = "https://example.invalid/"):
        self.status_code = status_code
        self._json = json_body or {}
        self.request = httpx.Request("GET", url)  # minimal request for exceptions
        self.url = url

    def json(self):
        return self._json

    def raise_for_status(self):
        if 400 <= self.status_code:
            raise httpx.HTTPStatusError(f"HTTP status {self.status_code}", request=self.request, response=httpx.Response(self.status_code, request=self.request))


class FakeAsyncClient:
    """
    Minimal drop-in mock for httpx.AsyncClient used by the provider.
    Route handlers are callables receiving (method, url, params, headers, json, timeout)
    and returning a FakeResponse.
    """
    def __init__(self, router):
        self.router = router

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, params=None, headers=None, timeout=None):
        return await self._call("GET", url, params=params, headers=headers, json_body=None, timeout=timeout)

    async def post(self, url, params=None, headers=None, json=None, timeout=None):
        return await self._call("POST", url, params=params, headers=headers, json_body=json, timeout=timeout)

    async def _call(self, method, url, params=None, headers=None, json_body=None, timeout=None):
        # Normalize on path to keep matching simple
        parsed = urlparse(url)
        path = parsed.path
        key = (method.upper(), path)
        if key not in self.router:
            raise AssertionError(f"No fake route for {key}")
        # Provide context so handlers can assert on inputs
        return await self.router[key](method=method, url=url, params=params or {}, headers=headers or {}, json=json_body, timeout=timeout)


def make_server_config(monkeypatch, *, server: Optional[str], token: Optional[str]):
    class _OAST:
        def __init__(self):
            self.interact_server = server
            self.interact_token = token

    class _CFG:
        def __init__(self):
            self.oast = _OAST()

    def _get_cfg():
        return _CFG()

    # Patch where the SUT imports it (module-level import inside the provider module)
    monkeypatch.setattr("shyhurricane.oast.interactsh.get_server_config", _get_cfg)


def encrypt_poll_payload(public_key_pem: bytes, interactions: list[dict]) -> dict:
    """
    Build a poll() JSON body that the provider can decrypt:
      {
        "aes_key": <RSA-OAEP(SHA256) encrypted 32-byte key, base64>,
        "data": [ <base64(iv + AES-CFB(json_bytes))>, ... ]
      }
    """
    pub = RSA.import_key(public_key_pem)
    oaep = PKCS1_OAEP.new(pub, hashAlgo=SHA256)
    aes_key = os.urandom(32)
    aes_key_b64 = base64.b64encode(oaep.encrypt(aes_key)).decode()

    data_b64 = []
    for item in interactions:
        iv = os.urandom(16)
        cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv, segment_size=128)
        pt = json.dumps(item).encode("utf-8")
        ct = cipher.encrypt(pt)  # IMPORTANT: do NOT include IV in the encryption input
        blob = iv + ct           # Provider expects blob = IV || CIPHERTEXT
        data_b64.append(base64.b64encode(blob).decode())

    return {"aes_key": aes_key_b64, "data": data_b64}


# ---------- Tests ----------

@pytest.mark.asyncio
async def test_server_url_helper(monkeypatch):
    # sanity check the static helper via the class
    assert InteractProvider._server_url("oast.test") == "https://oast.test"
    assert InteractProvider._server_url("https://oast.test") == "https://oast.test"


@pytest.mark.asyncio
async def test_health_ok_and_error(monkeypatch):
    make_server_config(monkeypatch, server="https://oast.health", token=None)

    async def alive_ok(**kwargs):
        return FakeResponse(status_code=200, json_body={"alive": True}, url=kwargs["url"])

    async def alive_fail(**kwargs):
        return FakeResponse(status_code=503, json_body={"alive": False}, url=kwargs["url"])

    # OK
    monkeypatch.setattr("httpx.AsyncClient", lambda: FakeAsyncClient({("GET", "/alive"): alive_ok}))
    p = InteractProvider()
    ok = await p.health()
    assert ok.status == "ok"

    # ERROR
    monkeypatch.setattr("httpx.AsyncClient", lambda: FakeAsyncClient({("GET", "/alive"): alive_fail}))
    p = InteractProvider()
    err = await p.health()
    assert err.status == "error"
    assert "HTTP 503" in (err.detail or "")


@pytest.mark.asyncio
async def test_init_and_endpoints(monkeypatch):
    """
    Verifies:
      - register call made with expected json keys
      - domain formatting (with scheme)
      - endpoints() returns consistent values
    """
    make_server_config(monkeypatch, server="https://oast.init", token="T0K3N")

    captured = {}

    async def register_ok(**kwargs):
        # verify headers include Authorization
        assert kwargs["headers"].get("Accept") == "application/json"
        assert kwargs["headers"].get("Authorization") == "Bearer T0K3N"
        body = kwargs["json"]
        # required fields present
        assert "public-key" in body and "secret-key" in body and "correlation-id" in body
        captured["correlation_id"] = body["correlation-id"]
        return FakeResponse(
            status_code=200,
            json_body={"message": "Registration successful"},
            url=kwargs["url"]
        )

    monkeypatch.setattr("httpx.AsyncClient", lambda: FakeAsyncClient({("POST", "/register"): register_ok}))

    p = InteractProvider()
    endpoints = await p.init()  # this also calls endpoints() internally when done

    # basic invariants
    assert p.inited is True
    assert p.server == "https://oast.init"
    assert p.token == "T0K3N"
    assert p.correlation_id == captured["correlation_id"]
    assert isinstance(p.domain, str) and p.domain.endswith(".oast.init")

    # endpoints consistency
    ep = await p.endpoints()
    # dns is domain without port
    assert ep.dns == p.domain.split(":", 1)[0]
    assert ep.http == f"http://{p.domain}"
    assert ep.https == f"https://{p.domain}"
    assert ep.smtp.endswith("@" + ep.smtp_domain)
    assert ep.ldap == f"ldap://{ep.smtp_domain}"


@pytest.mark.asyncio
async def test_poll_new_decrypts_and_deduplicates(monkeypatch):
    """
    Flow:
      - init() registers and generates RSA keys
      - poll_new() receives an RSA-encrypted AES key and CFB-encrypted data items
      - provider decrypts, filters duplicates, and returns PollOutput
    """
    make_server_config(monkeypatch, server="https://oast.pull", token=None)

    # Step 1: mock /register to allow init()
    async def register_ok(**kwargs):
        return FakeResponse(status_code=200, json_body={"message": "Registration successful"}, url=kwargs["url"])

    routes = {("POST", "/register"): register_ok}

    # We will fill in /poll after we have the provider's public key (post-init).
    def make_client():
        return FakeAsyncClient(routes)

    monkeypatch.setattr("httpx.AsyncClient", make_client)

    p = InteractProvider()
    await p.init()

    # Build encrypted poll payload using the provider's public key
    priv = RSA.import_key(p.private_key_pem.encode())
    public_pem = priv.publickey().export_key("PEM")
    interactions = [
        {"unique-id": "id-1", "protocol": "http", "raw-request": "GET /", "remote-address": "1.2.3.4"},
        {"unique-id": "id-2", "protocol": "dns", "qname": "abc.example"},
    ]
    poll_body = encrypt_poll_payload(public_pem, interactions)

    async def poll_ok(**kwargs):
        # ensure params include id/secret
        assert "id" in kwargs["params"] and "secret" in kwargs["params"]
        return FakeResponse(status_code=200, json_body=poll_body, url=kwargs["url"])

    routes[("GET", "/poll")] = poll_ok

    # First poll: should return both items
    out1 = await p.poll_new()
    ids1 = {item["unique-id"] for item in out1.interactions}
    assert ids1 == {"id-1", "id-2"}

    # Second poll with the same data: should be deduplicated to zero new items
    out2 = await p.poll_new()
    assert out2.interactions == []


@pytest.mark.asyncio
async def test_poll_handles_decrypt_errors(monkeypatch):
    """
    If decrypt fails for an item, it should yield an 'error' dict and skip ID-based dedup (no unique-id).
    """
    make_server_config(monkeypatch, server="https://oast.err", token=None)

    async def register_ok(**kwargs):
        return FakeResponse(status_code=200, json_body={"message": "Registration successful"}, url=kwargs["url"])

    # Build a bogus poll payload: valid aes_key, but data item is garbage
    routes = {("POST", "/register"): register_ok}
    monkeypatch.setattr("httpx.AsyncClient", lambda: FakeAsyncClient(routes))
    p = InteractProvider()
    await p.init()

    priv = RSA.import_key(p.private_key_pem.encode())
    public_pem = priv.publickey().export_key("PEM")

    # Make a valid AES key wrapper but random ciphertext bytes so JSON parse fails
    oaep = PKCS1_OAEP.new(RSA.import_key(public_pem), hashAlgo=SHA256)
    aes_key = os.urandom(32)
    aes_key_b64 = base64.b64encode(oaep.encrypt(aes_key)).decode()
    bad_item = base64.b64encode(os.urandom(64)).decode()

    async def poll_bad(**kwargs):
        return FakeResponse(
            status_code=200,
            json_body={"aes_key": aes_key_b64, "data": [bad_item]},
            url=kwargs["url"],
        )

    routes[("GET", "/poll")] = poll_bad

    out = await p.poll_new()
    assert len(out.interactions) == 1
    assert "error" in out.interactions[0]
    # No unique-id means it's not added to seen_ids; another poll returns the same error again
    out2 = await p.poll_new()
    assert len(out2.interactions) == 1
    assert "error" in out2.interactions[0]


@pytest.mark.asyncio
async def test_deregister_calls_endpoint(monkeypatch):
    make_server_config(monkeypatch, server="https://oast.bye", token="BEAR")

    called = {"deregister": 0}

    async def register_ok(**kwargs):
        return FakeResponse(status_code=200, json_body={"message": "Registration successful"}, url=kwargs["url"])

    async def dereg_ok(**kwargs):
        called["deregister"] += 1
        # verify expected auth and params
        assert kwargs["headers"].get("Authorization") == "Bearer BEAR"
        assert "correlation_id" in kwargs["params"] and "secret" in kwargs["params"]
        return FakeResponse(status_code=200, json_body={"message": "deregistered"}, url=kwargs["url"])

    routes = {
        ("POST", "/register"): register_ok,
        ("POST", "/deregister"): dereg_ok,
    }

    monkeypatch.setattr("httpx.AsyncClient", lambda: FakeAsyncClient(routes))

    p = InteractProvider()
    await p.init()
    await p.deregister()
    assert called["deregister"] == 1
