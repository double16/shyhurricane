import base64
import json
import os
import random
import string
import logging
from typing import Any, Dict, List

import httpx

from shyhurricane.server_config import get_server_config
from shyhurricane.oast import OASTProvider, Endpoints, PollOutput, HealthOutput
from shyhurricane.utils import b64

try:
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
except Exception:
    # Only needed for interact.sh; webhook.site & collaborator bridge don't need crypto
    AES = PKCS1_OAEP = SHA256 = RSA = None  # type: ignore

PUBLIC_SERVERS = ["oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me"]

logger = logging.getLogger(__name__)


def _rand(n: int) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))


def _decrypt_interact(aes_key_b64: str, data_b64: str, private_key_pem: str) -> Dict[str, Any]:
    priv = RSA.import_key(private_key_pem)
    oaep = PKCS1_OAEP.new(priv, hashAlgo=SHA256)
    aes_key = oaep.decrypt(base64.b64decode(aes_key_b64))
    blob = base64.b64decode(data_b64)
    iv = blob[:16]
    cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv, segment_size=128)
    plain = cipher.decrypt(blob)
    return json.loads(plain[16:])


class InteractProvider(OASTProvider):
    def __init__(self):
        super().__init__()
        self.private_key_pem = None
        self.server = None
        self.token = None
        self.correlation_id = None
        self.secret = None
        self.domain = None

    @staticmethod
    def _server_url(server: str):
        if "://" in server:
            return server
        return "https://" + server

    async def health(self) -> HealthOutput:
        server_config = get_server_config()
        server = server_config.oast.interact_server or random.choice(PUBLIC_SERVERS)
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{self._server_url(server)}/alive", timeout=5)
        if r.status_code == 200:
            return HealthOutput(status="ok")
        return HealthOutput(status="error", detail=f"HTTP {r.status_code}")

    async def init(self) -> Endpoints:
        if RSA is None:
            raise RuntimeError("pycryptodome is required for interact.sh (pip install pycryptodome)")

        if self.inited:
            return await self.endpoints()

        server_config = get_server_config()
        server = server_config.oast.interact_server or random.choice(PUBLIC_SERVERS)
        token = server_config.oast.interact_token

        pre = _rand(20)
        nonce = _rand(13)
        correlation_id = f"{pre}{nonce}"
        secret = b64(os.urandom(24))

        key = RSA.generate(2048)
        self.private_key_pem = key.export_key("PEM").decode()
        public_pem = key.publickey().export_key("PEM")

        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        async with httpx.AsyncClient() as client:
            r = await client.post(f"{self._server_url(server)}/register", headers=headers, json={
                "public-key": b64(public_pem),
                "secret-key": secret,
                "correlation-id": correlation_id,
            }, timeout=20)
        r.raise_for_status()
        msg = (r.json() or {}).get("message", "")
        if "registration successful" not in msg.lower():
            raise RuntimeError(f"interact.sh register failed: {msg!r}")

        if "://" in server:
            domain = f"{pre}{nonce}.{server.split("://", 1)[1]}"
        else:
            domain = f"{pre}{nonce}.{server}"
        self.inited = True
        self.server = server
        self.token = token
        self.correlation_id = correlation_id
        self.secret = secret
        self.domain = domain

        return await self.endpoints()

    async def endpoints(self) -> Endpoints:
        self._check_inited()
        d = self.domain
        d_no_port = d.split(":", 1)[0]
        return Endpoints(
            dns=d_no_port, http=f"http://{d}", https=f"https://{d}",
            smtp=f"{d.split('.', 1)[0]}@{d_no_port}", smtp_domain=d_no_port, ldap=f"ldap://{d_no_port}"
        )

    async def poll_new(self) -> PollOutput:
        self._check_inited()
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        async with httpx.AsyncClient() as client:
            url = f"{self._server_url(self.server)}/poll"
            params = {"id": self.correlation_id, "secret": self.secret}
            logger.info("Polling %s with params %s and headers %s", url, params, headers)
            r = await client.get(url, params=params, headers=headers, timeout=20)
        r.raise_for_status()
        js = r.json() or {}
        logger.info("poll result %s", js)
        data_list = js.get("data", [])
        aes_key_b64 = js.get("aes_key")
        out: List[Dict[str, Any]] = []
        seen: set[str] = self.seen_ids
        if data_list and aes_key_b64:
            for enc in data_list:
                try:
                    item = _decrypt_interact(aes_key_b64, enc, self.private_key_pem)
                    uid = item.get("unique-id")
                    if uid and uid not in seen:
                        seen.add(uid)
                        out.append(item)
                except Exception as e:
                    item = {"error": f"decrypt_failed: {e.__class__.__name__}: {e}"}
                    out.append(item)
        self.seen_ids = seen
        return PollOutput(interactions=out)

    async def deregister(self) -> None:
        if not self.inited:
            return
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        async with httpx.AsyncClient() as client:
            url = f"{self._server_url(self.server)}/deregister"
            params = {"correlation_id": self.correlation_id, "secret": self.secret}
            logger.info("Deregistering %s with params %s and headers %s", url, params, headers)
            await client.post(url, params=params, headers=headers, timeout=20)
