from __future__ import annotations
import base64, json, os, random, string
from typing import Any, Dict, List

import httpx

from shyhurricane.mcp_server.server_config import ProviderName, get_server_config
from shyhurricane.outofband import OOBProvider, _state, Endpoints, PollOutput, HealthOutput
from shyhurricane.utils import b64

try:
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
except Exception:
    # Only needed for interact.sh; webhook.site & collaborator bridge don't need crypto
    AES = PKCS1_OAEP = SHA256 = RSA = None  # type: ignore

PUBLIC_SERVERS = ["oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me"]


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


class InteractProvider(OOBProvider):
    name: ProviderName = "interactsh"

    async def health(self, session: Dict[str, Any]) -> HealthOutput:
        server_config = get_server_config()
        server = server_config.out_of_band.interact_server or random.choice(PUBLIC_SERVERS)
        async with httpx.AsyncClient() as client:
            r = await client.get(f"https://{server}/alive", timeout=5)
        if r.status_code == 200:
            return HealthOutput(status="ok")
        return HealthOutput(status="error", detail=f"HTTP {r.status_code}")

    async def init(self, session: Dict[str, Any]) -> Endpoints:
        if RSA is None:
            raise RuntimeError("pycryptodome is required for interact.sh (pip install pycryptodome)")

        st = _state(session)
        if st.get("provider", None) == self.name:
            return await self.endpoints(session)

        server_config = get_server_config()
        server = server_config.out_of_band.interact_server or random.choice(PUBLIC_SERVERS)
        token = server_config.out_of_band.interact_token

        pre = _rand(20)
        nonce = _rand(13)
        correlation_id = f"{pre}{nonce}"
        secret = b64(os.urandom(24))

        key = RSA.generate(2048)
        st["private_key_pem"] = key.export_key("PEM").decode()
        public_pem = key.publickey().export_key("PEM")

        headers = {"Accept": "application/json"}
        if token: headers["Authorization"] = token
        async with httpx.AsyncClient() as client:
            r = await client.post(f"https://{server}/register", headers=headers, json={
                "public-key": b64(public_pem),
                "secret-key": secret,
                "correlation-id": correlation_id,
            }, timeout=20)
        r.raise_for_status()
        msg = (r.json() or {}).get("message", "")
        if "registration successful" not in msg.lower():
            raise RuntimeError(f"interact.sh register failed: {msg!r}")

        domain = f"{pre}{nonce}.{server}"
        st.update({"provider": self.name, "server": server, "token": token,
                   "correlation_id": correlation_id, "secret": secret, "domain": domain})
        return await self.endpoints(session)

    async def endpoints(self, session: Dict[str, Any]) -> Endpoints:
        st = _state(session)
        if st.get("provider") != self.name or not st.get("domain"):
            raise RuntimeError("interact.sh session not initialized")
        d = st["domain"]
        return Endpoints(
            dns=d, http=f"http://{d}", https=f"https://{d}",
            smtp=f"{d.split('.', 1)[0]}@{d}", smtp_domain=d, ldap=f"ldap://{d}"
        )

    async def poll_new(self, session: Dict[str, Any]) -> PollOutput:
        st = _state(session)
        for k in ("server", "correlation_id", "secret", "private_key_pem"):
            if not st.get(k): raise RuntimeError("interact.sh session not initialized")
        headers = {"Accept": "application/json"}
        if st.get("token"): headers["Authorization"] = st["token"]
        async with httpx.AsyncClient() as client:
            r = await client.get(f"https://{st['server']}/poll",
                                 params={"id": st["correlation_id"], "secret": st["secret"]},
                                 headers=headers, timeout=20)
        r.raise_for_status()
        js = r.json() or {}
        data_list = js.get("data") or []
        aes_key_b64 = js.get("aes_key")
        out: List[Dict[str, Any]] = []
        seen: set[str] = st["seen_ids"]
        if data_list and aes_key_b64:
            for enc in data_list:
                try:
                    item = _decrypt_interact(aes_key_b64, enc, st["private_key_pem"])
                except Exception as e:
                    item = {"error": f"decrypt_failed: {e.__class__.__name__}: {e}"}
                uid = item.get("unique-id")
                if uid and uid in seen: continue
                if uid: seen.add(uid)
                out.append(item)
        st["seen_ids"] = list(seen)
        return PollOutput(interactions=out)
