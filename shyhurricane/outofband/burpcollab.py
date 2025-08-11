from __future__ import annotations
from typing import Any, Dict, List

import httpx

from shyhurricane.mcp_server.server_config import get_server_config, ProviderName
from shyhurricane.outofband import OOBProvider, _state, Endpoints, PollOutput, HealthOutput


# There is no public HTTP API for the PortSwigger public server; programmatic access is via Burp's CollaboratorClient (Montoya API) inside Burp.
# This provider calls a *bridge* you run locally (e.g., a tiny Java service/extension that exposes HTTP endpoints to create/poll payloads).
# If no BURP_COLLAB_BRIDGE_URL is provided at startup, init/poll will raise an error with guidance.

class BurpCollaboratorProvider(OOBProvider):
    name: ProviderName = "burp_collaborator"

    def __init__(self):
        server_config = get_server_config()
        self.burp_bridge_url = server_config.out_of_band.burp_bridge_url
        self.burp_bridge_secret = server_config.out_of_band.burp_bridge_secret

    def _bridge(self) -> str:
        if not self.burp_bridge_url:
            raise RuntimeError(
                "Burp Collaborator requires a local bridge built on the Montoya API. "
                "Set BURP_COLLAB_BRIDGE_URL to enable (e.g., http://127.0.0.1:8009)."
            )
        return self.burp_bridge_url.rstrip("/")

    def _headers(self) -> Dict[str, str]:
        h = {"Accept": "application/json"}
        if self.burp_bridge_secret:
            h["X-Bridge-Secret"] = self.burp_bridge_secret
        return h

    async def health(self, session: Dict[str, Any]) -> HealthOutput:
        if not self.burp_bridge_url:
            return HealthOutput(status="error", detail="BURP_COLLAB_BRIDGE_URL not set")
        headers = {}
        if self.burp_bridge_secret:
            headers["X-Bridge-Secret"] = self.burp_bridge_secret
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{self.burp_bridge_url.rstrip('/')}/health", headers=headers, timeout=5)
        if r.status_code == 200:
            return HealthOutput(status="ok")
        return HealthOutput(status="error", detail=f"HTTP {r.status_code}")

    async def init(self, session: Dict[str, Any]) -> Endpoints:
        st = _state(session)
        if st.get("provider", None) == self.name:
            return await self.endpoints(session)

        # Expect the bridge to create a payload and return JSON with fields:
        # { "payload": "abc123.oastify.com", "biid": "...", "poll_secret": "..." }
        async with httpx.AsyncClient() as client:
            r = await client.post(f"{self._bridge()}/collab/init", headers=self._headers(), timeout=15)
        r.raise_for_status()
        js = r.json()
        host = js["payload"]
        st.update({"provider": self.name, "collab_payload": host, "collab_biid": js.get("biid"),
                   "collab_secret": js.get("poll_secret")})
        return Endpoints(
            dns=host, http=f"http://{host}", https=f"https://{host}",
            smtp=f"{host.split('.', 1)[0]}@{host}", smtp_domain=host
        )

    async def endpoints(self, session: Dict[str, Any]) -> Endpoints:
        st = _state(session)
        if st.get("provider") != self.name or not st.get("collab_payload"):
            raise RuntimeError("Burp Collaborator session not initialized")
        host = st["collab_payload"]
        return Endpoints(
            dns=host, http=f"http://{host}", https=f"https://{host}",
            smtp=f"{host.split('.', 1)[0]}@{host}", smtp_domain=host
        )

    async def poll_new(self, session: Dict[str, Any]) -> PollOutput:
        st = _state(session)
        if st.get("provider") != self.name or not st.get("collab_biid"):
            raise RuntimeError("Burp Collaborator session not initialized or bridge missing")
        async with httpx.AsyncClient() as client:
            r = await client.request(
                f"{self._bridge()}/collab/poll",
                params={"biid": st["collab_biid"]},
                headers=self._headers(),
                timeout=20
            )
        r.raise_for_status()
        js = r.json() or {}
        items = js.get("interactions") or []
        out: List[Dict[str, Any]] = []
        seen: set[str] = st["seen_ids"]
        for it in items:
            uid = it.get("unique-id") or it.get("id")
            if uid and uid in seen: continue
            if uid: seen.add(uid)
            out.append(it)
        st["seen_ids"] = list(seen)
        return PollOutput(interactions=out)
