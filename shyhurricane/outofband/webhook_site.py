from __future__ import annotations
from typing import Any, Dict, List

import httpx

from shyhurricane.mcp_server.server_config import ProviderName, get_server_config
from shyhurricane.outofband import OOBProvider, Endpoints, _state, PollOutput, HealthOutput


# Docs: API is public; create token; list requests; also supports subdomain form, email, and DNSHook.
# Token -> URL: https://webhook.site/{uuid} and https://{uuid}.webhook.site
# Email: {uuid}@emailhook.site ; DNS: {uuid}.dnshook.site
# Ref: usage/auth + examples + endpoints.
# (Unauthenticated works for many endpoints; add Api-Key header if available.)  # docs
#
# See citations in the chat body.

class WebhookSiteProvider(OOBProvider):
    name: ProviderName = "webhook_site"

    def _headers(self) -> Dict[str, str]:
        server_config = get_server_config()
        h = {"Accept": "application/json", "Content-Type": "application/json"}
        if server_config.out_of_band.webhook_api_key:
            h["Api-Key"] = server_config.out_of_band.webhook_api_key
        return h

    async def health(self, session: Dict[str, Any]) -> HealthOutput:
        async with httpx.AsyncClient() as client:
            r = await client.get("https://webhook.site", timeout=5)
            if r.status_code == 200:
                return HealthOutput(status="ok")
            return HealthOutput(status="error", detail=f"HTTP {r.status_code}")

    async def init(self, session: Dict[str, Any]) -> Endpoints:
        st = _state(session)
        if st.get("provider", None) == self.name:
            return await self.endpoints(session)

        # Create a new token (works without Api-Key; with key it associates to your account)
        async with httpx.AsyncClient() as client:
            r = await client.post("https://webhook.site/token", headers=self._headers(), timeout=20)
        r.raise_for_status()
        js = r.json()
        token_id = js["uuid"]
        st.update({"provider": self.name, "webhook_token_id": token_id})
        return await self.endpoints(session)

    async def endpoints(self, session: Dict[str, Any]) -> Endpoints:
        st = _state(session)
        if st.get("provider") != self.name or not st.get("webhook_token_id"):
            raise RuntimeError("webhook.site session not initialized")
        tid = st["webhook_token_id"]
        # expose common OAST-ish surfaces where applicable
        return Endpoints(
            http=f"https://webhook.site/{tid}",
            https=f"https://webhook.site/{tid}",
            dns=f"{tid}.dnshook.site",  # DNSHook (works where available)
            smtp=f"{tid}@emailhook.site",  # Emailhook address
            extras={
                "http_subdomain": f"https://{tid}.webhook.site",
                "token_id": tid
            }
        )

    async def poll_new(self, session: Dict[str, Any]) -> PollOutput:
        st = _state(session)
        if st.get("provider") != self.name or not st.get("webhook_token_id"):
            raise RuntimeError("webhook.site session not initialized")
        tid = st["webhook_token_id"]
        # newest-first, single page is fine for polling loops
        url = f"https://webhook.site/token/{tid}/requests"
        async with httpx.AsyncClient() as client:
            r = await client.get(url, headers=self._headers(), params={"sorting": "newest"}, timeout=20)
        r.raise_for_status()
        data = r.json() or {}
        items = data.get("data") or []
        out: List[Dict[str, Any]] = []
        seen: set[str] = st["seen_ids"]
        for it in items:
            uid = it.get("uuid")
            if uid and uid in seen: continue
            if uid: seen.add(uid)
            out.append(it)
        st["seen_ids"] = list(seen)
        return PollOutput(interactions=out)
