from __future__ import annotations
from typing import Any, Dict, List

import httpx

from shyhurricane.server_config import get_server_config
from shyhurricane.oast import OASTProvider, Endpoints, PollOutput, HealthOutput


# Docs: API is public; create token; list requests; also supports subdomain form, email, and DNSHook.
# Token -> URL: https://webhook.site/{uuid} and https://{uuid}.webhook.site
# Email: {uuid}@emailhook.site ; DNS: {uuid}.dnshook.site
# Ref: usage/auth + examples + endpoints.
# (Unauthenticated works for many endpoints; add Api-Key header if available.)

class WebhookSiteProvider(OASTProvider):
    def __init__(self):
        super().__init__()
        self.webhook_token_id = None

    def _headers(self) -> Dict[str, str]:
        server_config = get_server_config()
        h = {"Accept": "application/json", "Content-Type": "application/json"}
        if server_config.oast.webhook_api_key:
            h["Api-Key"] = server_config.oast.webhook_api_key
        return h

    async def health(self) -> HealthOutput:
        async with httpx.AsyncClient() as client:
            r = await client.get("https://webhook.site", timeout=5)
            if r.status_code == 200:
                return HealthOutput(status="ok")
            return HealthOutput(status="error", detail=f"HTTP {r.status_code}")

    async def init(self) -> Endpoints:
        if self.inited:
            return await self.endpoints()

        # Create a new token (works without Api-Key; with key it associates to your account)
        async with httpx.AsyncClient() as client:
            r = await client.post("https://webhook.site/token", headers=self._headers(), timeout=20)
        r.raise_for_status()
        js = r.json()
        token_id = js["uuid"]
        self.inited = True
        self.webhook_token_id = token_id
        return await self.endpoints()

    async def endpoints(self) -> Endpoints:
        self._check_inited()
        tid = self.webhook_token_id
        # expose common OAST-ish surfaces where applicable
        return Endpoints(
            http=f"http://webhook.site/{tid}",
            https=f"https://webhook.site/{tid}",
            dns=f"{tid}.dnshook.site",  # DNSHook (works where available)
            smtp=f"{tid}@emailhook.site",  # Emailhook address
            extras={
                "http_subdomain": f"https://{tid}.webhook.site",
                "token_id": tid
            }
        )

    async def poll_new(self) -> PollOutput:
        self._check_inited()
        tid = self.webhook_token_id
        # newest-first, single page is fine for polling loops
        url = f"https://webhook.site/token/{tid}/requests"
        async with httpx.AsyncClient() as client:
            r = await client.get(url, headers=self._headers(), params={"sorting": "newest"}, timeout=20)
        r.raise_for_status()
        data = r.json() or {}
        items = data.get("data") or []
        out: List[Dict[str, Any]] = []
        seen: set[str] = self.seen_ids
        for it in items:
            uid = it.get("uuid")
            if uid and uid in seen: continue
            if uid: seen.add(uid)
            out.append(it)
        self.seen_ids = seen
        return PollOutput(interactions=out)

    async def deregister(self) -> None:
        if not self.inited:
            return
        tid = self.webhook_token_id
        url = f"https://webhook.site/token/{tid}"
        async with httpx.AsyncClient() as client:
            await client.delete(url, params={"password": ""}, headers=self._headers(), timeout=20)
