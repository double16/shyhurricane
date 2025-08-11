from __future__ import annotations

from typing import Optional, Dict, List, Any, Literal

from pydantic import BaseModel, Field

from shyhurricane.mcp_server.server_config import ProviderName


class Endpoints(BaseModel):
    # Optional fields to support heterogeneous providers
    dns: Optional[str] = None
    http: Optional[str] = None
    https: Optional[str] = None
    smtp: Optional[str] = None
    smtp_domain: Optional[str] = None
    ldap: Optional[str] = None
    # provider-specific extras
    extras: Dict[str, str] = Field(default_factory=dict)


class PollOutput(BaseModel):
    interactions: List[Dict[str, Any]] = Field(default_factory=list)


class HealthOutput(BaseModel):
    status: str = Field(..., description='"ok" if provider is reachable, "error" otherwise')
    detail: Optional[str] = Field(None, description="Optional error message")


class OOBProvider:
    name: ProviderName

    async def health(self, session: Dict[str, Any]) -> HealthOutput: ...

    async def init(self, session: Dict[str, Any]) -> Endpoints: ...

    async def endpoints(self, session: Dict[str, Any]) -> Endpoints: ...

    async def poll_new(self, session: Dict[str, Any]) -> PollOutput: ...


def _state(session: Dict[str, Any]) -> Dict[str, Any]:
    st = session.setdefault("oob", {})
    st.setdefault("seen_ids", [])
    if not isinstance(st["seen_ids"], set):
        st["seen_ids"] = set(st["seen_ids"])
    return st
