from typing import Optional, Dict, List, Any, Set

from mcp import McpError, ErrorData
from pydantic import BaseModel, Field


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
    status: str = Field(description='"ok" if provider is reachable, "error" otherwise')
    detail: Optional[str] = Field(None, description="Optional error message")


class OASTProvider:
    def __init__(self):
        self.inited = False
        self.seen_ids: Set[str] = set()

    def _check_inited(self):
        if not self.inited:
            raise McpError(ErrorData(code=400, message=f"{self.name} session not initialized"))

    async def health(self) -> HealthOutput: ...

    async def init(self) -> Endpoints: ...

    async def endpoints(self) -> Endpoints: ...

    async def poll_new(self) -> PollOutput: ...

    async def deregister(self) -> None: ...
