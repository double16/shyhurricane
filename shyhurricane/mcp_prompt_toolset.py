import logging
from typing import List, Dict

import requests
from haystack import component

logger = logging.getLogger(__name__)


@component
class MCPPromptTool:
    """
    Call an MCP prompt (POST /prompt/<name>) and return the JSON reply.
    """

    def __init__(self, base_url: str, prompt_name: str):
        super().__init__()
        if base_url.endswith("/"):
            base_url = base_url[:-1]
        self.url = f"{base_url}/prompt/{prompt_name}"
        self.session_id = None  # set after first call

    def run(self, **kwargs):  # kwargs == parameters for the prompt
        headers = {"Content-Type": "application/json"}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id

        resp = requests.post(self.url, json=kwargs, headers=headers, timeout=60)
        resp.raise_for_status()

        # preserve session header for multi-turn chat
        if "Mcp-Session-Id" in resp.headers:
            self.session_id = resp.headers["Mcp-Session-Id"]

        return {"result": resp.json()}


class MCPPromptToolset:
    """Query an MCP endpoint for its prompt registry and generate a list of
    :class:`MCPPromptTool` instances, accessible both via iteration and by
    name-indexing (``toolset["prompt_name"]``).
    """

    def __init__(self, base_url: str, *, include_openworld: bool = False):
        if base_url.endswith("/"):  # tidy
            base_url = base_url[:-1]
        self.base_url = base_url
        self._tool_map: Dict[str, MCPPromptTool] = {}
        self._discover(include_openworld)

    # ------------------------------------------------------------------
    def _discover(self, include_openworld: bool):
        """Populate self._tool_map by calling GET <base_url>/mcp."""
        try:
            resp = requests.get(f"{self.base_url}/mcp", timeout=15)
            resp.raise_for_status()
            manifest = resp.json()
            prompts = manifest.get("prompts", [])
            for p in prompts:
                if not include_openworld and p.get("openworld", False):
                    continue  # skip internet-reaching tools by default
                name = p["name"]
                self._tool_map[name] = MCPPromptTool(self.base_url, name)
            logger.info("MCP discovery: registered %d prompt tools", len(self))
        except Exception as exc:
            logger.error("MCP discovery failed: %s", exc)
            raise

    # ------------------------------------------------------------------
    @property
    def tools(self) -> List[MCPPromptTool]:
        """Return the list of instantiated tools (order is deterministic)."""
        return list(self._tool_map.values())

    # dict-like access ---------------------------------------------------
    def __getitem__(self, name: str) -> MCPPromptTool:
        return self._tool_map[name]

    def __iter__(self):
        return iter(self._tool_map.values())

    def __len__(self):
        return len(self._tool_map)

    # nice repr ----------------------------------------------------------
    def __repr__(self):
        names = ", ".join(self._tool_map)
        return f"<MCPPromptToolset [{names}]>"
