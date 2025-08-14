from dataclasses import dataclass
from typing import Any, Callable, Dict

from haystack_integrations.tools.mcp import MCPTool


def normalize_all_types(schema: Any) -> Any:
    """Wrap any JSON Schema 'type' string into ['type'] at all levels."""
    if isinstance(schema, dict):
        out = {k: normalize_all_types(v) for k, v in schema.items()}
        if "type" in out and isinstance(out["type"], str):
            out["type"] = [out["type"]]
        return out
    if isinstance(schema, list):
        return [normalize_all_types(x) for x in schema]
    return schema


@dataclass
class ToolLike:
    name: str
    description: str
    parameters: Dict[str, Any]
    function: Callable[..., Any]

    @property
    def tool_spec(self) -> Dict[str, Any]:
        # Common serialization used by many adapters
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def to_openai_tool(self) -> Dict[str, Any]:
        # OpenAI-compatible dict
        return self.tool_spec

    def to_dict(self) -> Dict[str, Any]:
        # Some Haystack/Ollama paths call to_dict(); return same structure
        return self.tool_spec


def wrap_mcp_tool_for_ollama(mcp: MCPTool) -> ToolLike:
    # Ensure the MCP tool spec is available
    spec = getattr(mcp, "tool_spec", None)
    if not spec:
        try:
            mcp.invoke()
        except Exception:
            pass
        spec = mcp.tool_spec or {}

    fn = spec.get("function", {})
    name = fn.get("name") or getattr(mcp, "name", "mcp_tool")
    desc = fn.get("description") or getattr(mcp, "description", "")
    root_params = fn.get("parameters") or getattr(mcp, "parameters", None) or {"type": "object", "properties": {}}
    params = normalize_all_types(root_params)

    def _delegate(**kwargs):
        return mcp.invoke(**kwargs)

    return ToolLike(name=name, description=desc, parameters=params, function=_delegate)

