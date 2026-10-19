"""Compact presentation and explicit resource associations over a bounded graph snapshot."""

from collections import defaultdict
from urllib.parse import urlsplit

from shyhurricane.graph.model import web_url

NODE_FIELDS = {"id", "kind", "name", "role", "url", "method", "source_path", "location"}
STEP_FIELDS = {
    "id", "kind", "source", "target", "classification", "evidence_id", "original_hops", "summary_notice"
}
INTERPRETATION = (
    "Source/sink labels describe static operations, including network boundaries, not proven attacker control. "
    "Framework symbols and generic property reads do not establish prototype pollution or template injection. "
    "Script association is not data-flow evidence. HTTP captures do not establish backend database or filesystem execution."
)


def present(item, detail, *, step=False):
    if detail not in {"compact", "full"}:
        raise ValueError("detail must be compact or full")
    if detail == "full":
        return dict(item)
    fields = STEP_FIELDS if step else NODE_FIELDS
    return {key: value for key, value in item.items() if key in fields}


def in_context(node, url):
    return node["url"] == url or url in node.get("context_urls", [])


class ResourceDiscovery:
    """Index associations without treating containment or script loading as flow edges."""

    def __init__(self, nodes, relationships):
        self.nodes = nodes
        self.resources = {key: node for key, node in nodes.items() if node["kind"] == "resource"}
        self.by_url = defaultdict(set)
        self.direct = defaultdict(set)
        self.contexts = defaultdict(set)
        self.loads = defaultdict(set)
        self.captured = set()
        self.script_ids = set()
        for key, node in nodes.items():
            if key in self.resources:
                self.by_url[node["url"]].add(key)
                if urlsplit(node["url"]).path.lower().endswith((".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")):
                    self.script_ids.add(key)
            for url in node.get("context_urls", []):
                self.contexts[url].add(key)
        for edge in relationships:
            source, target, kind = edge["source"], edge["target"], edge["kind"]
            if kind == "HOSTED_AT" and edge.get("classification") == "observed":
                self.captured.add(source)
            if source in self.resources and kind in {"CONTAINS", "SENDS_FIELD", "SETS_COOKIE"}:
                self.direct[source].add(target)
                if nodes[target].get("source_path") == nodes[source]["url"]:
                    self.script_ids.add(source)
            if target in self.resources and kind in {"SENDS_FIELD", "SUBMITS_TO", "SENDS_COOKIE"}:
                if source not in self.resources:
                    self.direct[target].add(source)
            if kind in {"LOADS", "IMPORTS"} and target in self.resources:
                self.loads[source].add(target)

    def associated(self, resource_id):
        resource = self.resources[resource_id]
        direct = self.direct[resource_id]
        contextual = self.contexts[resource["url"]]
        scripts = ((self.loads[resource_id] | contextual) & self.script_ids) - {resource_id}
        related = set(contextual)
        for script_id in scripts:
            related.update(self.direct[script_id])
        return direct, related - direct, scripts

    def select(self, value, role=None):
        selected = {value} if value in self.nodes else self.by_url.get(web_url(value, fragment=True), set())
        if role is None:
            return sorted(selected)
        seeds = set()
        for key in selected:
            if key not in self.resources:
                seeds.add(key)
                continue
            direct, related, _ = self.associated(key)
            seeds.update(candidate for candidate in direct | related if self.nodes[candidate].get("role") == role)
        return sorted(seeds)

    def overview(self, resource_id, scope):
        resource = self.resources[resource_id]
        direct, related, scripts = self.associated(resource_id)

        def section(ids, follow_up):
            ordered = sorted(ids, key=lambda key: (self.nodes[key].get("name", ""), key))
            return {
                "count": len(ordered),
                "examples": [
                    {
                        **present(self.nodes[key], "compact"),
                        "association": "direct" if key in direct else "script_context",
                    }
                    for key in ordered[:3]
                ],
                "examples_limited": len(ordered) > 3,
                "follow_up": follow_up if ordered else [],
            }

        result = {
            "id": resource_id,
            "url": resource["url"],
            "method": resource.get("method", "GET"),
            "capture_status": "captured" if resource_id in self.captured else "referenced",
            "inputs": section(
                {
                    key
                    for key in direct
                    if self.nodes[key]["kind"] == "field"
                    or (
                        self.nodes[key]["kind"] == "element"
                        and self.nodes[key].get("html_tag") in {"input", "select", "textarea", "form"}
                    )
                },
                [
                    {
                        "tool": "find_application_relationships",
                        "arguments": {
                            "scope": scope,
                            "element_id": resource_id,
                            "direction": direction,
                            "max_depth": 1,
                        },
                    }
                    for direction in ("forward", "backward")
                ],
            ),
            "scripts": section(
                scripts,
                [
                    {
                        "tool": "find_application_relationships",
                        "arguments": {"scope": scope, "element_id": resource_id, "kinds": ["LOADS", "IMPORTS"]},
                    },
                    {
                        "tool": "find_application_elements",
                        "arguments": {"scope": scope, "context_url": resource["url"], "kinds": ["resource"]},
                    },
                ],
            ),
        }
        for role in ("source", "sink"):
            result[f"{role}s"] = section(
                {key for key in direct | related if self.nodes[key].get("role") == role},
                [
                    {
                        "tool": "find_application_elements",
                        "arguments": {"scope": scope, "context_url": resource["url"], "role": role},
                    },
                    {
                        "tool": "find_application_relationships",
                        "arguments": {"scope": scope, "element_id": resource_id, "direction": "backward"},
                    },
                ],
            )
        return result
