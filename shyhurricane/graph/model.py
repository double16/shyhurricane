"""Stable identities and a transport-independent semantic graph."""

import hashlib
import json
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit, urlunsplit

ANALYSIS_VERSION = 2
MAX_BYTES = 40 * 1024 * 1024
MAX_GRAPH_NODES = 10000
MAX_GRAPH_EDGES = 20000
FLOW_KINDS = {
    "FLOWS_TO", "CALL_ARGUMENT", "RETURNS_TO", "READS_FROM", "WRITES_TO", "SUBMITS_TO", "REQUESTS", "SUMMARIZED_FLOW"
}
JOURNEY_KINDS = {"NAVIGATES_TO", "SUBMITS_TO", "REDIRECTS_TO"}


def identity(*parts) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def web_url(value: str, base: str = "", *, fragment: bool = False) -> str | None:
    """Normalize only URL authority; preserve path escaping and query order/values."""
    try:
        parsed = urlsplit(urljoin(base, value.strip()))
        if parsed.scheme.lower() not in {"http", "https", "ws", "wss"} or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        host = parsed.hostname.lower()
        host = f"[{host}]" if ":" in host else host
        port = parsed.port
        if port and port != {"http": 80, "https": 443, "ws": 80, "wss": 443}[parsed.scheme.lower()]:
            host += f":{port}"
        return urlunsplit(
            (parsed.scheme.lower(), host, parsed.path or "/", parsed.query, parsed.fragment if fragment else "")
        )
    except (ValueError, AttributeError):
        return None


def optional_filter(value):
    """Treat blank optional filters as omitted without coercing other types."""
    return (value.strip() or None) if isinstance(value, str) else value


def capture_unit_path(event):
    """Keep root-unit identity tied to the retained capture, before URL normalization."""
    return "capture:" + event["data"]["url"]


def capture_event(request_response, *, backfill: bool = False) -> dict:
    data = request_response.model_dump() if hasattr(request_response, "model_dump") else dict(request_response)
    capture_id = identity("capture", data)
    try:
        value = str(data.get("timestamp", "")).replace("Z", "+00:00")
        stamp = datetime.fromisoformat(value)
        stamp = stamp.replace(tzinfo=timezone.utc) if stamp.tzinfo is None else stamp
        observed_at = stamp.timestamp()
        inferred = False
    except (ValueError, TypeError):
        observed_at = datetime.now(timezone.utc).timestamp()
        inferred = True
    return {
        "id": capture_id,
        "data": data,
        "observed_at": observed_at,
        "timestamp_inferred": inferred,
        "backfill": backfill,
    }


class Projection:
    """One immutable capture projection. All properties are Neo4j-compatible scalars."""

    def __init__(self, event: dict):
        self.event = event
        self.url = web_url(event["data"]["url"]) or event["data"]["url"]
        self.nodes: dict[str, dict] = {}
        self.edges: dict[str, dict] = {}
        self.evidence: dict[str, dict] = {}
        self.gaps: list[str] = []
        self.contexts: list[dict] = []
        self.browser_references: list[str] = []
        self.candidate_sources: list[dict] = []
        self.analysis: list[dict] = []
        self.planned_links = None
        self.structural_nodes = None
        self.node_limit = MAX_GRAPH_NODES
        self.edge_limit = MAX_GRAPH_EDGES

    def node(self, kind: str, key: str, **properties) -> str:
        node_id = identity(kind, key)
        if node_id not in self.nodes and len(self.nodes) >= self.node_limit:
            if "Capture entity budget reached" not in self.gaps:
                self.gaps.append("Capture entity budget reached")
            return node_id
        existing = self.nodes.setdefault(
            node_id, {"id": node_id, "kind": kind, "key": key, "url": self.url, "name": key}
        )
        existing.update({key: value for key, value in properties.items() if value is not None})
        return node_id

    def resource(self, url: str, method: str = "GET") -> str:
        return self.node("resource", f"{method.upper()} {url}", url=url, method=method.upper(), name=url)

    def fact(
        self,
        source: str,
        target: str,
        kind: str,
        rule: str,
        *,
        classification: str = "declared",
        location: str = "",
        snippet: str = "",
        **properties,
    ) -> str:
        if source not in self.nodes or target not in self.nodes:
            return ""
        if len(self.edges) >= self.edge_limit:
            if "Capture relationship budget reached" not in self.gaps:
                self.gaps.append("Capture relationship budget reached")
            return ""
        evidence_id = identity(self.event["id"], rule, location, snippet, ANALYSIS_VERSION)
        if kind == "SUMMARIZED_FLOW":
            evidence_id = identity(evidence_id, source, target, properties)
        self.evidence[evidence_id] = {
            "id": evidence_id,
            "capture_id": self.event["id"],
            "url": self.url,
            "rule": rule,
            "location": location,
            "snippet": snippet[:1000],
            "classification": classification,
            "analysis_version": ANALYSIS_VERSION,
            "context_urls": [context["url"] for context in self.contexts],
            "confidence": "observed" if classification == "observed" else "supported",
        }
        if kind == "SUMMARIZED_FLOW":
            self.evidence[evidence_id].update(
                {key: properties[key] for key in ("original_hops", "endpoint_locations", "witness", "summary_notice")}
            )
        edge_id = identity(source, target, kind, evidence_id)
        if properties.get("context_capture_id") is not None:
            edge_id = identity(edge_id, properties["context_capture_id"])
        self.edges[edge_id] = {
            "id": edge_id,
            "source": source,
            "target": target,
            "kind": kind,
            "evidence_id": evidence_id,
            "capture_id": self.event["id"],
            "classification": classification,
            **properties,
        }
        return edge_id


def compact_event(event):
    """Capture bodies stay in the immutable capture artifact, not every planning checkpoint."""
    return {**event, "data": {**event["data"], **{
        key: "" for key in ("response_body", "request_body") if event["data"].get(key)
    }}}


def projection_snapshot(projection):
    """Intern repeated context arrays in JSON checkpoints and publication digests."""
    state = dict(projection.__dict__)
    state["event"] = compact_event(projection.event)
    arrays = sorted({
        tuple(record["context_urls"])
        for name in ("nodes", "evidence") for record in state[name].values()
        if isinstance(record.get("context_urls"), list)
    })
    lookup = {urls: index for index, urls in enumerate(arrays)}
    arrays = [list(urls) for urls in arrays]
    for collection in ("nodes", "evidence"):
        records = {}
        for key, record in state[collection].items():
            record = dict(record)
            if isinstance(record.get("context_urls"), list):
                urls = tuple(record["context_urls"])
                record["context_urls"] = {"_context_list": lookup[urls]}
            records[key] = record
        state[collection] = records
    state["_context_lists"] = arrays
    return state


def restore_projection(snapshot):
    state = dict(snapshot)
    arrays = state.pop("_context_lists", [])
    for collection in ("nodes", "evidence"):
        records = {}
        for key, record in state[collection].items():
            record = dict(record)
            context = record.get("context_urls")
            if isinstance(context, dict) and "_context_list" in context:
                record["context_urls"] = arrays[context["_context_list"]]
            records[key] = record
        state[collection] = records
    projection = Projection(state["event"])
    projection.__dict__.update(state)
    return projection
