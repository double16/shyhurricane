"""Bounded passive joins over a single graph publication revision per finding."""

import hashlib
import re
import time

from shyhurricane.finding_metadata import categories
from shyhurricane.graph.budget import QueryBudget
from shyhurricane.graph.model import identity
from shyhurricane.graph.query import GraphQuery
from shyhurricane.investigation.ranking import score
from shyhurricane.investigation.storage import POLICY_VERSION
from shyhurricane.investigation.targets import target_coordinates


class RevisionQuery(GraphQuery):
    """Share one revision across independent focused discovery and traversal operations."""

    def __init__(self, store, revision, budget):
        super().__init__(store, budget=budget)
        self.revision = revision

    def snapshot(self, scope, **arguments):
        raise TimeoutError("Investigation requires revision-aware graph lookup indexes")

    def read(self, statement, **parameters):
        if statement.startswith("/* traversal:revision */"):
            return [{"revision": self.revision}]
        return super().read(statement, **parameters)


def compact_witness(witness, context_url=None):
    """Retain proofs and coordinates without duplicating unbounded script-context arrays."""
    fields = {"id", "kind", "name", "role", "url", "method", "source_path", "location", "capture_id"}
    nodes = []
    for node in witness.get("nodes", []):
        compact = {key: value for key, value in node.items() if key in fields}
        contexts = node.get("context_urls", [])
        if contexts:
            compact["context_urls"] = list(
                dict.fromkeys(([context_url] if context_url in contexts else []) + contexts[:3])
            )[:3]
        nodes.append(compact)
    return {
        "nodes": nodes,
        "steps": [
            {
                key: value
                for key, value in step.items()
                if key
                in {
                    "id",
                    "source",
                    "target",
                    "kind",
                    "evidence_id",
                    "classification",
                    "context_capture_id",
                    "capture_id",
                    "original_hops",
                    "summary_notice",
                }
            }
            for step in witness.get("steps", [])
        ],
        "possible_path": True,
    }


def operation_matches(node, metadata, url, verify_hash):
    location = metadata.get("code_location") or {}
    space = location.get("coordinate_space")
    source_path = node.get("source_path")
    wanted = location.get("source_path")
    if space not in {"delivered", "recovered"} or not source_path or not wanted:
        return False
    delivered = source_path == url
    if delivered != (space == "delivered"):
        return False
    if wanted != source_path and not (delivered and wanted == "source.js"):
        return False
    match = re.fullmatch(r"(\d+):(\d+)(?:-(\d+):(\d+))?", node.get("location", ""))
    if not match or not location.get("start_line"):
        return False
    start = (location["start_line"], location.get("start_column", 1))
    end = (location.get("end_line", start[0]), location.get("end_column", 2**31))
    node_start = (int(match[1]), int(match[2]) + 1)
    node_end = (int(match[3] or match[1]), int(match[4] or match[2]) + 1)
    if node_end < start or node_start > end:
        return False
    if metadata.get("capture_id"):
        if metadata["capture_id"] != node.get("capture_id"):
            return False
        return not metadata.get("content_sha256") or verify_hash(node, metadata["content_sha256"])
    return bool(metadata.get("content_sha256") and verify_hash(node, metadata["content_sha256"]))


def artifact_hash_verifier(artifacts):
    cache = {}

    def verify(node, digest):
        capture_id = node.get("capture_id")
        if not capture_id or node.get("source_path") != node.get("url"):
            return False
        if capture_id not in cache:
            row = artifacts.connection.execute("SELECT path FROM captures WHERE id=?", (capture_id,)).fetchone()
            if not row:
                return False
            body = artifacts.read(row[0])["data"].get("response_body") or ""
            cache[capture_id] = hashlib.sha256(body.encode(errors="surrogatepass")).hexdigest()
        return cache[capture_id] == digest

    return verify


def correlate(job, query, graph_revision, *, verify_hash=lambda node, digest: False):
    metadata = job["metadata"]
    target = job["target"]
    coordinates = target_coordinates(target)
    url, scope = coordinates.url, coordinates.scope
    conflicts = job["conflicts"]
    anchor_conflict = any(
        item["field"].split(".")[0]
        in {
            "affected_method",
            "code_location",
            "capture_id",
            "content_sha256",
            "parameter",
        }
        for item in conflicts
    )
    candidate = {
        "id": identity("investigation", job["id"]),
        "kind": "target",
        "finding_ids": [job["id"]],
        "finding_revisions": {job["id"]: job["revision"]},
        "metadata": metadata,
        "metadata_conflicts": conflicts,
        "graph_revision": graph_revision,
        "policy_version": POLICY_VERSION,
        "materialized_at": time.time(),
        "affected_urls": [target],
        "affected_methods": [],
        "vulnerability_types": categories(metadata),
        "anchor": "host" if not url else "url",
        "connectivity": "association",
        "hypothesis": False,
        "witnesses": [],
        "context_urls": [],
        "operation_ids": [],
        "sink_ids": [],
        "source_ids": [],
        "resource_ids": [],
        "analysis_gaps": [],
        "missing_prerequisites": [],
        "follow_up": [],
        "anchor_conflict": anchor_conflict,
        "incomplete_path": False,
        "contexts_limited": False,
        "coverage": {"discovery": "bounded", "flow": "bounded"},
        "association_keys": [],
        "excluded": metadata.get("verification_status") == "false_positive",
    }
    if candidate["excluded"] or not url:
        if not url:
            candidate["missing_prerequisites"].append(
                "Identify an affected URL; host context is not an endpoint anchor"
            )
        candidate.update(score(candidate))
        return candidate
    gaps = set()

    def collect(result, relation=None):
        gaps.update(result.get("analysis_gaps", []))
        if result.get("retrieval_truncated"):
            candidate["contexts_limited"] = True
            candidate["incomplete_path"] = True
            gaps.add("Correlation uses bounded graph results: " + ", ".join(result.get("truncation_reasons", [])))
        if relation:
            available = max(0, 100 - sum(w["relation"] == relation for w in candidate["witnesses"]))
            for witness in result.get("results", [])[:available]:
                if any(len(node.get("context_urls", [])) > 3 for node in witness.get("nodes", [])):
                    candidate["contexts_limited"] = True
                    gaps.add("Witness context memberships retain at most three examples")
                candidate["witnesses"].append({"relation": relation, **compact_witness(witness, url)})
            if len(result.get("results", [])) > available:
                candidate["contexts_limited"] = True
                gaps.add("Witness retention limited to 100 per relation")
        return result.get("results", [])

    resources = collect(query.endpoints(scope, url=url, method=metadata.get("affected_method"), detail="summary"))
    candidate["resource_ids"] = [item["id"] for item in resources]
    candidate["affected_methods"] = sorted({item["method"] for item in resources if item.get("method")})
    if not resources:
        candidate["anchor"] = "host"
        gaps.add("Affected URL or method has no resource in the selected graph")
    elif metadata.get("affected_method") and not anchor_conflict:
        candidate["anchor"] = "method"
    elif len(candidate["affected_methods"]) > 1:
        gaps.add("Affected method is unknown; multiple resource methods match")
    elements = collect(query.elements(scope, url=url, detail="full")) if resources else []
    operations = [
        node for node in elements if not anchor_conflict and operation_matches(node, metadata, url, verify_hash)
    ]
    if operations:
        candidate["anchor"] = "operation"
        candidate["operation_ids"] = sorted({node["id"] for node in operations})
    elif metadata.get("code_location"):
        gaps.add("Code location could not be bound to compatible artifact identity and coordinates")
    consumers = (
        collect(
            query.paths(
                scope,
                url,
                direction="backward",
                mode="relationships",
                kinds=["LOADS", "IMPORTS"],
                max_depth=8,
                detail="full",
            ),
            "consumer",
        )
        if resources
        else []
    )
    contexts = {url} if resources else set()
    for witness in consumers:
        contexts.update(node["url"] for node in witness["nodes"] if node["kind"] == "resource")
    # Association establishes consumers only. Sources and sinks require existing flow edges.
    starts = candidate["resource_ids"][:20]
    for resource_id in starts:
        collect(query.paths(scope, resource_id, mode="flow", detail="full", max_depth=8), "flow")
    if len(candidate["resource_ids"]) > 20:
        gaps.add("Flow seeds limited to 20 methods")
        candidate["contexts_limited"] = True
    for operation in operations[:10]:
        # A backward witness ends at a source. Reverse it before joining to a forward sink witness.
        backward = collect(
            query.paths(scope, operation["id"], mode="flow", direction="backward", detail="full", max_depth=8)
        )
        forward = collect(query.paths(scope, operation["id"], mode="flow", detail="full", max_depth=8))
        if operation.get("role") == "source":
            backward = [{"nodes": [operation], "steps": []}]
        if operation.get("role") == "sink":
            forward = [{"nodes": [operation], "steps": []}]
        count = 0
        for before in backward:
            for after in forward:
                nodes = list(reversed(before["nodes"])) + after["nodes"][1:]
                # Do not create a cyclic path or splice incompatible browser contexts/captures.
                if len({node["id"] for node in nodes}) != len(nodes):
                    continue
                before_contexts = {
                    step.get("context_capture_id") for step in before["steps"] if step.get("context_capture_id")
                }
                after_contexts = {
                    step.get("context_capture_id") for step in after["steps"] if step.get("context_capture_id")
                }
                if before_contexts and after_contexts and before_contexts != after_contexts:
                    continue
                if sum(w["relation"] == "flow" for w in candidate["witnesses"]) >= 100:
                    candidate["contexts_limited"] = True
                    break
                candidate["witnesses"].append(
                    {
                        "relation": "flow",
                        **compact_witness({"nodes": nodes, "steps": list(reversed(before["steps"])) + after["steps"]}),
                    }
                )
                count += 1
                if count >= 20:
                    break
            if count >= 20:
                candidate["contexts_limited"] = True
                break
    if len(operations) > 10:
        candidate["contexts_limited"] = True
        gaps.add("Operation traversal limited to 10 matches")
    if set(candidate["vulnerability_types"]) & {"authentication", "access_control"}:
        collect(query.paths(scope, url, mode="journey", max_depth=8, detail="full"), "journey")
    flows = [
        w
        for w in candidate["witnesses"]
        if w["relation"] == "flow"
        and w.get("nodes")
        and w["nodes"][0].get("role") == "source"
        and w["nodes"][-1].get("role") == "sink"
    ]
    candidate["source_ids"] = sorted({w["nodes"][0]["id"] for w in flows})
    candidate["sink_ids"] = sorted({w["nodes"][-1]["id"] for w in flows})
    for source_id in candidate["source_ids"][:10]:
        collect(
            query.paths(scope, source_id, mode="relationships", kinds=["RESPONSE_FROM"], max_depth=1, detail="full"),
            "response",
        )
    if flows:
        candidate["connectivity"] = "contextual_flow"
        if any(set(candidate["operation_ids"]) & {node["id"] for node in w["nodes"]} for w in flows):
            candidate["connectivity"] = "anchored_flow"
    else:
        gaps.add("No relevant source-to-sink witness discovered; absence does not establish safety")
    candidate["incomplete_path"] |= any(step["kind"] == "SUMMARIZED_FLOW" for w in flows for step in w["steps"])
    candidate["context_urls"] = sorted(contexts)
    candidate["analysis_gaps"] = sorted(gaps)
    candidate["missing_prerequisites"].append("Validate attacker control and execution against retained evidence")
    candidate["follow_up"] = [
        {
            "tool": "find_application_endpoints",
            "arguments": {"scope": scope, "url": url, "detail": "summary", "method": metadata.get("affected_method")},
        }
    ]
    evidence_ids = sorted(
        {step["evidence_id"] for w in candidate["witnesses"] for step in w.get("steps", []) if step.get("evidence_id")}
    )
    candidate["evidence_ids"] = evidence_ids
    candidate["follow_up"].extend(
        {"tool": "fetch_application_graph_evidence", "arguments": {"evidence_id": key}} for key in evidence_ids[:3]
    )
    candidate["association_keys"] = sorted(
        {f"url:{value}" for value in contexts}
        | {f"node:{value}" for value in candidate["operation_ids"] + candidate["sink_ids"]}
        | {
            f"url:{node['url']}"
            for w in candidate["witnesses"]
            if w["relation"] == "journey"
            for node in w["nodes"]
            if node.get("url")
        }
    )
    candidate["hotspot_keys"] = list(candidate["association_keys"])
    candidate["pairing_keys"] = sorted(
        set(candidate["hotspot_keys"])
        | {f"url:{value}" for value in candidate["affected_urls"]}
        | {
            f"flow:{node['id']}"
            for witness in candidate["witnesses"]
            if witness["relation"] == "flow"
            for node in witness["nodes"]
        }
        | {
            f"state:{node['id']}"
            for witness in candidate["witnesses"]
            if witness["relation"] == "flow"
            for node in witness["nodes"]
            if node.get("kind") in {"storage", "message"}
        }
        | {
            f"url:{node['url']}"
            for witness in candidate["witnesses"]
            if witness["relation"] == "response"
            for node in witness["nodes"]
            if node.get("url")
            and any(step["kind"] == "RESPONSE_FROM" and step["target"] == node["id"] for step in witness["steps"])
        }
    )
    candidate.update(score(candidate))
    return candidate


def correlation_query(store, revision):
    return RevisionQuery(store, revision, QueryBudget())
