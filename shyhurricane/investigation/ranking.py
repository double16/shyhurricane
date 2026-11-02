"""Versioned investigation priority, independent of vulnerability confidence."""

SCORING_VERSION = 4
ANCHORS = {"host": 0, "url": 8, "method": 12, "operation": 20}


def score(candidate):
    origins = ui_origins(candidate)
    metadata = candidate.get("metadata", {})
    contributions = {
        "ui_origin": 10 if origins else 0,
        "severity": {"low": 5, "medium": 10, "high": 20, "critical": 25}.get(metadata.get("severity"), 0),
        "anchor": ANCHORS[candidate["anchor"]],
        "connectivity": {"anchored_flow": 30}.get(candidate["connectivity"], 0),
        "verification": {"suspected": 4, "confirmed": 10}.get(metadata.get("verification_status"), 0),
        "affected_contexts": min(10, len(candidate.get("affected_urls", []))),
        "producer_confidence": {"medium": 2, "high": 5}.get(metadata.get("confidence"), 0),
        "metadata_conflict": -10 if candidate.get("anchor_conflict") else 0,
        "incomplete_path": -10 if candidate.get("incomplete_path") else 0,
    }
    contextual = candidate.get("association_basis") == "contextual"
    if contextual or candidate.get("rule_id") == "protection_gap":
        contributions["affected_contexts"] = 0
    priority = max(0, sum(contributions.values()))
    cap = 40 if candidate.get("hypothesis") else 100
    if contextual or candidate.get("rule_id") == "protection_gap":
        cap = min(cap, 20)
    if candidate["anchor"] == "host":
        cap = min(cap, 20)
    return {
        "ui_origins": origins,
        "priority": min(cap, priority),
        "score_contributions": contributions,
        "score_cap": cap,
        "scoring_version": SCORING_VERSION,
        "anchor_rank": list(ANCHORS).index(candidate["anchor"]),
    }


def ui_origins(candidate):
    """Identify retained UI proofs on complete operation-bound source-to-sink flows."""
    if (
        candidate.get("hypothesis")
        or candidate.get("association_basis") == "contextual"
        or candidate.get("rule_id") == "protection_gap"
    ):
        return []
    operations = set(candidate.get("operation_ids", []))
    shared = candidate.get("shared_key", "")
    origins = {}
    for witness in candidate.get("witnesses", []):
        nodes, steps = witness.get("nodes", []), witness.get("steps", [])
        if (
            witness.get("relation") != "flow"
            or not nodes
            or not steps
            or nodes[-1].get("role") != "sink"
            or nodes[0].get("role") != "source"
            or len(steps) != len(nodes) - 1
            or any(
                step.get("source") != left["id"] or step.get("target") != right["id"]
                for left, right, step in zip(nodes, nodes[1:], steps)
            )
            or not operations.intersection(node["id"] for node in nodes)
            or any(step.get("kind") == "SUMMARIZED_FLOW" or not step.get("evidence_id") for step in steps)
        ):
            continue
        if shared and not any(shared in {f"node:{node['id']}", f"url:{node.get('url')}"} for node in nodes):
            continue
        source = nodes[0]
        if source.get("kind") != "element" or not source.get("ui_origin") or not source.get("capture_id"):
            continue
        contexts = {step["context_capture_id"] for step in steps if step.get("context_capture_id")}
        if contexts != {source["capture_id"]}:
            continue
        origins[source["id"]] = {
            "element_id": source["id"],
            "capture_id": source["capture_id"],
            "location": source.get("location"),
            "evidence_ids": sorted({step["evidence_id"] for step in steps}),
            "witness_node_ids": [node["id"] for node in nodes],
        }
    return [origins[key] for key in sorted(origins)]
