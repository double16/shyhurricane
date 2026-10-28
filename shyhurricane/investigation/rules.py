"""Explicit chain prerequisites; navigation and protection gaps remain hypotheses."""

from shyhurricane.graph.model import identity
from shyhurricane.investigation.ranking import score

RULES = {
    "shared_flow": {"hypothesis": False, "requires": "both anchored operations on one flow witness"},
    "response_to_sink": {"hypothesis": False, "requires": "explicit RESPONSE_FROM plus a response-source flow"},
    "shared_state": {"hypothesis": False, "requires": "a shared state node with explicit write and read witnesses"},
    "protection_gap": {"hypothesis": True, "requires": "configuration category and compatible sink on same page"},
    "navigation": {"hypothesis": True, "requires": "authentication/access-control categories and journey witness"},
}


def pair_candidate(left, right, rule, witnesses, *, hotspot=False):
    members = sorted(set(left["finding_ids"] + right["finding_ids"]))
    metadata = {}
    for field, order in (
        ("severity", ["unknown", "informational", "low", "medium", "high", "critical"]),
        ("confidence", ["unknown", "low", "medium", "high"]),
        ("verification_status", ["unverified", "suspected", "confirmed"]),
    ):
        values = [item["metadata"].get(field) for item in (left, right)]
        metadata[field] = max((value for value in values if value in order), key=order.index, default="unknown")
    anchor = min((left["anchor"], right["anchor"]), key=["host", "url", "method", "operation"].index)
    candidate = {
        "id": identity("hotspot" if hotspot else rule, members),
        "kind": "hotspot" if hotspot else "chain",
        "rule_id": rule,
        "finding_ids": members,
        "finding_revisions": {**left["finding_revisions"], **right["finding_revisions"]},
        "result_generations": {**left.get("result_generations", {}), **right.get("result_generations", {})},
        "graph_revision": min(left["graph_revision"], right["graph_revision"]),
        "policy_version": left["policy_version"],
        "materialized_at": max(left["materialized_at"], right["materialized_at"]),
        "affected_urls": sorted(set(left["affected_urls"] + right["affected_urls"])),
        "context_urls": sorted(set(left["context_urls"] + right["context_urls"])),
        "vulnerability_types": sorted(set(left["vulnerability_types"] + right["vulnerability_types"])),
        "anchor": anchor,
        "metadata": metadata,
        "hypothesis": False if hotspot else RULES[rule]["hypothesis"],
        "connectivity": (
            "anchored_flow" if rule in {"shared_flow", "shared_state", "response_to_sink"} else "association"
        ),
        "witnesses": witnesses[:10],
        "analysis_gaps": sorted(set(left["analysis_gaps"] + right["analysis_gaps"])),
        "missing_prerequisites": ["Validate attacker control, execution, and exploit composition"],
        "anchor_conflict": left["anchor_conflict"] or right["anchor_conflict"],
        "incomplete_path": left["incomplete_path"] or right["incomplete_path"],
        "follow_up": left["follow_up"] + right["follow_up"],
        "contexts_limited": left["contexts_limited"] or right["contexts_limited"],
    }
    candidate.update(score(candidate))
    return candidate


def state_witnesses(candidate):
    reads, writes = {}, {}
    operations = set(candidate.get("operation_ids", []))
    for witness in candidate["witnesses"]:
        if witness.get("relation") != "flow" or not operations & {node["id"] for node in witness["nodes"]}:
            continue
        state = {node["id"] for node in witness["nodes"] if node.get("kind") in {"storage", "message"}}
        for step in witness["steps"]:
            if step["kind"] == "WRITES_TO" and step["target"] in state:
                writes.setdefault(step["target"], witness)
            if step["kind"] == "READS_FROM" and step["source"] in state:
                reads.setdefault(step["source"], witness)
    return reads, writes


def derive(left, neighbors, *, include_hotspots=True):
    """Bounded pairs; matching names/hosts alone never establish a chain."""
    results = {}
    if left.get("excluded"):
        return []
    left_reads, left_writes = state_witnesses(left)
    for right in neighbors:
        if right["id"] == left["id"] or right.get("excluded") or right["graph_revision"] != left["graph_revision"]:
            continue
        if left["anchor_conflict"] or right["anchor_conflict"]:
            continue
        flows = [w for item in (left, right) for w in item["witnesses"] if w.get("relation") == "flow"]
        shared_flows = [
            w
            for w in flows
            if set(left.get("operation_ids", [])) & {node["id"] for node in w["nodes"]}
            and set(right.get("operation_ids", [])) & {node["id"] for node in w["nodes"]}
        ]
        if shared_flows:
            candidate = pair_candidate(left, right, "shared_flow", shared_flows)
            results[candidate["id"]] = candidate
        # Same storage identity alone is insufficient: require actual write/read witnesses.
        right_reads, right_writes = state_witnesses(right)
        for writes, reads in ((left_writes, right_reads), (right_writes, left_reads)):
            shared = sorted(writes.keys() & reads.keys())
            if shared:
                state = shared[0]
                candidate = pair_candidate(left, right, "shared_state", [writes[state], reads[state]])
                results[candidate["id"]] = candidate
                break
        for owner, other in ((left, right), (right, left)):
            responses = [w for w in owner["witnesses"] if w.get("relation") == "response"]
            for response in responses:
                sources = {
                    step["source"]
                    for step in response["steps"]
                    if step["kind"] == "RESPONSE_FROM"
                    and any(
                        node.get("id") == step["target"] and node.get("url") in other["affected_urls"]
                        for node in response["nodes"]
                    )
                }
                matched = [
                    w
                    for w in flows
                    if w["nodes"]
                    and w["nodes"][0]["id"] in sources
                    and w["nodes"][0].get("role") == "source"
                    and w["nodes"][-1].get("role") == "sink"
                ]
                if matched:
                    candidate = pair_candidate(left, right, "response_to_sink", [response, *matched])
                    results[candidate["id"]] = candidate
        contexts = set(left["context_urls"]) & set(right["context_urls"])
        for owner, other in ((left, right), (right, left)):
            if (
                contexts
                and "configuration" in owner["vulnerability_types"]
                and set(other["vulnerability_types"]) & {"xss", "injection", "exposure"}
                and other.get("sink_ids")
            ):
                candidate = pair_candidate(left, right, "protection_gap", other["witnesses"])
                candidate["missing_prerequisites"].append(
                    "Establish protection applicability and bypass; co-location is insufficient"
                )
                results[candidate["id"]] = candidate
        if set(left["vulnerability_types"]) & {"authentication", "access_control"} and set(
            right["vulnerability_types"]
        ) & {"authentication", "access_control"}:
            journeys = [
                w
                for item in (left, right)
                for w in item["witnesses"]
                if w.get("relation") == "journey"
                and any(node.get("url") in left["affected_urls"] for node in w["nodes"])
                and any(node.get("url") in right["affected_urls"] for node in w["nodes"])
            ]
            if journeys:
                candidate = pair_candidate(left, right, "navigation", journeys)
                candidate["missing_prerequisites"].append("Establish session continuity and privilege transitions")
                results[candidate["id"]] = candidate
    if include_hotspots:
        for key in left.get("hotspot_keys", left.get("association_keys", [])):
            members = [
                item
                for item in [*(item for item in neighbors if item["id"] != left["id"]), left]
                if not item.get("excluded")
                and item["graph_revision"] == left["graph_revision"]
                and key in item.get("hotspot_keys", item.get("association_keys", []))
            ]
            if candidate := aggregate_hotspot(key, members):
                results[candidate["id"]] = candidate
    return sorted(results.values(), key=lambda item: item["id"])


def aggregate_hotspot(key, members, *, limited=False):
    """Aggregate one indexed group independently of whichever member changed."""
    if not key.startswith(("url:", "node:")):
        return None
    members = sorted({item["id"]: item for item in members}.values(), key=lambda item: item["id"])
    if len(members) < 2:
        return None
    candidate = members[0]
    for member in members[1:]:
        candidate = pair_candidate(
            candidate, member, "shared_hotspot", candidate["witnesses"] + member["witnesses"], hotspot=True
        )
    candidate["id"] = identity("hotspot", key)
    candidate["shared_key"] = key
    candidate["contributing_finding_count"] = len(candidate["finding_ids"])
    if limited:
        candidate["contexts_limited"] = True
        candidate["analysis_gaps"].append("Hotspot membership limited to 100 contributing findings")
    return candidate
