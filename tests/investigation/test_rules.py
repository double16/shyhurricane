"""Every deterministic chain has an explicit graph prerequisite."""

from shyhurricane.investigation.engine import correlate
from shyhurricane.investigation.ranking import score
from shyhurricane.investigation.rules import derive
from tests.investigation.test_engine import PAGE, URL, Query, flow, job, node


def candidate(finding_id="a", metadata=None):
    value = correlate(job(metadata, finding_id=finding_id), Query(), 1)
    value["operation_ids"] = [finding_id]
    return value


def test_score_is_explainable_capped_and_not_multiplied_by_finding_count():
    value = candidate(metadata={"severity": "critical", "confidence": "high", "verification_status": "confirmed"})
    value.update(anchor="operation", connectivity="anchored_flow", affected_urls=[str(i) for i in range(15)])
    assert score(value)["priority"] == 100
    value["finding_ids"] *= 10
    assert score(value)["priority"] == 100
    value["hypothesis"] = True
    assert score(value)["priority"] == 40
    value["anchor"] = "host"
    assert score(value)["priority"] == 20
    value.update(metadata={}, connectivity="association", context_urls=[], anchor_conflict=True, incomplete_path=True)
    assert score(value)["priority"] == 0


def test_shared_flow_requires_both_operation_anchors_and_keeps_graph_proof():
    left, right = candidate(), candidate("b")
    left["witnesses"] = [{"relation": "flow", **flow([node("a", "source"), node("b", "sink")])}]
    result = derive(left, [left, right])
    chain = next(item for item in result if item.get("rule_id") == "shared_flow")
    assert chain["finding_ids"] == ["a", "b"]
    assert not chain["hypothesis"]
    assert chain["witnesses"][0]["steps"][0]["evidence_id"] == "proof"
    right["operation_ids"] = []
    assert all(item.get("rule_id") != "shared_flow" for item in derive(left, [right]))


def test_shared_storage_needs_write_and_read_on_same_identity_and_both_findings():
    left, right = candidate(), candidate("b")
    state = node("state", kind="storage")
    left["witnesses"] = [{"relation": "flow", **flow([node("a"), state], "WRITES_TO")}]
    right["witnesses"] = [{"relation": "flow", **flow([state, node("b")], "READS_FROM")}]
    assert any(item.get("rule_id") == "shared_state" for item in derive(left, [right]))
    right["witnesses"][0]["steps"][0]["source"] = "other-state"
    assert not any(item.get("rule_id") == "shared_state" for item in derive(left, [right]))
    left["witnesses"] = []
    assert not any(item.get("rule_id") == "shared_state" for item in derive(left, [right]))


def test_response_rule_requires_explicit_response_association_not_request_body():
    left, right = candidate(), candidate("b")
    response = {"relation": "response", **flow([node("input", "source"), node("endpoint", url=URL)], "RESPONSE_FROM")}
    left["witnesses"].append(response)
    assert any(item.get("rule_id") == "response_to_sink" for item in derive(left, [right]))
    response["steps"][0]["kind"] = "REQUESTS"
    assert not any(item.get("rule_id") == "response_to_sink" for item in derive(left, [right]))


def test_protection_and_journey_links_remain_hypotheses():
    left = candidate(metadata={"vulnerability_types": ["configuration"]})
    right = candidate("b", {"vulnerability_types": ["xss"]})
    result = derive(left, [right])
    chain = next(item for item in result if item.get("rule_id") == "protection_gap")
    assert chain["hypothesis"] and chain["priority"] <= 40
    assert any("co-location" in text for text in chain["missing_prerequisites"])
    right["context_urls"] = ["https://example.com/elsewhere"]
    assert not any(item.get("rule_id") == "protection_gap" for item in derive(left, [right]))
    left = candidate(metadata={"vulnerability_types": ["authentication"]})
    right = candidate("b", {"vulnerability_types": ["access_control"]})
    right["affected_urls"] = [PAGE]
    left["witnesses"] = [
        {"relation": "journey", **flow([node("start", url=URL), node("end", url=PAGE)], "NAVIGATES_TO")}
    ]
    chain = next(item for item in derive(left, [right]) if item.get("rule_id") == "navigation")
    assert chain["hypothesis"]
    assert any("session continuity" in text for text in chain["missing_prerequisites"])
    left["witnesses"] = []
    assert not any(item.get("rule_id") == "navigation" for item in derive(left, [right]))


def test_hotspots_group_unique_members_and_deduplicate():
    left, second, third = candidate(), candidate("b"), candidate("c")
    result = derive(left, [second, third, third])
    hotspots = [item for item in result if item["kind"] == "hotspot"]
    assert hotspots
    assert all(item["contributing_finding_count"] == 3 for item in hotspots)
    assert all(item["finding_ids"] == ["a", "b", "c"] for item in hotspots)
    assert len({item["id"] for item in hotspots}) == len(hotspots)


def test_exclusions_versions_and_conflicts_do_not_create_chains():
    left, right = candidate(), candidate("b")
    left["excluded"] = True
    assert derive(left, [right]) == []
    left["excluded"] = False
    right["excluded"] = True
    assert derive(left, [right]) == []
    right["excluded"] = False
    right["graph_revision"] = 2
    assert derive(left, [right]) == []
    right["graph_revision"] = 1
    left["anchor_conflict"] = True
    assert all(item["kind"] == "hotspot" for item in derive(left, [right]))
    left["association_keys"] = ["unrelated:value"]
    assert derive(left, []) == []


def test_hotspot_refresh_uses_new_finding_revision_not_its_previous_result():
    left, previous, other = candidate(), candidate(), candidate("b")
    left["finding_revisions"] = {"a": "enriched"}
    left["metadata"] = {"severity": "critical"}
    hotspots = [item for item in derive(left, [previous, other]) if item["kind"] == "hotspot"]
    assert hotspots
    assert all(item["finding_revisions"]["a"] == "enriched" for item in hotspots)
    assert all(item["score_contributions"]["severity"] == 25 for item in hotspots)


def test_hotspot_basis_scoring_and_deduplication_are_order_independent():
    from shyhurricane.investigation.rules import aggregate_hotspot
    left, right = candidate(), candidate("b")
    left["metadata"] = right["metadata"] = {"severity": "critical"}
    direct = aggregate_hotspot("url:" + left["affected_urls"][0], [left, right])
    assert direct["association_basis"] == "direct"
    assert direct["direct_contributor_count"] == 2
    contextual = aggregate_hotspot("url:https://example.com/other", [left, right])
    assert contextual["association_basis"] == "contextual"
    assert contextual["priority"] <= 20
    assert contextual["score_contributions"]["affected_contexts"] == 0
    assert contextual == aggregate_hotspot("url:https://example.com/other", [right, left])
    assert len(contextual["follow_up"]) == len(left["follow_up"])
    assert len(contextual["witnesses"]) <= 10


def test_hotspot_selects_key_witnesses_and_reports_distinct_omissions():
    from shyhurricane.investigation.rules import aggregate_hotspot
    left, right = candidate(), candidate("b")
    witnesses = [
        {"relation": "consumer", "nodes": [{"id": str(index), "url": "https://example.com/other"}], "steps": []}
        for index in range(15)
    ]
    left["witnesses"] = witnesses
    right["witnesses"] = [*witnesses, {"relation": "consumer", "nodes": [{"id": "match", "url": URL}], "steps": []}]
    value = aggregate_hotspot("url:" + URL, [left, right])
    assert value["witnesses"][0]["nodes"][0]["id"] == "match"
    assert len(value["witnesses"]) == 10
    assert value["omitted_witness_count"] == 6
    assert value == aggregate_hotspot("url:" + URL, [right, left])
    left["operation_ids"] = right["operation_ids"] = ["shared-operation"]
    assert aggregate_hotspot("node:shared-operation", [left, right])["association_basis"] == "direct"


def test_protection_gap_retains_explicit_unproven_association():
    left = candidate(metadata={"vulnerability_types": ["configuration"], "severity": "high"})
    right = candidate("b", {"vulnerability_types": ["injection"], "severity": "critical"})
    chain = next(item for item in derive(left, [right]) if item.get("rule_id") == "protection_gap")
    assert chain["hypothesis"]
    assert chain["applicability_status"] == "unproven"
    assert chain["association_reason"]["configuration_finding_ids"] == ["a"]
    assert chain["association_reason"]["related_finding_ids"] == ["b"]
    assert chain["priority"] <= 20
    assert chain["score_contributions"]["affected_contexts"] == 0
