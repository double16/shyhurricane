"""UI evidence contributes once and requires an anchored, capture-compatible flow."""

from copy import deepcopy

import pytest

from shyhurricane.investigation.ranking import score


def candidate():
    return {
        "anchor": "operation",
        "connectivity": "anchored_flow",
        "operation_ids": ["sink"],
        "witnesses": [
            {
                "relation": "flow",
                "nodes": [
                    {"id": "input", "kind": "element", "ui_origin": True, "capture_id": "page", "role": "source"},
                    {"id": "sink", "role": "sink"},
                ],
                "steps": [
                    {
                        "kind": "READS_FROM",
                        "source": "input",
                        "target": "sink",
                        "evidence_id": "proof",
                        "context_capture_id": "page",
                    }
                ],
            }
        ],
    }


def test_ui_bonus_once():
    item = candidate()
    item["witnesses"] *= 2
    result = score(item)
    assert result["score_contributions"]["ui_origin"] == 10
    assert result["priority"] == 60
    assert len(result["ui_origins"]) == 1


@pytest.mark.parametrize(
    "change",
    [
        {"hypothesis": True},
        {"association_basis": "contextual"},
        {"operation_ids": []},
        {"shared_key": "node:unrelated"},
    ],
)
def test_ineligible_candidates(change):
    item = candidate() | change
    assert score(item)["score_contributions"]["ui_origin"] == 0


@pytest.mark.parametrize(
    "part,change",
    [
        ("source", {"kind": "operation"}),
        ("source", {"ui_origin": False}),
        ("source", {"capture_id": None}),
        ("sink", {"role": "source"}),
        ("step", {"kind": "SUMMARIZED_FLOW"}),
        ("step", {"evidence_id": None}),
        ("step", {"context_capture_id": "other"}),
    ],
)
def test_invalid_proofs(part, change):
    item = deepcopy(candidate())
    witness = item["witnesses"][0]
    target = witness["steps"][0] if part == "step" else witness["nodes"][part == "sink"]
    target.update(change)
    assert score(item)["ui_origins"] == []


@pytest.mark.parametrize(
    "change",
    [
        {"witnesses": []},
        {"rule_id": "protection_gap"},
        {"witnesses": [{"relation": "consumer", "nodes": [], "steps": []}]},
    ],
)
def test_missing_and_context_only_evidence(change):
    assert score(candidate() | change)["ui_origins"] == []


@pytest.mark.parametrize(
    "change",
    [
        {"source": "other"},
        {"target": "other"},
        {"context_capture_id": None},
    ],
)
def test_disconnected_or_unbound_steps(change):
    item = candidate()
    item["witnesses"][0]["steps"][0].update(change)
    assert score(item)["ui_origins"] == []


def test_score_caps_and_direct_hotspot_proofs():
    item = candidate() | {"shared_key": "node:sink"}
    assert score(item)["score_contributions"]["ui_origin"] == 10
    item["anchor"] = "host"
    assert score(item)["priority"] == 20
    item.update(
        anchor="operation",
        metadata={"severity": "critical", "confidence": "high", "verification_status": "confirmed"},
        affected_urls=list(range(15)),
    )
    assert score(item)["priority"] == 100


def test_library_nodes_do_not_disqualify_ui_flow():
    item = candidate()
    witness = item["witnesses"][0]
    witness["nodes"].insert(1, {"id": "library", "source_path": "vendor.js"})
    witness["steps"] = [
        {"source": left, "target": right, "kind": "FLOWS_TO", "evidence_id": "proof", "context_capture_id": "page"}
        for left, right in [("input", "library"), ("library", "sink")]
    ]
    assert score(item)["score_contributions"]["ui_origin"] == 10
