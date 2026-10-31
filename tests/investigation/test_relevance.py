"""Priority must reflect direct evidence rather than library fan-out."""
from shyhurricane.investigation.ranking import score


def test_context_does_not_raise_priority():
    candidate = {"anchor": "url", "connectivity": "contextual_flow", "affected_urls": [],
                 "context_urls": ["https://example.com/"] * 100}
    result = score(candidate)
    assert result["score_contributions"]["connectivity"] == 0
    assert result["score_contributions"]["affected_contexts"] == 0
    candidate["connectivity"] = "anchored_flow"
    assert score(candidate)["score_contributions"]["connectivity"] == 30


def test_protection_hypothesis_cap():
    candidate = {"anchor": "operation", "connectivity": "association", "rule_id": "protection_gap",
                 "hypothesis": True, "metadata": {"severity": "critical"},
                 "affected_urls": ["https://example.com/"]}
    assert score(candidate)["priority"] == 20
    assert score(candidate)["score_contributions"]["affected_contexts"] == 0
