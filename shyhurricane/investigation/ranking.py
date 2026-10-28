"""Versioned investigation priority, independent of vulnerability confidence."""

SCORING_VERSION = 1
ANCHORS = {"host": 0, "url": 8, "method": 12, "operation": 20}


def score(candidate):
    metadata = candidate.get("metadata", {})
    contributions = {
        "severity": {"low": 5, "medium": 10, "high": 20, "critical": 25}.get(metadata.get("severity"), 0),
        "anchor": ANCHORS[candidate["anchor"]],
        "connectivity": {"contextual_flow": 15, "anchored_flow": 30}.get(candidate["connectivity"], 0),
        "verification": {"suspected": 4, "confirmed": 10}.get(metadata.get("verification_status"), 0),
        "affected_contexts": min(10, len(candidate.get("context_urls", []))),
        "producer_confidence": {"medium": 2, "high": 5}.get(metadata.get("confidence"), 0),
        "metadata_conflict": -10 if candidate.get("anchor_conflict") else 0,
        "incomplete_path": -10 if candidate.get("incomplete_path") else 0,
    }
    priority = max(0, sum(contributions.values()))
    cap = 40 if candidate.get("hypothesis") else 100
    if candidate["anchor"] == "host":
        cap = min(cap, 20)
    return {
        "priority": min(cap, priority),
        "score_contributions": contributions,
        "score_cap": cap,
        "scoring_version": SCORING_VERSION,
        "anchor_rank": list(ANCHORS).index(candidate["anchor"]),
    }
