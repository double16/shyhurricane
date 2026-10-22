"""Cheap publication estimates; never inspect entity or relationship records."""


def summarize_captures(rows):
    def totals(captures):
        covered = [
            row
            for row in captures
            if row.get("entity_estimate") is not None and row.get("relationship_estimate") is not None
        ]
        return {
            "captures": len(captures),
            "resources": len({row["resource_key"] for row in captures}),
            "covered_captures": len(covered),
            "coverage_complete": len(covered) == len(captures),
            "entity_estimate": sum(row["entity_estimate"] for row in covered) if covered or not captures else None,
            "relationship_estimate": (
                sum(row["relationship_estimate"] for row in covered) if covered or not captures else None
            ),
            "summarized_captures": sum(bool(row.get("summarized")) for row in captures),
            "budget_limited_captures": sum(bool(row.get("budget_limited")) for row in captures),
        }

    latest = {}
    for row in rows:
        key = row["resource_key"]
        latest[key] = max(latest.get(key, float("-inf")), row["observed_at"])
    history = totals(rows)
    current = totals([row for row in rows if row["observed_at"] == latest[row["resource_key"]]])
    return {
        "current": current,
        "retained_history": history,
        "entities": history["entity_estimate"],
        "relationships": history["relationship_estimate"],
        "approximate": True,
        "captures": len(rows),
        "incomplete_captures": sum(bool(row.get("gaps")) for row in rows),
        "last_published_at": max((row.get("published_at", 0) or 0 for row in rows), default=None),
    }
