"""Generation visibility shared by publication linking and graph queries."""


def visible_node(alias: str, capture: str | None = None) -> str:
    """Only internal aliases are accepted; callers never interpolate user input."""
    condition = (
        f"(({alias}._publication_id IS NOT NULL AND EXISTS {{ "
        f"MATCH (owner:GraphCapture {{id:{alias}._owner_capture_id}}) "
        f"WHERE owner.complete=true AND owner.active_publication_id={alias}._publication_id }}) OR "
        f"({alias}._publication_id IS NULL AND ({alias}.capture_id IS NULL OR EXISTS {{ "
        f"MATCH (owner:GraphCapture {{id:{alias}.capture_id}}) "
        "WHERE owner.complete=true AND owner.active_publication_id IS NULL })))"
    )
    if capture:
        return (
            f"(CASE WHEN {alias}._publication_id IS NOT NULL AND {alias}._owner_capture_id={capture}.id "
            f"THEN {alias}._publication_id=selected_generation "
            f"WHEN {alias}._publication_id IS NULL AND {alias}.capture_id={capture}.id "
            f"THEN selected_generation IS NULL ELSE {condition} END)"
        )
    return condition


def visible_relationship(alias: str, capture: str | None = None) -> str:
    condition = (
        f"(({alias}._publication_id IS NOT NULL AND EXISTS {{ "
        f"MATCH (publisher:GraphCapture {{id:{alias}._build_capture_id}}) "
        f"WHERE publisher.active_publication_id={alias}._publication_id }}) OR "
        f"({alias}._publication_id IS NULL AND EXISTS {{ "
        f"MATCH (publisher:GraphCapture {{id:{alias}.capture_id}}) "
        "WHERE publisher.active_publication_id IS NULL AND publisher.complete=true }))"
    )
    if capture:
        return (
            f"(CASE WHEN {alias}._publication_id IS NULL THEN selected_generation IS NULL "
            f"WHEN {alias}._build_capture_id={capture}.id THEN {alias}._publication_id=selected_generation "
            f"ELSE {condition} END)"
        )
    return condition


def public_properties(record: dict) -> dict:
    result = {key: value for key, value in record.items() if not key.startswith("_") and key != "context_owner_id"}
    result["id"] = record.get("_logical_id", record["id"])
    return result
