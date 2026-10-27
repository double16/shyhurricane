"""Generation visibility shared by publication linking and graph queries."""


def publication_at(alias: str, revision: str = "$revision") -> str:
    """Select a published interval; pre-revision installations form revision zero."""
    return (
        f"({alias}.published_at IS NOT NULL AND coalesce({alias}.published_revision,0)<={revision} "
        f"AND ({alias}.retired_revision>{revision} OR ({alias}.retired_revision IS NULL "
        f"AND NOT {alias}.state IN ['retired','abandoned','staging'])))"
    )


def legacy_at(capture: str, revision: str = "$revision") -> str:
    return (
        f"EXISTS {{ MATCH (legacy_owner:GraphCapture {{id:{capture}}}) WHERE legacy_owner.complete=true "
        "AND (legacy_owner.active_publication_id IS NULL OR EXISTS { "
        "MATCH (archive:GraphPublication {capture_id:legacy_owner.id}) "
        f"WHERE archive.digest IS NULL AND {publication_at('archive', revision)} }}) }}"
    )


def visible_node(alias: str, capture: str | None = None, *, revision: str | None = None) -> str:
    """Only internal aliases are accepted; callers never interpolate user input."""
    if revision is not None:
        return (
            f"(({alias}._publication_id IS NOT NULL AND EXISTS {{ "
            f"MATCH (owner:GraphPublication {{id:{alias}._publication_id}}) "
            f"WHERE ({publication_at('owner', revision)} OR EXISTS {{ "
            "MATCH (dependent:GraphPublication)-[:DEPENDS_ON]->(owner) "
            f"WHERE {publication_at('dependent', revision)} }}) }}) OR "
            f"({alias}._publication_id IS NULL AND ({alias}.capture_id IS NULL OR "
            f"{legacy_at(f'{alias}.capture_id', revision)})))"
        )
    condition = (
        f"(({alias}._publication_id IS NOT NULL AND EXISTS {{ "
        f"MATCH (owner:GraphCapture {{id:{alias}._owner_capture_id}}) "
        f"WHERE owner.complete=true AND (owner.active_publication_id={alias}._publication_id "
        f"OR owner.active_link_publication_id={alias}._publication_id OR EXISTS {{ "
        f"MATCH (dependent:GraphPublication)-[:DEPENDS_ON]->"
        f"(dependency:GraphPublication {{id:{alias}._publication_id}}) "
        "WHERE dependent.state='published' } OR EXISTS { "
        f"MATCH (unit:GraphAnalysisUnit {{id:{alias}._unit_id}}) "
        f"WHERE unit.active_publication_id={alias}._publication_id }}) }}) OR "
        f"({alias}._publication_id IS NULL AND ({alias}.capture_id IS NULL OR EXISTS {{ "
        f"MATCH (owner:GraphCapture {{id:{alias}.capture_id}}) "
        "WHERE owner.complete=true AND owner.active_publication_id IS NULL })))"
    )
    if capture:
        return (
            f"(CASE WHEN {alias}._link_publication=true OR {alias}._unit_id IS NOT NULL THEN {condition} "
            f"WHEN {alias}._publication_id IS NOT NULL AND {alias}._owner_capture_id={capture}.id "
            f"THEN {alias}._publication_id=selected_generation "
            f"WHEN {alias}._publication_id IS NULL AND {alias}.capture_id={capture}.id "
            f"THEN selected_generation IS NULL ELSE {condition} END)"
        )
    return condition


def visible_relationship(alias: str, capture: str | None = None, *, revision: str | None = None) -> str:
    if revision is not None:
        return (
            f"(({alias}._publication_id IS NOT NULL AND EXISTS {{ "
            f"MATCH (publisher:GraphPublication {{id:{alias}._publication_id}}) "
            f"WHERE {publication_at('publisher', revision)} }}) OR "
            f"({alias}._publication_id IS NULL AND {legacy_at(f'{alias}.capture_id', revision)}))"
        )
    condition = (
        f"(({alias}._publication_id IS NOT NULL AND EXISTS {{ "
        f"MATCH (publisher:GraphCapture {{id:{alias}._build_capture_id}}) "
        f"WHERE (publisher.active_publication_id={alias}._publication_id "
        f"OR publisher.active_link_publication_id={alias}._publication_id OR EXISTS {{ "
        f"MATCH (unit:GraphAnalysisUnit {{id:{alias}._unit_id}}) "
        f"WHERE unit.active_publication_id={alias}._publication_id }}) }}) OR "
        f"({alias}._publication_id IS NULL AND EXISTS {{ "
        f"MATCH (publisher:GraphCapture {{id:{alias}.capture_id}}) "
        "WHERE publisher.active_publication_id IS NULL AND publisher.complete=true }))"
    )
    if capture:
        return (
            f"(CASE WHEN {alias}._link_publication=true OR {alias}._unit_id IS NOT NULL THEN {condition} "
            f"WHEN {alias}._publication_id IS NULL THEN selected_generation IS NULL "
            f"WHEN {alias}._build_capture_id={capture}.id THEN {alias}._publication_id=selected_generation "
            f"ELSE {condition} END)"
        )
    return condition


def public_properties(record: dict) -> dict:
    result = {key: value for key, value in record.items() if not key.startswith("_") and key != "context_owner_id"}
    result["id"] = record.get("_logical_id", record["id"])
    return result
