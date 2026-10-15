"""Unit tests for relationship generation visibility predicates."""

import pytest

from shyhurricane.graph.visibility import visible_relationship


@pytest.mark.parametrize("alias", ["r", "edge"])
@pytest.mark.parametrize("capture", [None, ""])
def test_relationship_without_capture_uses_active_publications(alias, capture):
    condition = visible_relationship(alias, capture)

    assert condition == (
        f"(({alias}._publication_id IS NOT NULL AND EXISTS {{ "
        f"MATCH (publisher:GraphCapture {{id:{alias}._build_capture_id}}) "
        f"WHERE publisher.active_publication_id={alias}._publication_id }}) OR "
        f"({alias}._publication_id IS NULL AND EXISTS {{ "
        f"MATCH (publisher:GraphCapture {{id:{alias}.capture_id}}) "
        "WHERE publisher.active_publication_id IS NULL AND publisher.complete=true }))"
    )
    assert "selected_generation" not in condition
    assert visible_relationship(alias) == condition


def test_relationship_with_capture_selects_generation_and_falls_back_to_active_publications():
    condition = visible_relationship("edge", "capture")

    assert condition == (
        "(CASE WHEN edge._publication_id IS NULL THEN selected_generation IS NULL "
        "WHEN edge._build_capture_id=capture.id THEN edge._publication_id=selected_generation "
        f"ELSE {visible_relationship('edge')} END)"
    )
