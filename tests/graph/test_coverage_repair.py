"""Fresh inventory coverage preserves capture identity and optional-filter semantics."""

import pytest

from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.extract import extract
from shyhurricane.graph.model import capture_unit_path


@pytest.mark.parametrize("url", ["https://example.com", "https://EXAMPLE.com:443", "https://example.com/"])
def test_root_completion_uses_retained_capture_identity(graph_paths, event, url, publish_inventory):
    artifacts = ArtifactStore("db")
    capture = artifacts.register(event(url=url))
    extract(capture, artifacts)
    rows = artifacts.connection.execute(
        "SELECT source_path,discovery,flow FROM graph_manifest_units WHERE source_path LIKE 'capture:%'"
    ).fetchall()
    assert rows == [(capture_unit_path(capture), "complete", "complete")]
    publish_inventory(artifacts)
    assert artifacts.manifest.coverage(scope="example.com")["discovery"] == "complete"
    artifacts.close()


@pytest.mark.parametrize("blank", [None, "", " \t\n"])
def test_inventory_optional_blank_filters_match_omission(graph_paths, event, blank, publish_inventory):
    from shyhurricane.graph.manifest_query import manifest_query

    artifacts = ArtifactStore("db")
    extract(artifacts.register(event()), artifacts)
    query = publish_inventory(artifacts)
    expected = query.endpoints("example.com")["results"]
    assert expected
    assert query.endpoints("example.com", url=blank, method=blank)["results"] == expected
    assert manifest_query(artifacts, "example.com", kind="resource", url=blank,
                          context_url=blank, method=blank)["results"] == expected
    assert query.endpoints("example.com", url="https://example.com/missing")["results"] == []
    assert query.endpoints("example.com", method="POST")["results"] == []
    artifacts.close()
