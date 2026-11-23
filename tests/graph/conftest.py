import json
import subprocess
from pathlib import Path

import pytest

from shyhurricane.graph.model import capture_event


@pytest.fixture
def graph_paths(monkeypatch, tmp_path):
    def path(db, name):
        return tmp_path / name

    monkeypatch.setattr("shyhurricane.persistent_queue.persistent_queue_path", path)
    monkeypatch.setattr("shyhurricane.graph.artifacts.persistent_queue_path", path)
    monkeypatch.setattr("shyhurricane.graph.status.persistent_queue_path", path)
    monkeypatch.setattr("shyhurricane.indexing_wait.persistent_queue_path", path)
    return tmp_path


@pytest.fixture
def event():
    def create(url="https://example.com/page", body="", mime="text/html", **kwargs):
        return capture_event(
            {
                "url": url,
                "method": "GET",
                "timestamp": "2026-01-01T00:00:00Z",
                "request_headers": {},
                "response_headers": {"Content-Type": mime},
                "response_code": 200,
                "response_body": body,
                "request_body": None,
                **kwargs,
            }
        )

    return create


@pytest.fixture
def javascript_runner():
    """Run the shipped AST analyzer without Docker or target network access."""
    analyzer = Path("src/docker/unix_command/graph-analysis/analyze.cjs").resolve()

    def run(source, filename):
        result = subprocess.run(
            ["node", str(analyzer)], input=json.dumps({"source": source, "filename": filename}),
            text=True, capture_output=True, check=True, timeout=15,
        )
        return json.loads(result.stdout)

    return run


@pytest.fixture
def inventory_database():
    """Only a dedicated empty graph, or one explicitly marked by this fixture, may be cleared."""
    import os

    from neo4j import GraphDatabase

    from shyhurricane.graph.database import GraphStore

    uri = os.environ.get("GRAPH_INVENTORY_TEST_URI")
    if not uri:
        pytest.skip("Requires a dedicated fresh inventory test Neo4j")
    driver = GraphDatabase.driver(uri, auth=None, max_transaction_retry_time=2)
    marker = "shyhurricane_inventory_test_database"
    try:
        with driver.session() as session:
            owned = session.run("MATCH (s:GraphState {id:$id}) RETURN s.id AS id", id=marker).single()
            if not owned:
                if session.run("MATCH (n) RETURN n LIMIT 1").single():
                    pytest.fail("Inventory integration tests require an empty dedicated database")
                session.run("CREATE (:GraphState {id:$id})", id=marker).consume()
            while session.run(
                "MATCH ()-[r]->() WITH r LIMIT 500 DELETE r RETURN count(*) AS count"
            ).single()["count"]:
                pass
            while session.run(
                "MATCH (n) WHERE NOT (n:GraphState AND n.id=$id) "
                "WITH n LIMIT 500 DELETE n RETURN count(*) AS count", id=marker,
            ).single()["count"]:
                pass
        store = GraphStore(uri)
        try:
            store.ready()
            yield store
        finally:
            store.close()
    finally:
        driver.close()


@pytest.fixture
def publish_inventory(inventory_database):
    """Run the real publisher synchronously for inventory contract fixtures."""
    from shyhurricane.graph.inventory_pipeline import InventoryPipeline
    from shyhurricane.graph.query import GraphQuery

    pipelines = {}

    def publish(artifacts):
        artifacts.manifest.flush()
        artifacts.connection.commit()
        pipeline = pipelines.setdefault(id(artifacts), InventoryPipeline(artifacts, inventory_database))
        for _ in range(20000):
            if not pipeline.step():
                break
        else:
            pytest.fail("Inventory fixture did not drain")
        return GraphQuery(inventory_database, artifacts=artifacts)

    publish.store = inventory_database
    return publish
