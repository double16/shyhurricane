"""Focused native reads use indexes rather than scanning unrelated inventory."""

from shyhurricane.graph.artifacts import ArtifactStore


def test_scoped_query_work_is_independent_of_unrelated_inventory(graph_paths, event, publish_inventory):
    artifacts = ArtifactStore("db")
    try:
        capture = artifacts.register(event())
        unit = artifacts.manifest.unit(capture["id"], "fixture", discovery="complete", flow="complete")
        artifacts.manifest.facts(unit, capture["id"], [("field", {
            "id": str(index), "url": "https://example.com/api", "name": str(index),
        }) for index in range(100)])
        publish_inventory(artifacts)

        def measured_page():
            reader = artifacts.manifest.reader
            original = reader.read
            queries = []

            def read(statement, **parameters):
                if "RETURN f.manifest_id" in statement:
                    queries.append((statement, parameters))
                return original(statement, **parameters)

            reader.read = read
            try:
                rows, _ = reader.page("https://example.com/api", kind="field", limit=10)
            finally:
                reader.read = original
            assert len(rows) == 10
            statement, parameters = queries[0]
            with publish_inventory.store.connect().session() as session:
                result = session.run("PROFILE " + statement, **parameters)
                result.data()
                plan = result.consume().profile

            def hits(node):
                assert "AllNodesScan" not in node["operatorType"]
                if node["dbHits"] > 1000:
                    print(node["operatorType"], node["dbHits"], node.get("args", {}).get("Details"))
                return node["dbHits"] + sum(hits(child) for child in node.get("children", []))

            return hits(plan)

        baseline = measured_page()
        other = artifacts.register(event(url="https://target.local/"))
        unit = artifacts.manifest.unit(other["id"], "unrelated", discovery="complete", flow="complete")
        for offset in range(0, 8000, 500):
            artifacts.manifest.facts(unit, other["id"], [("field", {
                "id": str(index), "url": "https://target.local/api", "name": str(index),
            }) for index in range(offset, offset + 500)])
        publish_inventory(artifacts)
        populated = measured_page()
        assert populated <= baseline * 2 + 1000, (baseline, populated)
    finally:
        artifacts.close()
