"""End-to-end derived work, aggregation, and optimistic dependency guards."""

from contextlib import closing
from unittest.mock import Mock

from shyhurricane.graph.model import identity
from shyhurricane.investigation import worker
from shyhurricane.investigation.engine import correlate
from shyhurricane.investigation.rules import aggregate_hotspot, derive
from shyhurricane.investigation.storage import CorrelationStore
from tests.investigation.test_engine import Query, location, node
from tests.investigation.test_storage import publish


def drain(store, revision=1):
    store.set_setting("graph_revision", revision)
    for _ in range(200):
        if not worker.materialize_one(store, Mock(), Mock(), revision):
            return
    raise AssertionError("Derived work did not settle")


def test_hotspots_survive_member_exclusion_without_reanalyzing_survivors(monkeypatch):
    monkeypatch.setattr(worker, "correlation_query", lambda *args: Query())
    with closing(CorrelationStore("test")) as store:
        for key in ("a", "b", "c"):
            store.submit(key, "https://example.com/app.js", {})
        drain(store)
        before = [row for row in store.read("example.com")["results"] if row["kind"] == "hotspot"]
        assert before and all(row["finding_ids"] == ["a", "b", "c"] for row in before)
        generations = {key: store.load_result(key)["result_generations"] for key in ("a", "b")}
        store.submit("c", "https://example.com/app.js", {"verification_status": "false_positive"})
        assert any(row["stale"] for row in store.read("example.com")["results"] if row["kind"] == "hotspot")
        drain(store)
        after = [row for row in store.read("example.com")["results"] if row["kind"] == "hotspot"]
        assert after and all(row["finding_ids"] == ["a", "b"] for row in after)
        assert all(store.load_result(key)["result_generations"] == generations[key] for key in generations)
        store.submit("b", "https://example.com/app.js", {"verification_status": "false_positive"})
        drain(store)
        assert not any(row["kind"] == "hotspot" for row in store.read("example.com")["results"])
        assert all(not status["pending"] for status in store.work_status().values())


def test_hotspot_generation_rejects_updates_during_aggregation():
    with closing(CorrelationStore("test")) as store:
        publish(store, "a")
        publish(store, "b")
        job = store._select_job(("hotspot",))
        members, _, _ = store.hotspot_members(job["id"], 1)
        candidate = aggregate_hotspot(job["id"], members)
        with store.connection:
            store.enqueue("hotspot", job["id"])
        assert not store.publish_derived(job, [candidate])
        assert (
            store.connection.execute(
                "SELECT generation FROM jobs WHERE kind='hotspot' AND key=?", (job["id"],)
            ).fetchone()[0]
            > job["generation"]
        )


def test_pending_members_preserve_previous_aggregate_and_restart_recovers(monkeypatch):
    monkeypatch.setattr(worker, "correlation_query", lambda *args: Query())
    with closing(CorrelationStore("test")) as store:
        publish(store, "a")
        publish(store, "b")
        drain(store)
        store.submit("b", "https://example.com/app.js", {"severity": "high"})
        job = store._select_job(("hotspot",))
        members, limited, waiting = store.hotspot_members(job["id"], 1)
        assert waiting and not limited
        assert not store.publish_derived(job, [], waiting=waiting)
        assert store.connection.execute(
            "SELECT 1 FROM targets WHERE id=?", (identity("hotspot", job["id"]),)
        ).fetchone()
    with closing(CorrelationStore("test")) as store:
        drain(store)
        assert all(not row["stale"] for row in store.read("example.com")["results"])


def test_derived_publication_rejects_changed_dependencies_and_stale_failure():
    with closing(CorrelationStore("test")) as store:
        _, left = publish(store, "a", metadata={"vulnerability_types": ["configuration"]})
        _, right = publish(store, "b", metadata={"vulnerability_types": ["xss"]})
        job = store._select_job(("derive",))
        chains = derive(left, [right], include_hotspots=False)
        assert chains
        store.submit("b", "https://example.com/app.js", {"severity": "high"}, source_revision=2)
        assert not store.publish_derived(job, chains, dependency=left)
        assert store._select_job(("derive",)) == job
        assert not store.load_result("b")
        assert not store.dependencies_current({**left, "finding_revisions": {"missing": "revision"}})
        assert not store.publish_derived(job, [], dependency={**left, "result_generations": {"a": -1}})
        with store.connection:
            store.enqueue("derive", "a")
        store.failed(job, ValueError(), transient=False)
        assert (
            store.connection.execute(
                "SELECT generation FROM jobs WHERE kind='derive' AND key=?", (job["id"],)
            ).fetchone()[0]
            > job["generation"]
        )


class StateQuery(Query):
    def __init__(self, url, key, write):
        self.url, self.key, self.write = url, key, write
        super().__init__(
            [node(key, url=url, source_path=url)], resources=[{"id": key + "-resource", "url": url, "method": "GET"}]
        )

    def paths(self, scope, start, **kwargs):
        if kwargs.get("mode") != "flow" or start != self.key + "-resource":
            return self.wrap([])
        src = node(self.key + "-source", "source", url=self.url)
        op = self.operations[0]
        sink = node(self.key + "-sink", "sink", url=self.url)
        state = node("shared-state", kind="storage", url=self.url)
        nodes = [src, op, state, sink] if self.write else [src, state, op, sink]
        steps = [{"source": a["id"], "target": b["id"], "kind": "FLOWS_TO"} for a, b in zip(nodes, nodes[1:])]
        steps[1]["kind"] = "WRITES_TO" if self.write else "READS_FROM"
        return self.wrap([{"nodes": nodes, "steps": steps}])


def test_cross_url_state_chain_uses_indexed_pairing_keys(monkeypatch):
    with closing(CorrelationStore("test")) as store:
        for key, write in (("a", True), ("b", False)):
            url = f"https://example.com/{key}.js"
            store.submit(key, url, location())
            task = store.work(1)
            result = correlate(task, StateQuery(url, key, write), 1)
            assert "state:shared-state" in result["pairing_keys"]
            assert "state:shared-state" not in result["hotspot_keys"]
            store.publish(task, result, 1)
        # Derived jobs must not call the graph analyzer.
        monkeypatch.setattr(worker, "correlate", Mock(side_effect=AssertionError("Unexpected graph analysis")))
        drain(store)
        chains = [row for row in store.read("example.com")["results"] if row["kind"] == "chain"]
        assert any(row["rule_id"] == "shared_state" and row["finding_ids"] == ["a", "b"] for row in chains)
        assert not any(row.get("shared_key") == "state:shared-state" for row in store.read("example.com")["results"])


def test_aggregation_limits_and_failed_derived_jobs_can_be_retried(monkeypatch):
    monkeypatch.setattr(worker, "correlation_query", lambda *args: Query())
    with closing(CorrelationStore("test")) as store:
        for key in range(102):
            publish(store, f"{key:03}")
        job = store._select_job(("hotspot",))
        members, limited, waiting = store.hotspot_members(job["id"], 1)
        assert limited and not waiting and len(members) == 100
        candidate = aggregate_hotspot(job["id"], members, limited=limited)
        assert candidate["contributing_finding_count"] == 100
        assert any("100 contributing" in gap for gap in candidate["analysis_gaps"])
        store.failed(job, ValueError(), transient=False)
        assert store.work_status()["hotspot"]["failed"] == 1
        assert store.retry() == 1
        assert store.work_status()["hotspot"]["pending"]


def test_unknown_or_pending_result_defers_derivation_without_removing_previous_data():
    with closing(CorrelationStore("test")) as store:
        assert store.load_result("missing") is None
        publish(store)
        store.submit("a", "https://example.com/app.js", {"severity": "high"})
        derive_job = store._select_job(("derive",))
        with store.connection:
            store.connection.execute("UPDATE jobs SET due=? WHERE kind='correlate'", (10**12,))
        assert worker.materialize_one(store, Mock(), Mock(), 1)
        assert store._select_job(("derive",)) is None
        assert derive_job["kind"] == "derive"


def test_changed_hotspot_key_rebuilds_old_group(monkeypatch):
    monkeypatch.setattr(worker, "correlation_query", lambda *args: Query())
    with closing(CorrelationStore("test")) as store:
        for key in ("a", "b", "c"):
            publish(store, key)
        drain(store)
        old_key = "node:sink"
        task = None
        with store.connection:
            store.enqueue("correlate", "c")
        task = store.work(1)
        result = correlate(task, Query(paths=[]), 1)
        assert old_key not in result["hotspot_keys"]
        store.publish(task, result, 1)
        drain(store)
        hotspot = next(row for row in store.read("example.com")["results"] if row.get("shared_key") == old_key)
        assert hotspot["finding_ids"] == ["a", "b"]


def test_neighbor_truncation_is_retained_on_derived_candidates(monkeypatch):
    with closing(CorrelationStore("test")) as store:
        _, left = publish(store, "a", metadata={"vulnerability_types": ["configuration"]})
        _, right = publish(store, "b", metadata={"vulnerability_types": ["xss"]})
        monkeypatch.setattr(store, "neighbors", lambda keys: ([left, right], True))
        assert worker.materialize_one(store, Mock(), Mock(), 1)
        chains = [row for row in store.read("example.com")["results"] if row["kind"] == "chain"]
        assert chains and all(row["contexts_limited"] for row in chains)
        assert all(any("100 neighbors" in gap for gap in row["analysis_gaps"]) for row in chains)


class ResponseQuery(Query):
    def __init__(self, url, response_url=None):
        self.url, self.response_url = url, response_url
        super().__init__(resources=[{"id": url, "url": url, "method": "GET"}])

    def paths(self, scope, start, **kwargs):
        source = node("response-source", "source", url=self.url)
        sink = node("response-sink", "sink", url=self.url)
        if not self.response_url:
            return self.wrap([])
        if kwargs.get("kinds") == ["RESPONSE_FROM"]:
            endpoint = node("api-resource", kind="resource", url=self.response_url)
            return self.wrap(
                [
                    {
                        "nodes": [source, endpoint],
                        "steps": [
                            {
                                "kind": "RESPONSE_FROM",
                                "source": source["id"],
                                "target": endpoint["id"],
                                "evidence_id": "response-proof",
                            }
                        ],
                    }
                ]
            )
        if kwargs.get("mode") == "flow":
            return self.wrap(
                [
                    {
                        "nodes": [source, sink],
                        "steps": [
                            {
                                "kind": "FLOWS_TO",
                                "source": source["id"],
                                "target": sink["id"],
                                "evidence_id": "flow-proof",
                            }
                        ],
                    }
                ]
            )
        return self.wrap([])


def test_response_endpoint_pairing_uses_explicit_association(monkeypatch):
    monkeypatch.setattr(worker, "correlate", Mock(side_effect=AssertionError("Unexpected graph analysis")))
    with closing(CorrelationStore("test")) as store:
        for key, url, response in (
            ("page", "https://example.com/app.js", "https://example.com/api"),
            ("api", "https://example.com/api", None),
        ):
            store.submit(key, url, {})
            task = store.work(1)
            result = correlate(task, ResponseQuery(url, response), 1)
            store.publish(task, result, 1)
        drain(store)
        chains = [row for row in store.read("example.com")["results"] if row["kind"] == "chain"]
        assert len(chains) == 1 and chains[0]["rule_id"] == "response_to_sink"
        assert "response-proof" in chains[0]["evidence_ids"]


def test_empty_bounded_derivation_reports_limit_on_individual_result(monkeypatch):
    with closing(CorrelationStore("test")) as store:
        publish(store)
        monkeypatch.setattr(store, "neighbors", lambda keys: ([], True))
        assert worker.materialize_one(store, Mock(), Mock(), 1)
        result = store.read("example.com")["results"][0]
        assert result["contexts_limited"]
        assert any("100 neighbors" in gap for gap in result["analysis_gaps"])


def test_cross_url_state_chain_rejects_missing_proof_and_conflicting_anchors(monkeypatch):
    monkeypatch.setattr(worker, "correlate", Mock(side_effect=AssertionError("Unexpected graph analysis")))
    with closing(CorrelationStore("test")) as store:
        for key, write in (("a", True), ("b", False)):
            url = f"https://example.com/{key}.js"
            conflicts = [{"field": "affected_method", "retained": "GET", "submitted": "POST"}] if key == "b" else []
            store.submit(key, url, location(), conflicts=conflicts)
            task = store.work(1)
            result = correlate(task, StateQuery(url, key, write), 1)
            store.publish(task, result, 1)
        drain(store)
        assert not any(row["kind"] == "chain" for row in store.read("example.com")["results"])


def test_pending_neighbor_preserves_previous_chain_as_stale(monkeypatch):
    monkeypatch.setattr(worker, "correlation_query", lambda *args: Query())
    with closing(CorrelationStore("test")) as store:
        publish(store, "a", metadata={"vulnerability_types": ["configuration"]})
        publish(store, "b", metadata={"vulnerability_types": ["xss"]})
        drain(store)
        assert any(row["kind"] == "chain" for row in store.read("example.com")["results"])
        store.submit("a", "https://example.com/app.js", {"severity": "high"})
        with store.connection:
            store.enqueue("derive", "b")
        job = store.connection.execute("SELECT generation FROM jobs WHERE kind='derive' AND key='b'").fetchone()[0]
        derive_job = {"kind": "derive", "id": "b", "generation": job}
        assert store.publish_derived(derive_job, [], dependency=store.load_result("b"))
        chains = [row for row in store.read("example.com")["results"] if row["kind"] == "chain"]
        assert chains and all(row["stale"] for row in chains)
