"""Transaction budgets, retry subdivision, generation activation, and incremental cleanup."""

from unittest.mock import MagicMock

import pytest
from neo4j.exceptions import Neo4jError

from shyhurricane.graph import publication
from shyhurricane.graph.extract import extract
from shyhurricane.graph.model import identity
from shyhurricane.graph.publication import GraphPublisher, PublicationConflict, PublicationMemoryError


def session_with_transactions():
    session = MagicMock()
    transactions = []

    def execute(action):
        tx = MagicMock()
        transactions.append(tx)
        return action(tx)

    session.execute_write.side_effect = execute
    return session, transactions


@pytest.mark.parametrize("count", [0, 1, 500, 501, 1001])
def test_payload_batches_commit_separate_transactions_without_loss(count, caplog):
    session, transactions = session_with_transactions()
    records = [{"id": str(index)} for index in range(count)]
    with caplog.at_level("INFO", logger="shyhurricane.graph.publication"):
        publication.write_batches(session, "capture", "entities", "QUERY", "nodes", records)
    batches = [tx.run.call_args.kwargs["nodes"] for tx in transactions]
    assert [record for batch in batches for record in batch] == records
    assert all(0 < len(batch) <= 500 for batch in batches)
    assert len(transactions) == (count + 499) // 500
    assert caplog.text.count("committed records=") == len(batches)


def test_byte_budget_includes_unicode_encoding_and_rejects_oversized_records(monkeypatch):
    monkeypatch.setattr(publication, "WRITE_BATCH_BYTES", 80)
    records = [{"id": str(index), "text": "🙂" * 3} for index in range(3)]
    batches = list(publication.payload_batches(records))
    assert len(batches) == 3
    assert [row for batch in batches for row in batch] == records
    with pytest.raises(PublicationMemoryError, match="payload budget"):
        list(publication.payload_batches([{"text": "🙂" * 100}]))


def test_write_budgets_use_configured_timeout_and_remaining_maintenance_budget(monkeypatch):
    monkeypatch.setenv("NEO4J_WRITE_TIMEOUT_SECONDS", "90")
    monkeypatch.setattr(publication.time, "monotonic", lambda: 10)
    session, _ = session_with_transactions()
    publication.write_batches(session, "capture", "entities", "QUERY", "rows", [{"id": "one"}])
    assert session.execute_write.call_args.args[0].timeout == 90
    publication.write_batches(session, "capture", "cleanup", "QUERY", "rows", [{"id": "one"}], deadline=12)
    assert session.execute_write.call_args.args[0].timeout == 2
    with pytest.raises(TimeoutError, match="maintenance budget"):
        publication.write_batches(session, "capture", "cleanup", "QUERY", "rows", [{"id": "one"}], deadline=9)


def memory_error():
    return Neo4jError._hydrate_neo4j(code="Neo.TransientError.General.MemoryPoolOutOfMemoryError", message="budget")


def test_memory_failures_subdivide_without_driver_retry_and_single_record_is_terminal(caplog):
    session = MagicMock()
    committed = []

    def execute(action):
        tx = MagicMock()

        def run(statement, **kwargs):
            batch = kwargs["rows"]
            if len(batch) > 2:
                raise memory_error()
            committed.extend(batch)
            return MagicMock()

        tx.run.side_effect = run
        return action(tx)

    session.execute_write.side_effect = execute
    records = [{"id": str(index)} for index in range(7)]
    publication.write_batches(session, "capture", "entities", "QUERY", "rows", records)
    assert committed == records
    assert "memory limit; splitting" in caplog.text
    session.execute_write.side_effect = publication._BatchMemoryError("budget")
    with pytest.raises(PublicationMemoryError, match="even with one record"):
        publication.write_batches(session, "capture", "entities", "QUERY", "rows", records[:1])
    session.execute_write.side_effect = memory_error()
    with pytest.raises(PublicationMemoryError):
        publication.write_batches(session, "capture", "entities", "QUERY", "rows", records[:1])


def test_other_database_errors_and_batch_failures_stop_publication():
    session, transactions = session_with_transactions()
    session.execute_write.side_effect = RuntimeError("database unavailable")
    with pytest.raises(RuntimeError, match="database unavailable"):
        publication.write_batches(session, "capture", "entities", "QUERY", "rows", [{"id": "a"}])
    error = Neo4jError._hydrate_neo4j(code="Neo.ClientError.Statement.SyntaxError", message="syntax")
    tx = MagicMock()
    tx.run.side_effect = error
    session.execute_write.side_effect = lambda action: action(tx)
    with pytest.raises(Neo4jError):
        publication.write_batches(session, "capture", "entities", "QUERY", "rows", [{"id": "a"}])


def test_begin_reuses_matching_active_and_staging_generations_and_archives_legacy():
    session, _ = session_with_transactions()
    tx = MagicMock()
    session.execute_write.side_effect = lambda action: action(tx)
    publisher = GraphPublisher(MagicMock())
    capture = {"id": "capture", "context_urls": ["https://example.com/page"]}
    tx.run.return_value.single.return_value = {"capture": {"active_publication_id": "active"}, "digest": "same"}
    assert publisher.begin(session, capture, "same") == ("active", True)
    tx.run.return_value.single.return_value = {
        "capture": {"complete": True, "staging_publication_id": "obsolete", "context_urls": ["https://old.test"]},
        "digest": None,
    }
    generation, complete = publisher.begin(session, capture, "different")
    assert not complete and generation == identity("publication", "capture", "different", "")
    assert any("abandoned" in call.args[0] for call in tx.run.call_args_list)
    archive = next(call for call in tx.run.call_args_list if "metadata" in call.kwargs)
    assert archive.kwargs["metadata"]["context_urls"] == ["https://old.test"]
    tx.run.reset_mock()
    tx.run.return_value.single.return_value = {"capture": {"staging_publication_id": generation}, "digest": None}
    assert publisher.begin(session, capture, "different") == (generation, False)
    assert not any("abandoned" in call.args[0] for call in tx.run.call_args_list)


def test_activation_rejects_stale_publisher_and_abandon_preserves_active():
    session, _ = session_with_transactions()
    tx = MagicMock()
    session.execute_write.side_effect = lambda action: action(tx)
    publisher = GraphPublisher(MagicMock())
    tx.run.return_value.single.return_value = None
    with pytest.raises(PublicationConflict):
        publisher.activate(session, {"id": "capture"}, "staging")
    assert "coalesce(c.active_publication_id,'')=p.expected_active" in tx.run.call_args.args[0]
    assert "c.staging_publication_id=p.id" in tx.run.call_args.args[0]
    tx.run.return_value.single.return_value = {"id": "staging"}
    publisher.activate(session, {"id": "capture"}, "staging")
    publisher.abandon(session, "staging")
    assert "p.published_at IS NULL" in str(session.run.call_args.args[0])


@pytest.mark.parametrize(
    "failure", [None, PublicationMemoryError("budget"), PublicationConflict("race"), RuntimeError("down")]
)
def test_publish_completion_failures_and_replay(event, monkeypatch, failure):
    store = MagicMock()
    store.read.return_value = []
    publisher = GraphPublisher(store)
    session = store.connect.return_value.session.return_value.__enter__.return_value
    monkeypatch.setattr(publisher, "begin", lambda *args: ("generation", False))
    stage = MagicMock(side_effect=failure)
    activate, cleanup = MagicMock(), MagicMock()
    monkeypatch.setattr(publisher, "stage", stage)
    monkeypatch.setattr(publisher, "activate", activate)
    monkeypatch.setattr(publisher, "cleanup", cleanup)
    graph = extract(event())
    if failure:
        with pytest.raises(type(failure)):
            publisher.publish(graph)
        activate.assert_not_called()
        cleanup.assert_not_called()
        assert session.run.called == isinstance(failure, (PublicationConflict, PublicationMemoryError))
    else:
        publisher.publish(graph)
        stage.assert_called_once()
        activate.assert_called_once()
        cleanup.assert_not_called()
        monkeypatch.setattr(publisher, "begin", lambda *args: ("generation", True))
        publisher.publish(graph)
        assert stage.call_count == activate.call_count == 1


def test_staging_storage_ids_context_links_and_legacy_evidence(event, monkeypatch):
    store = MagicMock()
    store.read.side_effect = [[{"id": "legacy"}], [], [{"id": "legacy-node"}], []]
    session, transactions = session_with_transactions()
    publisher = GraphPublisher(store)
    graph = extract(event(body='<a href="/next">next</a>'))
    source, target = list(graph.nodes)[:2]
    graph.nodes[source]["context_urls"] = ["https://example.com/form"]
    proof = next(iter(graph.evidence))
    links = {
        "link": {
            "id": "link",
            "source": source,
            "target": target,
            "capture_id": graph.event["id"],
            "evidence_id": proof,
            "_source_local": True,
            "_target_local": False,
            "_proof_local": True,
            "_source_storage_id": source,
            "_target_storage_id": "external",
        }
    }
    original_nodes = {key: dict(value) for key, value in graph.nodes.items()}
    publisher.stage(session, {"id": graph.event["id"]}, "generation", graph, links)
    assert graph.nodes == original_nodes
    calls = [tx.run.call_args for tx in transactions]
    nodes = next(call.kwargs["nodes"] for call in calls if "nodes" in call.kwargs)
    assert nodes[0]["id"] == identity("generation", nodes[0]["_logical_id"])
    assert nodes[0]["context_owner_id"] == "generation"
    edges = next(call.kwargs["edges"] for call in calls if "edges" in call.kwargs)
    assert edges[-1]["_source_storage_id"] == identity("generation", source)
    assert edges[-1]["_target_storage_id"] == "external"
    assert edges[-1]["evidence_id"] == identity("generation", proof)
    assert calls[-1].kwargs["rows"][0]["owner"] == identity("legacy-publication", graph.event["id"])
    store.read.side_effect = [[{"id": "external"}], []]
    publisher.validate_dependencies(links)
    with pytest.raises(PublicationConflict):
        publisher.validate_dependencies(links)


def test_cleanup_is_bounded_preserves_published_evidence_and_defers_failure(monkeypatch, caplog):
    store = MagicMock()
    publication_record = {"id": "retired", "capture": "capture", "abandoned": False}
    store.read.side_effect = [[publication_record], [{"id": "edge"}]] + [[]] * 7
    publisher = GraphPublisher(store)
    session, transactions = session_with_transactions()
    store.connect.return_value.session.return_value.__enter__.return_value = session
    publisher.cleanup()
    assert len(transactions) == 2
    assert "DELETE r" in transactions[0].run.call_args.args[0]
    assert "cleaned=true REMOVE p:GraphCleanupPending" in transactions[-1].run.call_args.args[0]
    assert not any("GraphEvidence" in stage[0] for stage in publisher.cleanup_stages(publication_record))
    assert any(
        "GraphEvidence" in stage[0] for stage in publisher.cleanup_stages({**publication_record, "abandoned": True})
    )
    legacy = {**publication_record, "id": identity("legacy-publication", "capture")}
    assert "n._publication_id IS NULL" in publisher.cleanup_stages(legacy)[1][0]
    monkeypatch.setattr(publication, "CLEANUP_BATCHES", 1)
    store.read.side_effect = [[publication_record], [{"id": "edge"}]]
    session.run.reset_mock()
    publisher.cleanup()
    session.run.assert_not_called()
    store.read.side_effect = RuntimeError("database unavailable")
    with pytest.raises(RuntimeError, match="database unavailable"):
        publisher.cleanup()


def test_metadata_and_activation_memory_errors_are_terminal_and_retirement_failure_is_logged(
    event, monkeypatch, caplog
):
    store = MagicMock()
    store.read.return_value = []
    publisher = GraphPublisher(store)
    monkeypatch.setattr(publisher, "begin", MagicMock(side_effect=memory_error()))
    with pytest.raises(PublicationMemoryError, match="metadata"):
        publisher.publish(extract(event()))
    monkeypatch.setattr(publisher, "begin", lambda *args: ("generation", False))
    monkeypatch.setattr(publisher, "stage", MagicMock())
    monkeypatch.setattr(publisher, "activate", MagicMock(side_effect=memory_error()))
    monkeypatch.setattr(publisher, "abandon", MagicMock(side_effect=RuntimeError("database unavailable")))
    with pytest.raises(PublicationMemoryError, match="activation"):
        publisher.publish(extract(event()))
    assert "retirement deferred" in caplog.text
    syntax = Neo4jError._hydrate_neo4j(code="Neo.ClientError.Statement.SyntaxError", message="syntax")
    monkeypatch.setattr(publisher, "activate", MagicMock(side_effect=syntax))
    with pytest.raises(Neo4jError):
        publisher.publish(extract(event()))
    monkeypatch.setattr(publisher, "begin", MagicMock(side_effect=syntax))
    with pytest.raises(Neo4jError):
        publisher.publish(extract(event()))


def test_publication_estimates_include_deduplicated_links_and_only_activate_after_staging(event, monkeypatch):
    store = MagicMock()
    store.read.return_value = []
    publisher = GraphPublisher(store)
    graph = extract(event())
    graph.analysis = [{"mode": "summary", "library": "Fixture", "budget_limited": True}]
    links = {"a": {"id": "inferred"}, "duplicate": {"id": "inferred"}}
    monkeypatch.setattr(publication.LinkPlanner, "plan", lambda self: links)
    monkeypatch.setattr(publisher, "begin", lambda *args: ("generation", False))
    monkeypatch.setattr(publisher, "stage", lambda *args: None)
    monkeypatch.setattr(publisher, "validate_dependencies", lambda *args: None)
    activate = MagicMock()
    monkeypatch.setattr(publisher, "activate", activate)
    monkeypatch.setattr(publisher, "cleanup", lambda: None)
    publisher.publish(graph)
    capture = activate.call_args.args[1]
    assert capture["entity_estimate"] == len(graph.nodes)
    assert capture["relationship_estimate"] == len(graph.edges) + 1
    assert capture["summarized"] and capture["budget_limited"]
    assert '"library": "Fixture"' in capture["analysis_details"]
    publisher.publish(graph)
    assert activate.call_args.args[1] == capture


def test_summary_path_metadata_survives_staging_as_neo4j_properties(event):
    store = MagicMock()
    store.read.return_value = []
    session, transactions = session_with_transactions()
    graph = extract(event(body=""))
    source, target = list(graph.nodes)[:2]
    edge_id = graph.fact(
        source, target, "SUMMARIZED_FLOW", "js.size-summary", classification="statically_inferred",
        original_hops=30, endpoint_locations=["1:0", "30:0"], witness=["input -> internal", "internal -> output"],
        summary_notice="Intermediate operations omitted; static reachability only",
    )
    GraphPublisher(store).stage(session, {"id": graph.event["id"]}, "generation", graph, {})
    calls = [tx.run.call_args for tx in transactions]
    edges = [row for call in calls for row in call.kwargs.get("edges", [])]
    proofs = [row for call in calls for row in call.kwargs.get("evidence", [])]
    stored_edge = next(row for row in edges if row["_logical_id"] == edge_id)
    proof = next(row for row in proofs if row["id"] == stored_edge["evidence_id"])
    for record in (stored_edge, proof):
        assert record["original_hops"] == 30
        assert record["endpoint_locations"] == ["1:0", "30:0"]
        assert record["witness"] == ["input -> internal", "internal -> output"]
        assert "omitted" in record["summary_notice"]
        assert all(isinstance(value, str | int | float | bool | list) or value is None for value in record.values())
