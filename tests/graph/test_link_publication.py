"""Inferred links use independent generations and immutable structural evidence."""

from unittest.mock import MagicMock

import pytest

from shyhurricane.graph.extract import extract
from shyhurricane.graph.link_publication import LinkPublisher
from shyhurricane.graph.model import identity
from shyhurricane.graph.publication import PublicationConflict


def projection(event):
    graph = extract(event(body='<a href="/next">next</a>'))
    source, target = list(graph.nodes)[:2]
    proof = next(iter(graph.evidence))
    graph.planned_links = {"link": {
        "id": "link", "source": source, "target": target, "capture_id": graph.event["id"],
        "evidence_id": proof, "kind": "FLOWS_TO", "classification": "statically_inferred",
        "_source_local": True, "_target_local": False, "_proof_local": True,
        "_source_storage_id": source, "_target_storage_id": "external",
    }}
    return graph, source, proof


@pytest.mark.parametrize("completed", [False, True])
def test_links_publish_without_entities_and_reuse_structural_evidence(event, monkeypatch, completed):
    graph, source, proof = projection(event)
    store = MagicMock()
    store.read.side_effect = [[{"generation": "structural"}],
                              [{"id": identity("structural", source)}, {"id": "external"}]] * 3
    publisher = LinkPublisher(store)
    monkeypatch.setattr(publisher, "begin", lambda *a: ("links-generation", completed))
    activate = MagicMock()
    monkeypatch.setattr(publisher, "activate", activate)
    session = store.connect.return_value.session.return_value.__enter__.return_value
    transactions = []

    def execute(action):
        tx = MagicMock()
        transactions.append(tx)
        return action(tx)

    session.execute_write.side_effect = execute
    # Both validation passes inspect exact structural IDs; link-only activation changes none.
    store.read.side_effect = [[{"generation": "structural"}]] + [
        [{"id": identity("structural", source)}, {"id": "external"}]
    ] * 2 + [[{"id": identity("links-generation", "link")}]]
    assert publisher.publish(graph) is not completed
    assert activate.call_count == int(not completed)
    if not completed:
        call = next(tx.run.call_args for tx in transactions if "edges" in tx.run.call_args.kwargs)
        assert "GraphEntity" in call.args[0] and "MERGE (e:GraphEntity" not in call.args[0]
        record = call.kwargs["edges"][0]
        assert record["_source_storage_id"] == identity("structural", source)
        assert record["_target_storage_id"] == "external"
        assert record["evidence_id"] == identity("structural", proof)
        assert record["_link_publication"] is True
        assert record["_publication_id"] == "links-generation"


def test_missing_structural_generation_fails_without_writes(event):
    graph, _, _ = projection(event)
    for rows in ([], [{"generation": None}]):
        store = MagicMock()
        store.read.return_value = rows
        with pytest.raises(PublicationConflict, match="Structural"):
            LinkPublisher(store).publish(graph)
        store.connect.assert_not_called()


def test_invalidated_dependency_abandons_staging_and_never_activates(event, monkeypatch):
    graph, _, _ = projection(event)
    store = MagicMock()
    store.read.side_effect = [[{"generation": "structural"}], []]
    publisher = LinkPublisher(store)
    monkeypatch.setattr(publisher, "begin", lambda *a: ("staging", False))
    activate, abandon = MagicMock(), MagicMock()
    monkeypatch.setattr(publisher, "activate", activate)
    monkeypatch.setattr(publisher, "abandon", abandon)
    with pytest.raises(PublicationConflict):
        publisher.publish(graph)
    abandon.assert_called_once()
    activate.assert_not_called()


def test_independent_pointer_activation_and_cleanup_guards(event):
    graph, _, _ = projection(event)
    store = MagicMock()
    publisher = LinkPublisher(store)
    session, tx = MagicMock(), MagicMock()
    session.execute_write.side_effect = lambda action: action(tx)
    tx.run.return_value.single.return_value = {"capture": {}, "digest": None}
    publisher.begin(session, {"id": graph.event["id"]}, "digest")
    assert "c.active_link_publication_id" in tx.run.call_args_list[0].args[0]
    publisher.activate(session, {"id": graph.event["id"]}, "links")
    statement = tx.run.call_args.args[0]
    assert "c.active_link_publication_id=p.id" in statement
    assert "c.active_publication_id=p.id" not in statement
    publisher.abandon(session, "links")
    assert "c.staging_link_publication_id" in session.run.call_args.args[0].text
    for select, delete in publisher.cleanup_stages({"id": "retired", "capture": "capture", "abandoned": False}):
        for statement in (select, delete):
            assert "coalesce(c.active_link_publication_id,'')<>p.id" in statement
            assert "coalesce(c.staging_link_publication_id,'')<>p.id" in statement


def test_abandon_failure_preserves_original_conflict(event, monkeypatch, caplog):
    graph, _, _ = projection(event)
    store = MagicMock()
    store.read.side_effect = [[{"generation": "structural"}], []]
    publisher = LinkPublisher(store)
    monkeypatch.setattr(publisher, "begin", lambda *a: ("staging", False))
    monkeypatch.setattr(publisher, "abandon", MagicMock(side_effect=OSError("offline")))
    with pytest.raises(PublicationConflict):
        publisher.publish(graph)
    assert "staging retirement deferred" in caplog.text
