"""Lookup projection normalization and transactional backfill."""

import threading
from unittest.mock import MagicMock

import pytest

from shyhurricane.graph import lookup


def test_host_boundaries_and_context_identity():
    assert lookup.reverse_host("https://Sub.Example.com:8443/path") == "moc.elpmaxe.bus."
    assert not lookup.reverse_host("https://badexample.com").startswith(lookup.reverse_host("https://example.com"))
    assert lookup.reverse_host("") == "."
    first = lookup.context_records("owner", "GraphEntity", ["https://example.com", "https://example.com"])
    assert len(first) == 1 and first[0]["owner_id"] == "owner"
    assert first != lookup.context_records("owner", "GraphCapture", ["https://example.com"])
    assert lookup.context_records("owner", "GraphEntity", []) == []


@pytest.mark.parametrize("stage", [0, 1, 2])
def test_backfill_commits_projection_and_checkpoint_together(monkeypatch, stage):
    monkeypatch.setattr(lookup.time, "monotonic", lambda: 0)
    store = MagicMock()
    store.timeouts.read = 30
    tx = store.connect.return_value.session.return_value.__enter__.return_value.begin_transaction.return_value
    tx = tx.__enter__.return_value
    marker = {"stage": stage, "cursor": "", "complete": False}
    pages = iter([[{"id": "one", "url": "https://example.com/", "contexts": ["https://page.test/"],
                    "context_owner": None}], []])

    def run(statement, **kwargs):
        result = MagicMock()
        if "RETURN m.stage" in statement:
            result.single.return_value = dict(marker)
        elif "RETURN n.id" in statement:
            return next(pages)
        elif "SET m.stage" in statement:
            marker.update(stage=kwargs["stage"], cursor=kwargs["cursor"], complete=kwargs["complete"])
            if marker["stage"] != stage:
                marker["complete"] = True
        return result

    tx.run.side_effect = run
    assert lookup.migrate_lookup(store, 10, threading.Event(), batch_size=1) == 1
    calls = tx.run.call_args_list
    assert any("GraphContext" in call.args[0] and call.kwargs["rows"] for call in calls)
    updates = [call.kwargs for call in calls if call.args[0].startswith("MATCH (m:GraphState")]
    assert updates[0]["cursor"] == "one" and updates[1]["cursor"] == ""
    assert updates[1]["complete"] == (stage == 2)
    assert any("_reverse_host" in call.args[0] for call in calls) == (stage == 0)


def test_backfill_deadline_stop_and_failure(monkeypatch):
    monkeypatch.setattr(lookup.time, "monotonic", lambda: 10)
    store = MagicMock()
    stop = threading.Event()
    assert lookup.migrate_lookup(store, 10, stop) == 0
    stop.set()
    assert lookup.migrate_lookup(store, 20, stop) == 0
    store.connect.assert_not_called()
    stop.clear()
    store.timeouts.read = 30
    tx = store.connect.return_value.session.return_value.__enter__.return_value.begin_transaction.return_value
    tx.__enter__.return_value.run.side_effect = RuntimeError("interrupted")
    with pytest.raises(RuntimeError, match="interrupted"):
        lookup.migrate_lookup(store, 20, stop)
    assert tx.__exit__.call_args.args[0] is RuntimeError
