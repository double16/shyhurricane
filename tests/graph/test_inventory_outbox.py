"""A remote commit can replay safely before the local acknowledgement persists."""

import sqlite3
from unittest.mock import MagicMock

import pytest

from shyhurricane.graph.inventory_outbox import InventoryOutbox, initialize
from shyhurricane.graph.shard_store import ShardStore


def record(value="one"):
    return {"id": value, "manifest_id": value, "capture_id": "capture",
            "analysis_unit_id": "unit", "kind": "symbol"}


def test_outbox_replay_and_reopen(tmp_path):
    path = tmp_path / "state.sqlite"
    c = sqlite3.connect(path)
    initialize(c)
    store = ShardStore(tmp_path, c)
    outbox = InventoryOutbox(c, store)
    with c:
        ids = outbox.enqueue("generation", [record()])
    with c:
        assert outbox.enqueue("generation", [record()]) == ids
    pending = outbox.pending()
    assert len(pending) == 1
    assert store.read(pending[0][3]) == [record()]
    session = MagicMock()
    tx = MagicMock()
    tx.run.return_value.single.side_effect = [
        {"state": "staging"}, None,
        {"state": "active"}, {"shard": pending[0][3], "sequence": 0, "generation": "generation"},
    ]
    session.execute_write.side_effect = lambda fn: fn(tx)
    outbox.deliver(session, pending[0])
    c.rollback()  # Simulate lost local acknowledgement after the remote commit.
    c.close()
    c = sqlite3.connect(path)
    outbox = InventoryOutbox(c, store)
    assert len(outbox.pending()) == 1
    with c:
        outbox.deliver(session, outbox.pending()[0])
    assert outbox.pending() == []
    assert session.execute_write.call_count == 2
    c.close()


def test_conflicts_errors_and_bounds(tmp_path):
    c = sqlite3.connect(":memory:")
    initialize(c)
    outbox = InventoryOutbox(c, ShardStore(tmp_path, c))
    with c:
        outbox.enqueue("generation", [record()])
    with pytest.raises(ValueError, match="identity conflict"), c:
        outbox.enqueue("generation", [record("different")])
    assert len(outbox.pending()) == 1
    for limit in (0, 501):
        with pytest.raises(ValueError):
            outbox.pending(limit)
    session = MagicMock()
    session.execute_write.side_effect = OSError("unavailable")
    with pytest.raises(OSError):
        outbox.deliver(session, outbox.pending()[0])
    assert len(outbox.pending()) == 1
    c.close()


@pytest.mark.parametrize("state,receipt", [
    (None, None),
    ({"state": "active"}, None),
    ({"state": "staging"}, {"shard": "different", "sequence": 0, "generation": "generation"}),
])
def test_delivery_guards(tmp_path, state, receipt):
    from shyhurricane.graph.inventory_publication import InventoryConflict

    connection = sqlite3.connect(":memory:")
    try:
        initialize(connection)
        outbox = InventoryOutbox(connection, ShardStore(tmp_path, connection))
        with connection:
            outbox.enqueue("generation", [record()])
        tx = MagicMock()
        tx.run.return_value.single.side_effect = [state, receipt]
        session = MagicMock()
        session.execute_write.side_effect = lambda fn: fn(tx)
        with pytest.raises(InventoryConflict):
            outbox.deliver(session, outbox.pending()[0])
        assert len(outbox.pending()) == 1
    finally:
        connection.close()
