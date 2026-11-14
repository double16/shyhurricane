"""Inventory activation commits only complete generations and advances one revision."""

from unittest.mock import MagicMock

import pytest

from shyhurricane.graph.inventory_publication import (
    InventoryConflict,
    InventoryIncomplete,
    InventoryPublisher,
    initialize,
    visible_inventory,
)


def publisher(rows):
    tx = MagicMock()
    tx.run.return_value.single.side_effect = rows
    session = MagicMock()
    session.execute_write.side_effect = lambda fn: fn(tx)
    return InventoryPublisher(session), tx


def test_initialize_fresh_existing_and_rejection():
    for rows in ([None, None], [{"version": 1}]):
        session = MagicMock()
        session.run.return_value.single.side_effect = rows
        initialize(session)
        statements = [str(call.args[0]) for call in session.run.call_args_list]
        assert any("inventory_batch_slot" in text for text in statements)
    for rows in ([{"version": 3}], [None, {"id": "existing"}]):
        session = MagicMock()
        session.run.return_value.single.side_effect = rows
        with pytest.raises(ValueError):
            initialize(session)
        assert not any("CREATE" in str(call.args[0]) for call in session.run.call_args_list)


@pytest.mark.parametrize("state", ["active", "retired", None])
def test_begin_replay_and_staging(state):
    obj, tx = publisher([{"owner": None, "state": state, "staging": None}])
    assert obj.begin("unit", "generation", {"id": "capture"}) == (state or "staging")
    assert tx.run.call_count == (1 if state else 2)


@pytest.mark.parametrize("row", [
    {"owner": "other", "state": None, "staging": None},
    {"owner": "unit", "state": "staging", "staging": "different"},
])
def test_begin_conflict(row):
    obj, _ = publisher([row])
    with pytest.raises(InventoryConflict):
        obj.begin("unit", "generation", {"id": "capture"})


def staging():
    return {"owner": "unit", "active": "previous", "staging": "generation",
            "state": "staging", "revision": None}


def summary(count=1):
    return {"batches": count, "sequences": count, "first": 0, "last": count - 1}


def test_activate_complete_and_empty():
    for batches, facts in [(1, 2), (0, 0)]:
        obj, tx = publisher([staging(), summary(batches), {"facts": facts}, {"revision": 7}])
        assert obj.activate("unit", "generation", batches=batches, facts=facts) == 7
        assert tx.run.call_args.kwargs["revision"] == 7
    row = {**staging(), "active": "generation", "revision": 7}
    obj, tx = publisher([row])
    assert obj.activate("unit", "generation", batches=1, facts=2) == 7
    assert tx.run.call_count == 1


@pytest.mark.parametrize("row", [None, {**staging(), "owner": "other"},
                                {**staging(), "staging": "other"}, {**staging(), "state": "retired"}])
def test_activate_conflict(row):
    obj, _ = publisher([row])
    with pytest.raises(InventoryConflict):
        obj.activate("unit", "generation", batches=1, facts=2)


@pytest.mark.parametrize("counts", [
    {**summary(), "batches": 0}, {**summary(), "sequences": 0},
    {**summary(), "first": 1}, {**summary(), "last": 1}, summary(),
])
def test_incomplete_never_advances_revision(counts):
    obj, tx = publisher([staging(), counts, {"facts": 0}])
    with pytest.raises(InventoryIncomplete):
        obj.activate("unit", "generation", batches=1, facts=2)
    assert tx.run.call_count == 3


def test_validation_and_read_pin():
    obj, tx = publisher([])
    for kwargs in ({"batches": -1, "facts": 0}, {"batches": 0, "facts": -1},
                   {"batches": 0, "facts": 0, "flow": "invalid"},
                   {"batches": 0, "facts": 0, "discovery": "invalid"}):
        with pytest.raises(ValueError):
            obj.activate("unit", "generation", **kwargs)
    with pytest.raises(ValueError):
        obj.pin("token", -1, 100)
    tx.run.return_value.single.side_effect = [None, None]
    first = obj.pin("token", 7, 100)
    assert first == obj.pin("token", 7, 100)
    assert tx.run.call_args.kwargs["revision"] == 7
    assert "retired_revision" in visible_inventory()
