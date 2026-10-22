from unittest.mock import MagicMock

import pytest

from shyhurricane.graph import budget


def test_single_budget_clamps_reads_reports_progress_and_cancels(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(budget.time, "monotonic", lambda: clock[0])
    progress = MagicMock()
    request = budget.QueryBudget(progress)
    store = MagicMock()
    store.read.return_value = [{"id": "one"}]
    assert request.read(store, "READ", timeout=5) == [{"id": "one"}]
    store.read.assert_called_with("READ", timeout=5)
    progress.assert_called_once()
    assert budget.current_budget.get() is None
    clock[0] = 119
    request.read(store, "READ")
    store.read.assert_called_with("READ", timeout=1)
    request.terminate = MagicMock()
    request.cancel()
    request.terminate.assert_called_once()
    assert request.remaining() == 0
    with pytest.raises(TimeoutError):
        request.read(store, "READ")
    request.terminate = None
    request.cancel()


def test_budget_context_is_reset_on_database_error():
    request = budget.QueryBudget()
    store = MagicMock()
    store.read.side_effect = ValueError("bad query")
    with pytest.raises(ValueError):
        request.read(store, "READ")
    assert budget.current_budget.get() is None
