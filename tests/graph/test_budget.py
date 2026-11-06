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
    clock[0] = 114
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


def test_pool_exhaustion_is_a_bounded_timeout():
    from neo4j.exceptions import ConnectionAcquisitionTimeoutError

    request = budget.QueryBudget()
    store = MagicMock()
    store.read.side_effect = ConnectionAcquisitionTimeoutError("pool exhausted")
    with pytest.raises(TimeoutError, match="connection-pool"):
        request.read(store, "READ")
    assert budget.current_budget.get() is None


@pytest.mark.parametrize("failure", [False, True])
def test_operation_summary_on_success_and_failure(caplog, failure):
    class Service:
        def __init__(self):
            self.budget = budget.QueryBudget()

        @budget.summarize_reads
        def operation(self):
            store = MagicMock()
            store.read.return_value = []
            self.budget.read(store, "/* test */ READ")
            if failure:
                raise ValueError("failed")
            return 42

    with caplog.at_level("DEBUG"):
        if failure:
            with pytest.raises(ValueError, match="failed"):
                Service().operation()
        else:
            assert Service().operation() == 42
    summaries = [r.message for r in caplog.records if "Graph query complete" in r.message]
    assert len(summaries) == 1
    assert "reads=1" in summaries[0]
    assert f"outcome={'failed' if failure else 'complete'}" in summaries[0]
    assert "slowest_stage=test" in summaries[0]


def test_nested_summary_and_cancelled_outcome(caplog):
    class Service:
        def __init__(self):
            self.budget = budget.QueryBudget()

        @budget.summarize_reads
        def inner(self):
            self.budget.cancel()

        @budget.summarize_reads
        def outer(self):
            self.inner()

    with caplog.at_level("DEBUG"):
        Service().outer()
    summaries = [record.message for record in caplog.records if "Graph query complete" in record.message]
    assert len(summaries) == 1
    assert "operation=outer outcome=cancelled" in summaries[0]
