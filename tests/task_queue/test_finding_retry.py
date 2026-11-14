from unittest.mock import Mock

import httpx
import pytest

from shyhurricane.task_queue.finding_retry import run, transient


@pytest.mark.parametrize("status,expected", [(429, True), (502, True), (503, True), (504, True), (400, False)])
def test_status(status, expected):
    error = RuntimeError("invalid")
    error.status_code = status
    assert transient(error) is expected


def test_wrapped_and_runner():
    error = RuntimeError()
    error.__cause__ = httpx.ConnectTimeout("timeout")
    assert transient(error)
    runner = RuntimeError("dial tcp 127.0.0.1:123: connect: operation timed out")
    runner.status_code = 400
    assert transient(runner)
    assert not transient(ValueError("invalid"))


def test_retry_success_and_exhaustion(monkeypatch):
    sleep = Mock()
    monkeypatch.setattr("shyhurricane.task_queue.finding_retry.time.sleep", sleep)
    operation = Mock(side_effect=[httpx.ConnectTimeout(""), 42])
    assert run(operation) == 42
    sleep.assert_called_once_with(1)
    operation = Mock(side_effect=httpx.ConnectTimeout(""))
    with pytest.raises(httpx.ConnectTimeout):
        run(operation)
    assert operation.call_count == 4
    with pytest.raises(ValueError):
        run(Mock(side_effect=ValueError()))


def test_shutdown():
    event = Mock()
    event.wait.return_value = True
    with pytest.raises(KeyboardInterrupt):
        run(Mock(side_effect=httpx.ConnectTimeout("")), event)


def test_cycle():
    error = RuntimeError()
    error.__cause__ = error
    assert not transient(error)
