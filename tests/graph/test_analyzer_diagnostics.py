"""Analyzer failures retain bounded, useful diagnostics."""

import subprocess

import pytest

from shyhurricane.graph.analyzer_diagnostics import stderr_summary
from shyhurricane.graph.extract import run_javascript


@pytest.mark.parametrize("stderr", [None, "", b"", "const password = 'private';\n^^^^\n> 1 | private"])
def test_empty_and_source_only_stderr(stderr):
    assert stderr_summary(stderr, "const password = 'private';") == (
        "[stderr empty or omitted: no safe diagnostic lines]"
    )


def test_stderr_redacts_and_bounds():
    result = stderr_summary(
        b"SyntaxError: Unexpected token 'private'\n"
        b"  at parse (https://user:pass@example.com/a.js?token=secret:1:2)\n"
        b"Error: password=private\nconst private = 1;\n",
        "const private = 1;",
    )
    assert "SyntaxError" in result and "at parse" in result
    assert "private" not in result and "user:pass" not in result and "token=secret" not in result
    result = stderr_summary("Error: " + "x" * 5000, "")
    assert len(result) == 4096 + len(" [truncated]")
    assert result.endswith(" [truncated]")


@pytest.mark.parametrize("kind", ["exit", "timeout", "os"])
def test_runner_failure_context_and_propagation(kind, monkeypatch, caplog):
    errors = {
        "exit": subprocess.CalledProcessError(1, "docker", stderr=b"SyntaxError: bad input\n"),
        "timeout": subprocess.TimeoutExpired("docker", 240, stderr="Error: slow"),
        "os": OSError("cannot start"),
    }
    error = errors[kind]

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr("shyhurricane.graph.extract.subprocess.run", fail)
    monkeypatch.setattr("shyhurricane.graph.extract.unix_command_image", lambda: "test-image")
    with pytest.raises(type(error)) as raised:
        run_javascript("const x=1;", "app.js?token=private#fragment", "full")
    assert raised.value is error
    assert "filename=app.js image=test-image mode=full source_bytes=10" in caplog.text
    assert "token=private" not in caplog.text
    if kind == "exit":
        assert "exit_status=1" in caplog.text and "SyntaxError: bad input" in caplog.text
    elif kind == "timeout":
        assert "timeout=240" in caplog.text


def test_runner_success_has_no_failure_diagnostic(monkeypatch, caplog):
    def success(*args, **kwargs):
        assert kwargs["capture_output"] and kwargs["check"]
        assert kwargs["timeout"] == 240
        return subprocess.CompletedProcess(args[0], 0, stdout='{"nodes": []}')

    monkeypatch.setattr("shyhurricane.graph.extract.subprocess.run", success)
    assert run_javascript("", "a.js") == {"nodes": []}
    assert "JavaScript analyzer" not in caplog.text
