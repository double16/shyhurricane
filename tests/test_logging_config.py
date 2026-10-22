"""Diagnostic files preserve logger levels and tracebacks independently of the console."""

import logging
import multiprocessing
from pathlib import Path

import pytest
from mcp import Client
from mcp.server import MCPServer

from shyhurricane import logging_config


def all_loggers():
    root = logging.getLogger()
    return [root, *[item for item in root.manager.loggerDict.values() if isinstance(item, logging.Logger)]]


@pytest.fixture(autouse=True)
def restore_logging(monkeypatch):
    monkeypatch.delenv("LOG_FILE", raising=False)
    monkeypatch.delenv("LOG_MAX_BYTES", raising=False)
    monkeypatch.delenv("LOG_BACKUP_COUNT", raising=False)
    original = {
        logger: (logger.level, logger.disabled, logger.propagate, logger.handlers[:], logger.filters[:])
        for logger in all_loggers()
    }
    filters = {handler: handler.filters[:] for logger in original for handler in logger.handlers}
    disabled = logging.root.manager.disable
    console_enabled = logging_config._console_filter.enabled
    try:
        yield
    finally:
        for logger in all_loggers():
            previous = original.get(logger, (logging.WARNING, False, True, [], []))
            for handler in logger.handlers:
                if isinstance(handler, logging_config.DiagnosticFileHandler) and handler not in previous[3]:
                    handler.close()
            logger.setLevel(previous[0])
            logger.disabled, logger.propagate = previous[1:3]
            logger.handlers, logger.filters = previous[3:]
        for handler, previous_filters in filters.items():
            handler.filters = previous_filters
        logging.disable(disabled)
        logging_config.set_console_logging_enabled(console_enabled)


def test_no_destination_preserves_logging():
    root = logging.getLogger()
    level, handlers = root.level, root.handlers[:]
    driver = logging.getLogger("neo4j.io")
    driver.setLevel(logging.DEBUG)
    logging_config.configure_file_logging(None)
    logging_config.configure_file_logging("")
    assert root.level == level
    assert root.handlers == handlers
    assert not logging_config.file_logging_enabled()
    assert driver.level == logging.WARNING


def test_append_utf8_all_levels_third_party_and_traceback(tmp_path, monkeypatch):
    path = tmp_path / "nested" / "server.log"
    path.parent.mkdir()
    path.write_text("existing\n", encoding="utf-8")
    third_party = logging.getLogger("vendor.test.diagnostics")
    third_party.setLevel(logging.CRITICAL)
    third_party.disabled = True
    third_party.propagate = False
    logging.disable(logging.CRITICAL)
    logging_config.configure_file_logging(str(path), console_enabled=False)
    assert logging_config.file_logging_enabled()
    assert Path(logging_config.os.environ["LOG_FILE"]) == path
    for level in (logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL):
        third_party.log(level, "entry-%s π🙂", level)
    try:
        raise ValueError("diagnostic traceback")
    except ValueError:
        third_party.exception("operation failed")
    # Loggers created after configuration inherit the root's DEBUG threshold.
    logging.getLogger("new.logger.after.configuration").debug("new logger debug")
    text = path.read_text(encoding="utf-8")
    assert text.startswith("existing\n")
    for level in (10, 20, 30, 40, 50):
        assert f"entry-{level} π🙂" in text
    assert "vendor.test.diagnostics" in text
    assert "MainProcess:" in text
    assert "Traceback (most recent call last)" in text
    assert "ValueError: diagnostic traceback" in text
    assert "new logger debug" in text


def test_neo4j_payload_logging_is_suppressed_before_formatting(tmp_path):
    class ExpensiveParameters:
        def __repr__(self):
            raise AssertionError("Neo4j payload should never be formatted")

    driver = logging.getLogger("neo4j.io")
    driver.setLevel(logging.DEBUG)
    path = tmp_path / "driver.log"
    logging_config.configure_file_logging(str(path), console_enabled=False)
    logging_config.configure_file_logging(str(path), console_enabled=False)
    for logger in (driver, logging.getLogger("neo4j.new.child")):
        logger.debug("C: RUN %r", ExpensiveParameters())
        logger.info("driver information")
        logger.warning("driver warning retained")
    logging.getLogger("shyhurricane.graph.database").info("application progress retained")
    text = path.read_text()
    assert "C: RUN" not in text and "driver information" not in text
    assert text.count("driver warning retained") == 2
    assert "application progress retained" in text


def test_http_client_request_traces_are_suppressed_but_warnings_and_app_debug_remain(tmp_path):
    path = tmp_path / "http-client.log"
    logging_config.configure_file_logging(str(path), console_enabled=False)
    http_loggers = [
        logging.getLogger("httpx"),
        logging.getLogger("httpcore.connection"),
        logging.getLogger("httpcore.http11"),
        logging.getLogger("urllib3.connectionpool"),
        logging.getLogger("posthog"),
        logging.getLogger("posthog.request"),
    ]

    for logger in http_loggers:
        logger.debug("HTTP request trace")
        logger.info("HTTP Request: GET https://example.invalid/ HTTP/1.1 200")
        logger.warning("HTTP transport warning")
    logging.getLogger("shyhurricane.index.web_resources").debug("indexing detail retained")

    text = path.read_text(encoding="utf-8")
    assert "HTTP request trace" not in text
    assert "HTTP Request: GET" not in text
    assert text.count("HTTP transport warning") == len(http_loggers)
    assert "indexing detail retained" in text


def test_missing_property_notifications_are_deduplicated_across_reconfiguration(tmp_path, capsys):
    logging.getLogger().handlers = []
    path = tmp_path / "notifications.log"
    logger = logging.getLogger("neo4j.notifications")
    notification = "gql_status='01N52' The property `%s` does not exist in database `neo4j`"
    logging_config.configure_file_logging(str(path))
    for _ in range(2):
        logger.warning(notification, "imported_name")
    logging_config.configure_file_logging(str(path))
    logger.warning(notification, "imported_name")
    logger.warning(notification, "export_names")
    logger.warning("gql_status='01N52' unrecognized notification shape")
    logger.warning("gql_status='01N50' another warning")
    logger.error(notification, "imported_name")
    text = path.read_text()
    console = capsys.readouterr().err
    for output in (text, console):
        assert output.count("The property `imported_name`") == 2  # First warning and the error.
        assert output.count("The property `export_names`") == 1
        assert "unrecognized notification shape" in output
        assert "another warning" in output
    assert sum(isinstance(item, logging_config.Neo4jPropertyWarningFilter) for item in logger.filters) == 1


def test_console_can_be_silenced_and_restored_without_disabling_file(tmp_path, capsys, monkeypatch):
    root = logging.getLogger()
    root.handlers = []
    path = tmp_path / "server.log"
    logging_config.configure_file_logging(str(path))
    logging.getLogger("console-test").info("visible before")
    assert "visible before" in capsys.readouterr().err
    logging_config.set_console_logging_enabled(False)
    logging.getLogger("console-test").error("file only")
    assert capsys.readouterr().err == ""
    logging_config.set_console_logging_enabled(True)
    logging.getLogger("console-test").info("visible after")
    assert "visible after" in capsys.readouterr().err
    text = path.read_text()
    assert "visible before" in text and "file only" in text and "visible after" in text


def test_reconfiguration_closes_previous_handler_and_avoids_duplicates(tmp_path):
    first = tmp_path / "one.log"
    second = tmp_path / "two.log"
    logging_config.configure_file_logging(str(first), console_enabled=False)
    previous = next(
        handler for handler in logging.getLogger().handlers if isinstance(handler, logging_config.DiagnosticFileHandler)
    )
    logging.getLogger("repeat-config").info("first destination")
    logging_config.configure_file_logging(str(second), console_enabled=False)
    assert previous.stream is None
    logging_config.configure_file_logging(str(second), console_enabled=False)
    logging.getLogger("repeat-config").info("once in second")
    assert first.read_text().count("first destination") == 1
    assert "once in second" not in first.read_text()
    assert second.read_text().count("once in second") == 1
    assert (
        sum(isinstance(handler, logging_config.DiagnosticFileHandler) for handler in logging.getLogger().handlers) == 1
    )


def test_bad_destination_leaves_existing_logging_unchanged(tmp_path):
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    with pytest.raises(OSError):
        logging_config.configure_file_logging(str(tmp_path))
    assert root.handlers == handlers
    assert root.level == level
    assert not logging_config.file_logging_enabled()


def test_tty_and_shutdown_keep_file_logging_active(tmp_path, capsys):
    import mcp_service

    logging.getLogger().handlers = []
    path = tmp_path / "server.log"
    logging_config.configure_file_logging(str(path))
    mcp_service.configure_tty_logging()
    logging.getLogger("uvicorn.error").info("HTTP server started")
    logging.getLogger("mcp.server").error("MCP failure during dashboard")
    assert capsys.readouterr().err == ""
    mcp_service.configure_shutdown_logging()
    mcp_service.logger.info("shutdown file message")
    assert "shutdown file message" in capsys.readouterr().err
    text = path.read_text()
    assert "HTTP server started" in text
    assert "MCP failure during dashboard" in text
    assert "shutdown file message" in text


def write_spawned_log(destination, number):
    from qdrant_client.http.exceptions import ResponseHandlingException

    logging_config.configure_file_logging(destination, console_enabled=False)
    logger = logging.getLogger(f"spawned-worker-{number}")
    logger.debug("worker debug %s", number)
    logging.getLogger("neo4j.io").debug("worker driver payload")
    logging.getLogger("neo4j.io").warning("worker driver warning")
    try:
        raise RuntimeError(f"worker traceback {number}")
    except RuntimeError:
        logger.exception("worker failed %s", number)
    try:
        raise ResponseHandlingException(ConnectionError("Qdrant unavailable"))
    except ResponseHandlingException:
        logger.exception("worker Qdrant failed %s", number)


def test_spawned_workers_append_to_same_destination(tmp_path):
    path = tmp_path / "workers.log"
    context = multiprocessing.get_context("spawn")
    processes = [context.Process(target=write_spawned_log, args=(str(path), number)) for number in range(2)]
    try:
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=30)
            assert process.exitcode == 0
        text = path.read_text()
        for number in range(2):
            assert f"worker debug {number}" in text
            assert f"RuntimeError: worker traceback {number}" in text
            assert f"worker Qdrant failed {number} (ResponseHandlingException): Qdrant unavailable" in text
        assert text.count("Traceback (most recent call last)") == 2
        assert "worker driver payload" not in text
        assert text.count("worker driver warning") == 2
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
            process.close()


@pytest.mark.asyncio
async def test_mcp_tool_failure_traceback_reaches_log_file(tmp_path):
    path = tmp_path / "mcp.log"
    logging_config.configure_file_logging(str(path), console_enabled=False)
    server = MCPServer("logging-test")

    @server.tool()
    async def broken_tool() -> str:
        raise RuntimeError("original tool failure")

    async with Client(server, mode="legacy") as client:
        result = await client.call_tool("broken_tool")
        assert result.is_error
    text = path.read_text()
    assert "broken_tool" in text
    assert "Traceback (most recent call last)" in text
    assert "RuntimeError: original tool failure" in text


@pytest.mark.parametrize("file_enabled", [False, True])
@pytest.mark.parametrize("store_error", [False, True])
def test_qdrant_transport_exception_is_one_line_in_all_outputs(tmp_path, capsys, file_enabled, store_error):
    from haystack_integrations.document_stores.qdrant.document_store import QdrantStoreError
    from qdrant_client.http.exceptions import ResponseHandlingException

    error = (
        QdrantStoreError(
            "Error when calling QdrantDocumentStore.count_documents_async(): "
            "Server disconnected without sending a response.\r\nRetry later."
        )
        if store_error
        else ResponseHandlingException(ConnectionError("connection\r\nrefused"))
    )
    root = logging.getLogger()
    root.handlers = [logging.StreamHandler()]
    logger = logging.getLogger("qdrant-transport-test")
    logger.setLevel(logging.WARNING)
    path = tmp_path / "qdrant.log"
    # Simulate the noisy telemetry logger regardless of suite timing or telemetry settings.
    telemetry_logger = logging.getLogger("posthog")
    telemetry_logger.setLevel(logging.DEBUG)
    telemetry_logger.propagate = True
    destination = str(path) if file_enabled else None
    logging_config.configure_file_logging(destination)
    logging_config.configure_file_logging(destination)
    telemetry_logger.debug("making request: %s", "telemetry request body")
    assert not telemetry_logger.isEnabledFor(logging.DEBUG)
    try:
        try:
            raise ConnectionError("underlying transport failure")
        except ConnectionError as cause:
            raise error from cause
    except (ResponseHandlingException, QdrantStoreError):
        logger.exception("Query %s\nfailed", "count", stack_info=True)
    outputs = [capsys.readouterr().err]
    if file_enabled:
        outputs.append(path.read_text())
    for output in outputs:
        assert len(output.splitlines()) == 1
        assert f"Query count failed ({type(error).__name__}): {' '.join(str(error).split())}" in output
        assert "Traceback" not in output
        assert "underlying transport failure" not in output
    for handler in root.handlers:
        assert sum(isinstance(item, logging_config.QdrantExceptionFilter) for item in handler.filters) == 1


def test_qdrant_filter_clears_cached_traceback_and_preserves_other_errors():
    from qdrant_client.http.exceptions import ResponseHandlingException

    filter_ = logging_config.QdrantExceptionFilter()
    error = ResponseHandlingException(TimeoutError("timed out"))
    record = logging.LogRecord("test", logging.WARNING, __file__, 1, "operation failed", (), (type(error), error, None))
    record.exc_text = "previously formatted traceback"
    assert filter_.filter(record)
    assert record.exc_info is None and record.exc_text is None
    assert "ResponseHandlingException" in record.getMessage()
    for exception in (None, ValueError("unexpected error")):
        info = (type(exception), exception, None) if exception else None
        other = logging.LogRecord("test", logging.ERROR, __file__, 1, "other %s", ("failure",), info)
        assert filter_.filter(other)
        assert other.exc_info is info
        assert other.msg == "other %s"
        assert other.args == ("failure",)


@pytest.mark.parametrize("max_bytes,backups", [(None, None), (0, 1), (2048, 3)])
def test_rotation_settings_are_exported(tmp_path, max_bytes, backups):
    logging_config.configure_file_logging(
        str(tmp_path / "settings.log"), console_enabled=False, max_bytes=max_bytes, backup_count=backups,
    )
    handler = next(h for h in logging.getLogger().handlers if isinstance(h, logging_config.DiagnosticFileHandler))
    assert handler.maxBytes == (10485760 if max_bytes is None else max_bytes)
    assert handler.backupCount == (5 if backups is None else backups)
    assert logging_config.os.environ["LOG_MAX_BYTES"] == str(handler.maxBytes)
    assert logging_config.os.environ["LOG_BACKUP_COUNT"] == str(handler.backupCount)


@pytest.mark.parametrize("variable,value", [
    ("LOG_MAX_BYTES", "-1"), ("LOG_MAX_BYTES", "bad"), ("LOG_MAX_BYTES", "1.5"),
    ("LOG_BACKUP_COUNT", "0"), ("LOG_BACKUP_COUNT", "-1"), ("LOG_BACKUP_COUNT", ""),
])
def test_invalid_rotation_environment_preserves_logging(tmp_path, monkeypatch, variable, value):
    monkeypatch.setenv(variable, value)
    previous = logging.getLogger().handlers[:]
    with pytest.raises(ValueError):
        logging_config.configure_file_logging(str(tmp_path / "bad.log"))
    assert logging.getLogger().handlers == previous


def test_explicit_settings_override_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("LOG_MAX_BYTES", "invalid")
    monkeypatch.setenv("LOG_BACKUP_COUNT", "invalid")
    logging_config.configure_file_logging(str(tmp_path / "override.log"), max_bytes=1234, backup_count=2)
    assert logging_config.os.environ["LOG_MAX_BYTES"] == "1234"
    assert logging_config.os.environ["LOG_BACKUP_COUNT"] == "2"


def test_rollover_retention_and_restart(tmp_path):
    path = tmp_path / "rotation.log"
    logging_config.configure_file_logging(str(path), console_enabled=False, max_bytes=1, backup_count=2)
    logger = logging.getLogger("rotation-test")
    for index in range(4):
        logger.info("record-%s π🙂", index)
    assert "record-3 π🙂" in path.read_text()
    assert "record-2 π🙂" in Path(f"{path}.1").read_text()
    assert "record-1 π🙂" in Path(f"{path}.2").read_text()
    assert not Path(f"{path}.3").exists()
    logging_config.configure_file_logging(str(path), console_enabled=False, max_bytes=10000)
    logger.info("restart")
    assert "record-3 π🙂" in path.read_text()
    assert "restart" in path.read_text()


def test_existing_oversized_file_is_archived_intact(tmp_path):
    path = tmp_path / "existing.log"
    original = "existing π🙂\n" * 100
    path.write_text(original)
    logging_config.configure_file_logging(str(path), console_enabled=False, max_bytes=100)
    logging.getLogger("oversized").info("new entry")
    assert Path(f"{path}.1").read_text() == original
    assert "new entry" in path.read_text()


def test_zero_threshold_disables_rotation(tmp_path):
    path = tmp_path / "unbounded.log"
    logging_config.configure_file_logging(str(path), console_enabled=False, max_bytes=0)
    for index in range(100):
        logging.getLogger("unbounded").info("entry-%s", index)
    assert "entry-0" in path.read_text() and "entry-99" in path.read_text()
    assert not Path(f"{path}.1").exists()


@pytest.mark.parametrize("operation", ["_do_lock", "do_open"])
def test_preflight_failure_closes_new_handler_and_preserves_previous(tmp_path, monkeypatch, operation):
    logging_config.configure_file_logging(str(tmp_path / "previous.log"), console_enabled=False)
    previous = logging.getLogger().handlers[:]
    closed = []
    original_close = logging_config.DiagnosticFileHandler.close

    def close(handler):
        closed.append(handler)
        original_close(handler)

    def fail(handler):
        raise PermissionError("preflight denied")

    monkeypatch.setattr(logging_config.DiagnosticFileHandler, "close", close)
    monkeypatch.setattr(logging_config.DiagnosticFileHandler, operation, fail)
    with pytest.raises(PermissionError, match="preflight denied"):
        logging_config.configure_file_logging(str(tmp_path / "new.log"))
    assert logging.getLogger().handlers == previous
    assert len(closed) == 1
    assert closed[0].stream is None
    assert closed[0].stream_lock is None


def write_rotating_worker(destination, worker, ready, start):
    logging_config.configure_file_logging(destination, console_enabled=False)
    ready.put(worker)
    assert start.wait(timeout=30)
    for index in range(30):
        logging.getLogger("concurrent-rotation").info("unique-%s-%s π🙂", worker, index)
    logging.shutdown()


def test_spawned_writers_rotate_without_lost_or_duplicate_records(tmp_path):
    path = tmp_path / "shared.log"
    logging_config.configure_file_logging(str(path), console_enabled=False, max_bytes=2048, backup_count=20)
    context = multiprocessing.get_context("spawn")
    ready, start = context.Queue(), context.Event()
    processes = [
        context.Process(target=write_rotating_worker, args=(str(path), worker, ready, start))
        for worker in range(2)
    ]
    try:
        for process in processes:
            process.start()
        assert {ready.get(timeout=30) for _ in processes} == {0, 1}
        start.set()
        for index in range(30):
            logging.getLogger("concurrent-rotation").info("unique-parent-%s π🙂", index)
        for process in processes:
            process.join(timeout=30)
            assert process.exitcode == 0
        archives = list(tmp_path.glob("shared.log.*"))
        assert len(archives) >= 2
        text = "\n".join(file.read_text() for file in [path, *archives])
        records = [line.split("unique-", 1)[1] for line in text.splitlines() if "unique-" in line]
        expected = {f"{worker}-{index} π🙂" for worker in (0, 1, "parent") for index in range(30)}
        assert set(records) == expected
        assert len(records) == len(expected)
    finally:
        start.set()
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
            process.close()
        ready.close()
        ready.join_thread()


def test_unusable_lock_path_stops_configuration(tmp_path):
    path = tmp_path / "blocked.log"
    probe = logging_config.DiagnosticFileHandler(str(path))
    lock_path = Path(probe.lockFilename)
    probe.close()
    lock_path.mkdir()
    previous = logging.getLogger().handlers[:]
    with pytest.raises(OSError):
        logging_config.configure_file_logging(str(path))
    assert logging.getLogger().handlers == previous
    assert not logging_config.file_logging_enabled()


def test_test_process_disables_haystack_telemetry_before_initialization():
    from importlib import import_module

    telemetry = import_module("haystack.telemetry._telemetry")
    assert telemetry.telemetry is None
