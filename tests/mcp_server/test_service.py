import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

import mcp_service as service

SHUTDOWN_MESSAGE = "Shutting down: waiting up to 5 minutes (300 seconds) for current operations to finish."


@pytest.mark.asyncio
async def test_registered_tools_publish_first_line_summaries(monkeypatch):
    monkeypatch.setattr(service.mcp_instance, "open_world", True)
    tools = await service.mcp_instance.list_tools()
    assert len(tools) == 23
    for tool in tools:
        assert tool.description, tool.name
        summary = tool.description.splitlines()[0]
        assert summary.strip(), tool.name
        assert summary == summary.strip(), tool.name
        assert "\n\n" in tool.description, tool.name


@pytest.mark.parametrize(
    "value,expected", [("False", False), ("false", False), ("0", False), ("no", False), ("", False), ("true", True)]
)
def test_bool_configuration(value, expected):
    assert service._str_to_bool(value) is expected


@pytest.mark.parametrize("transport", service.TRANSPORTS)
def test_app_builder_uses_transport_specific_security_options(monkeypatch, transport):
    server = Mock()
    monkeypatch.setattr(service, "mcp_instance", server)
    app = service.build_mcp_app(transport, "0.0.0.0")
    factory = server.sse_app if transport == "sse" else server.streamable_http_app
    assert app is factory.return_value
    options = factory.call_args.kwargs
    assert options["host"] == "0.0.0.0"
    assert options["transport_security"].enable_dns_rebinding_protection is False
    if transport != "sse":
        assert options["stateless_http"] is (transport == "streamable-http-modern")
    with pytest.raises(ValueError, match="Unknown transport"):
        service.build_mcp_app("invalid", "127.0.0.1")


def test_tty_logging_configuration(monkeypatch):
    loggers = {
        name: SimpleNamespace(handlers=[object()], propagate=True)
        for name in ["uvicorn", "uvicorn.access", "uvicorn.error"]
    }
    fake_logging = SimpleNamespace(CRITICAL=logging.CRITICAL, disable=Mock(), getLogger=lambda name: loggers[name])
    monkeypatch.setattr(service, "logging", fake_logging)
    service.configure_tty_logging()
    fake_logging.disable.assert_called_once_with(logging.CRITICAL)
    assert all(logger.handlers == [] and not logger.propagate for logger in loggers.values())


def test_shutdown_logging_reenables_info_without_duplicate_output(monkeypatch, capsys):
    logger = logging.getLogger("shutdown-test")
    monkeypatch.setattr(logger, "handlers", [])
    monkeypatch.setattr(logger, "level", logging.NOTSET)
    monkeypatch.setattr(logger, "propagate", True)
    logger.addHandler(logging.StreamHandler())
    monkeypatch.setattr(service, "logger", logger)
    previous_disable = logging.root.manager.disable
    try:
        logging.disable(logging.CRITICAL)
        logger.info("dashboard is active")
        assert capsys.readouterr().err == ""
        service.configure_shutdown_logging()
        service.configure_shutdown_logging()
        logger.info(SHUTDOWN_MESSAGE)
        assert capsys.readouterr().err == f"INFO: {SHUTDOWN_MESSAGE}\n"
        assert logger.propagate is False
    finally:
        logging.disable(previous_disable)


@pytest.fixture
async def service_runtime(monkeypatch, tmp_path):
    monkeypatch.setattr(service, "logger", logging.Logger("service-test"))
    monkeypatch.setenv("QDRANT", "db:6333")
    monkeypatch.delenv("MCP_TRANSPORT", raising=False)
    monkeypatch.delenv("LOW_POWER", raising=False)
    monkeypatch.delenv("LOG_FILE", raising=False)
    monkeypatch.delenv("LOG_MAX_BYTES", raising=False)
    monkeypatch.delenv("LOG_BACKUP_COUNT", raising=False)
    monkeypatch.setattr(service, "configure_file_logging", Mock())
    monkeypatch.setattr(service, "file_logging_enabled", lambda: False)
    monkeypatch.delenv("SHYHURRICANE_MONITOR", raising=False)
    monkeypatch.setattr(service.sys, "argv", ["mcp_service.py"])
    for stream in [service.sys.stdin, service.sys.stdout, service.sys.stderr]:
        monkeypatch.setattr(stream, "isatty", lambda: False)
    monkeypatch.setattr(service.torch.accelerator, "device_count", lambda: 0)
    generator = Mock()
    generator.from_args.return_value.apply_summarizing_default.return_value.check.return_value = "generator"
    monkeypatch.setattr(service, "GeneratorConfig", generator)
    monkeypatch.setattr(service, "add_generator_args", lambda parser: None)
    monkeypatch.setattr(service, "set_generator_config", Mock())
    monkeypatch.setattr(service, "set_server_config", Mock())
    context = SimpleNamespace(db="db", close=Mock())
    monkeypatch.setattr(service, "get_server_context", AsyncMock(return_value=context))
    monkeypatch.setattr(service, "get_state_path", lambda *args: str(tmp_path))
    monkeypatch.setattr(service, "build_mcp_app", Mock(return_value=object()))
    monkeypatch.setattr(service, "mcp_instance", SimpleNamespace(open_world=True))
    configs = []
    monkeypatch.setattr(service, "Config", lambda **kwargs: configs.append(kwargs) or kwargs)

    class UvicornServer:
        should_exit = False

        def __init__(self, config):
            self.config = config

        async def serve(self):
            while not self.should_exit:
                await asyncio.sleep(0)

    monkeypatch.setattr(service, "Server", UvicornServer)
    proxy = SimpleNamespace(close=Mock(), serve_forever=AsyncMock())
    monkeypatch.setattr(service, "run_proxy_server", AsyncMock(return_value=proxy))
    monkeypatch.setattr(service, "configure_tty_logging", Mock())
    signals = []
    loop = asyncio.get_running_loop()

    def signal_handler(sig, callback):
        signals.append(sig)
        loop.call_soon(callback)

    monkeypatch.setattr(loop, "add_signal_handler", signal_handler)
    return SimpleNamespace(context=context, proxy=proxy, configs=configs, signals=signals, loop=loop)


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", service.TRANSPORTS)
async def test_main_uses_environment_transport_and_closes_servers(service_runtime, monkeypatch, transport, caplog):
    monkeypatch.setenv("MCP_TRANSPORT", transport)
    shutdown_logging = Mock()
    monkeypatch.setattr(service, "configure_shutdown_logging", shutdown_logging)
    # Use the existing console logging configuration for non-interactive starts.
    monkeypatch.setattr(service, "logger", logging.getLogger("service-test-noninteractive"))
    caplog.set_level(logging.INFO, logger="service-test-noninteractive")

    def close():
        assert SHUTDOWN_MESSAGE in caplog.messages

    service_runtime.context.close.side_effect = close
    await service.main()
    shutdown_logging.assert_not_called()
    assert caplog.messages.count(SHUTDOWN_MESSAGE) == 1
    service.build_mcp_app.assert_called_once_with(transport, "127.0.0.1")
    service.run_proxy_server.assert_awaited_once()
    service_runtime.proxy.close.assert_called_once()
    service_runtime.context.close.assert_called_once()
    config = service_runtime.configs[0]
    assert config["lifespan"] == "on"
    assert config["timeout_graceful_shutdown"] == 300
    assert config["access_log"] is True
    assert len(service_runtime.signals) == 2
    assert service.set_server_config.call_args.args[0].low_power is True


@pytest.mark.asyncio
async def test_cli_transport_overrides_environment_and_gpu_default(service_runtime, monkeypatch):
    monkeypatch.setenv("MCP_TRANSPORT", "invalid")
    monkeypatch.delenv("QDRANT")
    monkeypatch.setattr(service.sys, "argv", ["mcp_service.py", "--transport", "sse"])
    monkeypatch.setattr(service.torch.accelerator, "device_count", lambda: 1)
    await service.main()
    service.build_mcp_app.assert_called_once_with("sse", "127.0.0.1")
    assert service.set_server_config.call_args.args[0].low_power is False


@pytest.mark.asyncio
async def test_invalid_environment_transport_fails_before_startup(service_runtime, monkeypatch):
    monkeypatch.setenv("MCP_TRANSPORT", "invalid")
    with pytest.raises(SystemExit) as error:
        await service.main()
    assert error.value.code == 2
    service.build_mcp_app.assert_not_called()
    service.run_proxy_server.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("monitor_finishes", [True, False])
async def test_tty_monitor_and_signal_shutdown(service_runtime, monkeypatch, monitor_finishes, capsys):
    for stream in [service.sys.stdin, service.sys.stdout, service.sys.stderr]:
        monkeypatch.setattr(stream, "isatty", lambda: True)

    monitor_closed = False

    async def monitor(*args):
        nonlocal monitor_closed
        try:
            assert capsys.readouterr().err == ""
            if not monitor_finishes:
                await asyncio.Event().wait()
        finally:
            # Terminal teardown may require another event-loop iteration.
            await asyncio.sleep(0)
            assert capsys.readouterr().err == ""
            monitor_closed = True

    def close():
        assert monitor_closed
        assert capsys.readouterr().err == f"INFO: {SHUTDOWN_MESSAGE}\n"

    service_runtime.context.close.side_effect = close

    monkeypatch.setattr(service, "run_monitor", monitor)
    if monitor_finishes:

        def unsupported(*args):
            raise NotImplementedError

        monkeypatch.setattr(service_runtime.loop, "add_signal_handler", unsupported)
    await service.main()
    service.configure_tty_logging.assert_called_once()
    assert service.os.environ["SHYHURRICANE_MONITOR"] == "1"
    config = service_runtime.configs[0]
    assert config["log_level"] == "critical"
    assert config["access_log"] is False
    service_runtime.proxy.close.assert_called_once()


@pytest.mark.asyncio
async def test_cancellation_waits_for_monitor_before_logging(service_runtime, monkeypatch, capsys):
    for stream in [service.sys.stdin, service.sys.stdout, service.sys.stderr]:
        monkeypatch.setattr(stream, "isatty", lambda: True)
    monkeypatch.setattr(service_runtime.loop, "add_signal_handler", lambda *args: None)
    started = asyncio.Event()
    closed = asyncio.Event()

    async def monitor(*args):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            await asyncio.sleep(0)
            assert capsys.readouterr().err == ""
            closed.set()

    monkeypatch.setattr(service, "run_monitor", monitor)
    task = asyncio.create_task(service.main())
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert closed.is_set()
    assert capsys.readouterr().err == f"INFO: {SHUTDOWN_MESSAGE}\n"
    service_runtime.context.close.assert_called_once()


@pytest.mark.asyncio
async def test_monitor_failure_still_closes_workers_and_servers(service_runtime, monkeypatch):
    for stream in [service.sys.stdin, service.sys.stdout, service.sys.stderr]:
        monkeypatch.setattr(stream, "isatty", lambda: True)

    async def monitor(*args):
        raise RuntimeError("monitor failed")

    monkeypatch.setattr(service, "run_monitor", monitor)
    with pytest.raises(RuntimeError, match="monitor failed"):
        await service.main()
    service_runtime.context.close.assert_called_once()
    service_runtime.proxy.close.assert_called_once()


@pytest.mark.asyncio
async def test_proxy_startup_failure_still_closes_context(service_runtime, monkeypatch):
    monkeypatch.setattr(service, "run_proxy_server", AsyncMock(side_effect=RuntimeError("proxy failed")))
    with pytest.raises(RuntimeError, match="proxy failed"):
        await service.main()
    service_runtime.context.close.assert_called_once()


@pytest.mark.asyncio
async def test_cancellation_still_closes_context(service_runtime, monkeypatch):
    started = asyncio.Event()

    async def start_proxy(*args):
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(service, "run_proxy_server", start_proxy)
    task = asyncio.create_task(service.main())
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    service_runtime.context.close.assert_called_once()


@pytest.mark.asyncio
async def test_proxy_close_failure_still_closes_context(service_runtime):
    service_runtime.proxy.close.side_effect = RuntimeError("listener failed")
    await service.main()
    service_runtime.context.close.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("cli", [False, True])
async def test_log_file_option_and_environment_precedence(service_runtime, monkeypatch, cli):
    monkeypatch.setenv("LOG_FILE", "/tmp/environment.log")
    if cli:
        monkeypatch.setattr(service.sys, "argv", ["mcp_service.py", "--log-file", "/tmp/command-line.log"])
    monkeypatch.setattr(service, "file_logging_enabled", lambda: True)
    await service.main()
    service.configure_file_logging.assert_called_once_with(
        "/tmp/command-line.log" if cli else "/tmp/environment.log",
        console_enabled=True, max_bytes=10485760, backup_count=5,
    )
    config = service_runtime.configs[0]
    assert config["log_level"] == "debug"
    assert config["access_log"] is True
    assert config["log_config"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["default", "environment", "cli"])
async def test_default_log_file_uses_resolved_data_directory(service_runtime, monkeypatch, tmp_path, source):
    selected = tmp_path / source
    monkeypatch.setenv("DATA_DIR", str(selected))
    if source == "default":
        monkeypatch.delenv("DATA_DIR")
        monkeypatch.setattr("shyhurricane.data_paths.default_data_dir", lambda: selected)
    elif source == "cli":
        monkeypatch.setenv("DATA_DIR", str(tmp_path / "other"))
        monkeypatch.setattr(service.sys, "argv", ["mcp_service.py", "--data-dir", str(selected)])
    await service.main()
    service.configure_file_logging.assert_called_once_with(
        str(selected / "logs" / "shyhurricane.log"), console_enabled=True, max_bytes=10485760, backup_count=5,
    )


@pytest.mark.asyncio
async def test_unwritable_default_log_file_fails_before_services_start(service_runtime, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    service.configure_file_logging.side_effect = PermissionError("permission denied")
    with pytest.raises(SystemExit) as error:
        await service.main()
    assert error.value.code == 2
    assert str(tmp_path / "logs" / "shyhurricane.log") in capsys.readouterr().err
    service.get_server_context.assert_not_awaited()
    service.set_generator_config.assert_not_called()


@pytest.mark.asyncio
async def test_unwritable_log_file_fails_before_services_start(service_runtime, monkeypatch, capsys):
    monkeypatch.setenv("LOG_FILE", "/unwritable/server.log")
    service.configure_file_logging.side_effect = PermissionError("permission denied")
    with pytest.raises(SystemExit) as error:
        await service.main()
    assert error.value.code == 2
    assert "Cannot open log file" in capsys.readouterr().err
    service.get_server_context.assert_not_awaited()
    service.set_generator_config.assert_not_called()


@pytest.mark.asyncio
async def test_indexing_wait_environment_and_cli_override(service_runtime, monkeypatch):
    monkeypatch.setenv("INDEXING_WAIT_TIMEOUT_SECONDS", "12.5")
    await service.main()
    assert service.set_server_config.call_args.args[0].indexing_wait_timeout_seconds == 12.5
    monkeypatch.setattr(service.sys, "argv", ["mcp_service.py", "--indexing-wait-timeout-seconds", "0"])
    await service.main()
    assert service.set_server_config.call_args.args[0].indexing_wait_timeout_seconds == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid", ["-1", "nan", "inf", "invalid"])
async def test_invalid_indexing_wait_timeout_rejected_before_startup(service_runtime, monkeypatch, invalid):
    monkeypatch.setenv("INDEXING_WAIT_TIMEOUT_SECONDS", invalid)
    with pytest.raises(SystemExit) as error:
        await service.main()
    assert error.value.code == 2
    service.get_server_context.assert_not_awaited()


@pytest.mark.asyncio
async def test_data_dir_cli_overrides_environment(service_runtime, monkeypatch, tmp_path):
    selected = tmp_path / "selected"
    monkeypatch.setattr(service.sys, "argv", ["mcp_service.py", "--data-dir", str(selected)])
    await service.main()
    assert selected.is_dir()
    assert service.set_server_config.call_args.args[0].data_dir == str(selected)
    assert service.os.environ["DATA_DIR"] == str(selected)


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["", "../escape"])
async def test_invalid_data_dir_fails_before_startup(service_runtime, monkeypatch, value):
    monkeypatch.setattr(service.sys, "argv", ["mcp_service.py", "--data-dir", value])
    with pytest.raises(SystemExit) as error:
        await service.main()
    assert error.value.code == 2
    service.get_server_context.assert_not_awaited()


@pytest.mark.asyncio
async def test_unwritable_data_dir_fails_before_startup(service_runtime, monkeypatch, tmp_path):
    blocked = tmp_path / "file"
    blocked.touch()
    monkeypatch.setattr(service.sys, "argv", ["mcp_service.py", "--data-dir", str(blocked)])
    with pytest.raises(SystemExit) as error:
        await service.main()
    assert error.value.code == 2
    service.get_server_context.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("flag", ["--database", "--graph-database"])
async def test_removed_storage_flags_fail_before_startup(service_runtime, monkeypatch, flag):
    monkeypatch.setattr(service.sys, "argv", ["mcp_service.py", flag, "old"])
    with pytest.raises(SystemExit) as error:
        await service.main()
    assert error.value.code == 2
    service.get_server_context.assert_not_awaited()


async def test_main_disk_configuration_reaches_server_context(service_runtime, monkeypatch):
    monkeypatch.setenv("DISK_MIN_FREE_BYTES", "4096")
    monkeypatch.setattr(service.sys, "argv", ["mcp_service.py", "--disk-min-free-percent", "5"])
    await service.main()
    config = service.set_server_config.call_args.args[0]
    assert config.disk_min_free_percent == 5
    assert config.disk_min_free_bytes == 4096
    assert config.disk_resume_margin_percent == 1
    assert config.disk_resume_margin_bytes == 536870912


async def test_main_rejects_invalid_disk_config(service_runtime, monkeypatch):
    monkeypatch.setattr(service.sys, "argv", ["mcp_service.py", "--disk-min-free-percent", "nan"])
    with pytest.raises(SystemExit) as error:
        await service.main()
    assert error.value.code == 2
    service.get_server_context.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("cli", [False, True])
async def test_rotation_settings_precedence(service_runtime, monkeypatch, cli):
    monkeypatch.setenv("LOG_MAX_BYTES", "2048")
    monkeypatch.setenv("LOG_BACKUP_COUNT", "3")
    if cli:
        monkeypatch.setattr(service.sys, "argv", [
            "mcp_service.py", "--log-max-bytes", "0", "--log-backup-count", "1",
        ])
    await service.main()
    options = service.configure_file_logging.call_args.kwargs
    assert options["max_bytes"] == (0 if cli else 2048)
    assert options["backup_count"] == (1 if cli else 3)


@pytest.mark.asyncio
@pytest.mark.parametrize("option,variable,value", [
    ("--log-max-bytes", "LOG_MAX_BYTES", "-1"),
    ("--log-max-bytes", "LOG_MAX_BYTES", "bad"),
    ("--log-backup-count", "LOG_BACKUP_COUNT", "0"),
    ("--log-backup-count", "LOG_BACKUP_COUNT", "1.5"),
])
@pytest.mark.parametrize("source", ["cli", "environment"])
async def test_invalid_rotation_settings_stop_startup(
    service_runtime, monkeypatch, option, variable, value, source,
):
    if source == "cli":
        monkeypatch.setattr(service.sys, "argv", ["mcp_service.py", option, value])
    else:
        monkeypatch.setenv(variable, value)
    with pytest.raises(SystemExit) as error:
        await service.main()
    assert error.value.code == 2
    service.configure_file_logging.assert_not_called()
    service.get_server_context.assert_not_awaited()
