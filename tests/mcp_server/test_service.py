import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

import mcp_service as service


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


@pytest.fixture
async def service_runtime(monkeypatch, tmp_path):
    monkeypatch.setenv("QDRANT", str(tmp_path / "db"))
    monkeypatch.delenv("MCP_TRANSPORT", raising=False)
    monkeypatch.delenv("LOW_POWER", raising=False)
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
async def test_main_uses_environment_transport_and_closes_servers(service_runtime, monkeypatch, transport):
    monkeypatch.setenv("MCP_TRANSPORT", transport)
    await service.main()
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
    monkeypatch.setenv("QDRANT", "")
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
async def test_tty_monitor_and_signal_shutdown(service_runtime, monkeypatch, monitor_finishes):
    for stream in [service.sys.stdin, service.sys.stdout, service.sys.stderr]:
        monkeypatch.setattr(stream, "isatty", lambda: True)

    async def monitor(*args):
        if not monitor_finishes:
            await asyncio.Event().wait()

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
