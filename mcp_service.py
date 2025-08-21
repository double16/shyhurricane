#!/usr/bin/env python3
import argparse
import asyncio
import contextlib
import logging
import os
import signal
import sys

import torch
from uvicorn import Config, Server

from shyhurricane.config import configure
from shyhurricane.generator_config import GeneratorConfig, add_generator_args
from shyhurricane.mcp_server import mcp_instance, get_server_context
from shyhurricane.mcp_server.generator_config import set_generator_config
from shyhurricane.proxy_server.proxy_server import run_proxy_server
from shyhurricane.server_config import ServerConfig, set_server_config, add_oast_args, OASTConfig

import shyhurricane.mcp_server.prompts  # noqa: F401
import shyhurricane.mcp_server.tools.channels  # noqa: F401
import shyhurricane.mcp_server.tools.deobfuscate_javascript  # noqa: F401
import shyhurricane.mcp_server.tools.directory_buster  # noqa: F401
import shyhurricane.mcp_server.tools.encoder_decoder  # noqa: F401
import shyhurricane.mcp_server.tools.fetch_web_resource_content  # noqa: F401
import shyhurricane.mcp_server.tools.find_indexed_metadata  # noqa: F401
import shyhurricane.mcp_server.tools.find_web_resources  # noqa: F401
import shyhurricane.mcp_server.tools.find_wordlists  # noqa: F401
import shyhurricane.mcp_server.tools.findings  # noqa: F401
import shyhurricane.mcp_server.tools.indexers  # noqa: F401
import shyhurricane.mcp_server.tools.oast  # noqa: F401
import shyhurricane.mcp_server.tools.port_scan  # noqa: F401
import shyhurricane.mcp_server.tools.prompt_chooser  # noqa: F401
import shyhurricane.mcp_server.tools.register_hostname_address  # noqa: F401
import shyhurricane.mcp_server.tools.run_unix_command  # noqa: F401
import shyhurricane.mcp_server.tools.status  # noqa: F401
import shyhurricane.mcp_server.tools.web_search  # noqa: F401
from shyhurricane.utils import get_state_path

logger = logging.getLogger(__name__)

configure()


def _str_to_bool(bool_as_str: str) -> bool:
    if bool_as_str in ["False", "false", "0", "no"]:
        return False
    return True


async def main():
    open_world_default = os.environ.get("OPEN_WORLD", "True")

    if torch.accelerator.device_count() == 0:
        logger.info("low_power: CPU is the default pytorch device, defaulting to low power mode")
        low_power_default = os.environ.get("LOW_POWER", "True")
    else:
        low_power_default = os.environ.get("LOW_POWER", "False")

    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--transport",
        choices=["streamable-http", "sse"],
        default="streamable-http",
        help="Transport method to use: streamable-http or sse"
    )
    ap.add_argument("--host", default="127.0.0.1", help="Host to listen on")
    ap.add_argument("--port", type=int, default=8000, help="Port to listen on for MCP")
    ap.add_argument("--proxy-port", type=int, default=8010, help="Port to listen on for HTTP/HTTPS proxy")
    ap.add_argument("--task-pool-size", type=int, default=3, help="The number of processes in the task pool")
    ap.add_argument("--index-pool-size", type=int, default=1, help="The number of processes in the indexing pool")
    ap.add_argument("--open-world", type=str, default=open_world_default,
                    help="If true, the server is allowed to reach out to hosts. If false, only tools using indexed content are advertised.")
    ap.add_argument("--low-power", type=str, default=low_power_default,
                    help="If true, disables compute intensive features and those requiring GPU.")
    add_generator_args(ap)
    add_oast_args(ap)
    args = ap.parse_args()
    set_generator_config(GeneratorConfig.from_args(args).apply_summarizing_default().check())
    set_server_config(ServerConfig(
        task_pool_size=args.task_pool_size,
        ingest_pool_size=args.index_pool_size,
        open_world=_str_to_bool(args.open_world),
        low_power=_str_to_bool(args.low_power),
        oast=OASTConfig.from_args(args),
    ))
    server_context = await get_server_context()

    #
    # MCP Server
    #
    mcp_instance.open_world = _str_to_bool(args.open_world)

    match args.transport:
        case "sse":
            mcp_app = mcp_instance.sse_app(None)
        case "streamable-http":
            mcp_app = mcp_instance.streamable_http_app()

    uv_cfg = Config(app=mcp_app, host=args.host, port=args.port, loop="asyncio", lifespan="on", log_level="info")
    uv_server = Server(uv_cfg)
    uv_task = asyncio.create_task(uv_server.serve())

    #
    # Proxy Server
    #
    proxy_server = run_proxy_server(server_context.db, args.host, args.proxy_port,
                                    get_state_path(server_context.db, "certs"))
    proxy_task = asyncio.create_task(proxy_server)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            # Windows: no add_signal_handler for SIGTERM; fall back to Ctrl+C only
            pass

    await stop.wait()

    proxy_server.close()

    uv_server.should_exit = True
    await uv_task
    proxy_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await proxy_task


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(130)
