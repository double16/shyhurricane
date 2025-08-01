#!/usr/bin/env python3
import argparse
import asyncio
import logging
import sys

from shyhurricane.config import configure
from shyhurricane.generator_config import GeneratorConfig, add_generator_args
from shyhurricane.mcp_server import mcp_instance, get_server_context
from shyhurricane.mcp_server.generator_config import set_generator_config
from shyhurricane.mcp_server.server_context import set_server_config, ServerConfig

import shyhurricane.mcp_server.prompts
import shyhurricane.mcp_server.tools.deobfuscate_javascript
import shyhurricane.mcp_server.tools.directory_buster
import shyhurricane.mcp_server.tools.fetch_web_resource_content
import shyhurricane.mcp_server.tools.find_indexed_metadata
import shyhurricane.mcp_server.tools.find_web_resources
import shyhurricane.mcp_server.tools.find_wordlists
import shyhurricane.mcp_server.tools.findings
import shyhurricane.mcp_server.tools.indexers
import shyhurricane.mcp_server.tools.port_scan
import shyhurricane.mcp_server.tools.prompt_chooser
import shyhurricane.mcp_server.tools.register_hostname_address
import shyhurricane.mcp_server.tools.run_unix_command
import shyhurricane.mcp_server.tools.status

logger = logging.getLogger(__name__)

configure()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="streamable-http",
        help="Transport method to use: stdio, sse, or streamable-http"
    )
    ap.add_argument("--host", default="127.0.0.1", help="Host to listen on")
    ap.add_argument("--port", type=int, default=8000, help="Port to listen on")
    ap.add_argument("--task-pool-size", type=int, default=3, help="The number of processes in the task pool")
    ap.add_argument("--index-pool-size", type=int, default=1, help="The number of processes in the indexing pool")
    ap.add_argument("--open-world", type=str, default="True",
                    help="If true, the server is allowed to reach out to hosts. If false, only tools using indexed content are advertised.")
    add_generator_args(ap)
    args = ap.parse_args()
    set_generator_config(GeneratorConfig.from_args(args).apply_summarizing_default().check())
    set_server_config(ServerConfig(
        task_pool_size=args.task_pool_size,
        ingest_pool_size=args.index_pool_size,
        open_world=args.open_world,
    ))
    asyncio.run(get_server_context())
    mcp_instance.settings.host = args.host
    mcp_instance.settings.port = args.port

    if args.open_world in ["False", "false", "0", "no"]:
        mcp_instance.open_world = False

    mcp_instance.run(transport=args.transport)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
