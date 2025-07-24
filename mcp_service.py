#!/usr/bin/env python3
import argparse
import asyncio
import logging

from shyhurricane.config import configure
from shyhurricane.generator_config import GeneratorConfig, add_generator_args
from shyhurricane.mcp_server import mcp_instance, get_server_context
from shyhurricane.mcp_server.server_context import set_server_config, ServerConfig, set_generator_config

import shyhurricane.mcp_server.deobfuscate_javascript
import shyhurricane.mcp_server.directory_buster
import shyhurricane.mcp_server.fetch_web_resource_content
import shyhurricane.mcp_server.find_indexed_metadata
import shyhurricane.mcp_server.find_web_resources
import shyhurricane.mcp_server.find_wordlists
import shyhurricane.mcp_server.indexers
import shyhurricane.mcp_server.port_scan
import shyhurricane.mcp_server.prompts
import shyhurricane.mcp_server.register_hostname_address
import shyhurricane.mcp_server.run_unix_command

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
    add_generator_args(ap)
    args = ap.parse_args()
    set_generator_config(GeneratorConfig.from_args(args))
    set_server_config(ServerConfig(
        task_pool_size=args.task_pool_size,
        ingest_pool_size=args.index_pool_size,
    ))
    asyncio.run(get_server_context())
    mcp_instance.settings.host = args.host
    mcp_instance.settings.port = args.port
    mcp_instance.run(transport=args.transport)


if __name__ == "__main__":
    main()
