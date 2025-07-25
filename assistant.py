#!/usr/bin/env python3
"""
Cybersecurity offense assistant.
"""
import argparse
import datetime
import json
import logging
import os
import sys
from pathlib import Path
from typing import Iterable, Callable, Tuple

from haystack import Pipeline
from haystack.core.component import Component
from haystack.core.errors import PipelineRuntimeError
from haystack.dataclasses import ChatMessage, StreamingChunk
from haystack.tools import Toolset
from haystack_integrations.tools.mcp import MCPToolset
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from rich import get_console
from rich.markdown import Markdown

from shyhurricane.config import configure
from shyhurricane.generator_config import GeneratorConfig, add_generator_args
from shyhurricane.mcp_server.generator_config import set_generator_config
from shyhurricane.retrieval_pipeline import build_chat_pipeline, build_agent_pipeline, create_tools

logger = logging.getLogger(__name__)

configure()

console = get_console()


def configure_logging(level=logging.CRITICAL):
    for name in [
        "haystack",  # core
        "haystack_integrations",  # all integrations
        "haystack_telemetry",  # optional telemetry
        "chromadb",  # Chroma client (can be noisy)
        "sentence_transformers",
        "httpx",
        "httpcore",
        "mcp",
        "fastmcp",
        "streamable_http",
        "mcp.transport.streamable_http",
    ]:
        logging.getLogger(name).setLevel(level)


def streaming_chunk_callback(verbose: bool = False, chat_logger: Callable[[str], None] = None):
    def callback(chunk: StreamingChunk):
        console.print(chunk.content, end="")
        if chat_logger:
            chat_logger(chunk.content)
        if verbose:
            if chunk.tool_calls:
                for tool_call in chunk.tool_calls:
                    if tool_call.tool_name:
                        console.print(f"{tool_call.tool_name}({tool_call.arguments or ""})")
                if chunk.tool_call_result:
                    if chunk.tool_call_result.origin:
                        console.print(
                            f"{chunk.tool_call_result.origin.tool_name}({chunk.tool_call_result.origin.arguments or ""})")
                    console.print(f"{chunk.tool_call_result.result}")
            if chunk.finish_reason:
                msg = f"\n🛑 {chunk.finish_reason}"
                console.print(msg)
                if chat_logger:
                    chat_logger(msg)
        else:
            if chunk.finish_reason:
                console.print("\n")
                if chat_logger:
                    chat_logger("\n")

    return callback


def main():
    chat_history_default = datetime.date.today().isoformat() + "_history.md"

    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--mode",
        choices=["chat", "agent"],
        default="chat",
        help="AI mode to use: chat or agent"
    )
    ap.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")
    add_generator_args(ap)
    ap.add_argument("--mcp-url", nargs="+", required=False,
                    help="URL for the MCP server, i.e. http://127.0.0.1:8000/mcp/")
    ap.add_argument("--stream", action="store_true", help="Stream messages, always on for agent mode")
    ap.add_argument("--history", default=chat_history_default)
    args = ap.parse_args()

    if args.verbose:
        configure_logging(logging.INFO)
    else:
        configure_logging(logging.CRITICAL)

    generator_config = GeneratorConfig.from_args(args)
    set_generator_config(generator_config)

    tools = create_tools(args.mcp_url)
    prompt_chooser_tool = None
    for tool in tools:
        if tool.name == "prompt_chooser":
            prompt_chooser_tool = tool
            break
    if not prompt_chooser_tool:
        console.print("[red]No prompt_chooser tool found[/red]")
        sys.exit(1)

    def chat_logger(line):
        Path(args.history).touch(mode=0o644, exist_ok=True)
        with open(args.history, "a", encoding="utf-8") as f:
            f.write(line)

    def create_pipeline(system_prompt: str, tools: Toolset) -> Tuple[Pipeline, Component, Toolset]:
        if args.mode == "agent":
            args.stream = True
            pipe, generator, _ = build_agent_pipeline(generator_config, system_prompt, args.mcp_url, tools)
        else:
            pipe, generator, _ = build_chat_pipeline(generator_config, system_prompt, args.mcp_url, tools)

        if args.stream and generator is not None:
            generator.streaming_callback = streaming_chunk_callback(verbose=bool(args.verbose), chat_logger=chat_logger)

        return pipe, generator, tools

    pipe = None

    prompt_history_path = Path(Path.home(), ".local", "state", "shyhurricane", "prompt_history")
    os.makedirs(prompt_history_path.parent, mode=0o755, exist_ok=True)
    sess = PromptSession(history=FileHistory(os.fspath(prompt_history_path)),
                         # completer=WordCompleter(["/set","/show","/reload","/exit","/quit"], ignore_case=True)
                         )
    console.print(f"""
This is a penetration test assistant in {args.mode} mode using {generator_config.describe()}. You can say things like:
- Conduct a penetration test on 192.168.1.1
- Look for vulnerabilities on http://192.168.1.1
""")
    console.print("🛡️  Ready. Commands: /show • /exit\n")

    chat_logger(f"Assistant Info\n\n{args.mode} mode using {generator_config.describe()}")

    try:
        while True:
            try:
                user_in = sess.prompt("💬 ")
                if not user_in.strip():
                    continue
                if user_in.lower() in {"/exit", "/quit"}:
                    break
                if user_in.startswith("/show"):
                    console.print(Markdown(f"""
## Config
- Ollama URL `{generator_config.ollama_url}`
- Ollama Model `{generator_config.ollama_model}`
- Gemini Model `{generator_config.gemini_model}`
- OpenAI Model `{generator_config.openai_model}`

## Tools
{"\n".join(['- **' + tool.name + '(' + ', '.join(tool.parameters.keys()) + ')**: ' + tool.description for tool in tools])}
"""))
                    continue

                chat_logger(f"\n\n---\n\n# {datetime.datetime.now().isoformat()} Q: {user_in}\n\n")

                # special case of needing to bootstrap the pipeline with the correct prompt
                if pipe is None:
                    prompt = "\n".join(map(lambda e: e.get("text", ""),
                                           json.loads(prompt_chooser_tool.invoke(query=user_in)).get("content", [])))
                    if len(prompt) < 100:
                        # indicates an error because there should be a lot more text
                        console.print("🤖 " + prompt)
                        continue
                    console.print(Markdown(prompt))
                    console.print()
                    pipe, *_ = create_pipeline(prompt, tools)

                console.print("🤖 ", end="")

                # Build the pipeline input
                user_in_message = ChatMessage.from_user(user_in)
                run_input = {}
                try:
                    pipe.get_component("prompt_builder")
                    run_input["prompt_builder"] = {"query": [user_in_message]}
                except ValueError:
                    pass
                try:
                    pipe.get_component("memory_joiner")
                    run_input["memory_joiner"] = {"values": [user_in_message]}
                except ValueError:
                    pass

                # Run the pipeline
                try:
                    res = pipe.run(run_input)
                except PipelineRuntimeError as e:
                    print(str(e), file=sys.stderr)
                    continue

                # Process the output
                if "response_llm" in res:
                    replies = [user_in_message] + res["response_llm"]["replies"]
                elif "agent" in res:
                    replies = res["agent"]["messages"]
                else:
                    replies = []

                ans_md = "\n".join(replies[-1].texts)
                console.print("")
                console.print("")
                if not args.stream:
                    console.print(Markdown(ans_md))
                chat_logger(ans_md)
            except (KeyboardInterrupt, EOFError):
                break
            # except Exception as e:
            #     console.print(f"[red]Error: {e}")
    finally:
        console.print("[green]\n🧹 Cleaning up ...")
        if isinstance(tools, MCPToolset):
            tools.close()
        elif isinstance(tools, Iterable):
            for tool in tools:
                if hasattr(tool, "close"):
                    tool.close()
        console.print(f"[green]\n📜 History has been written to {args.history}")


if __name__ == "__main__":
    main()
