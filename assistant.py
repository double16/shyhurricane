#!/usr/bin/env python3
import argparse
import datetime
import json
import logging
import os
import sys
import traceback
from pathlib import Path
from typing import Iterable, Tuple, List

from haystack import Pipeline
from haystack.core.component import Component
from haystack.core.errors import PipelineRuntimeError
from haystack.dataclasses import ChatMessage
from haystack.tools import Tool
from haystack_integrations.tools.mcp import MCPToolset
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from rich import get_console
from rich.markdown import Markdown

from shyhurricane.config import configure
from shyhurricane.generator_config import GeneratorConfig, add_generator_args
from shyhurricane.mcp_server.generator_config import set_generator_config
from shyhurricane.retrieval_pipeline import build_chat_pipeline, build_agent_pipeline, create_tools
from shyhurricane.streaming_chunk_writer import StreamingChunkWriter

logger = logging.getLogger(__name__)

configure()

console = get_console()


def configure_logging(level=logging.CRITICAL):
    logging.getLogger().setLevel(level)


def prompt_multiline(session: PromptSession) -> str:
    history = session.history
    session.history = None
    try:
        line = session.prompt("💬 ").strip()
        if len(line) > 6 and line.startswith('"""') and line.endswith('"""'):
            full_input = line[3:-3]
        elif line.startswith('"""'):
            # Start collecting multiline input
            lines = []
            if len(line) > 3:
                lines.append(line[3:])
            while True:
                next_line = session.prompt("💬... ").strip()
                if next_line.endswith('"""'):
                    if len(next_line) > 3:
                        lines.append(next_line[:-3])
                    break
                lines.append(next_line)
            full_input = "\n".join(lines)
        else:
            full_input = line

        if history is not None:
            if "\n" in full_input:
                history.append_string(f'"""\n{full_input}\n"""')
            else:
                history.append_string(full_input)

        return full_input
    finally:
        session.history = history


def main():
    chat_history_default = datetime.date.today().isoformat() + "_history.md"

    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")
    add_generator_args(ap)
    ap.add_argument("--mcp-url", nargs="+", required=False,
                    help="URL for the MCP server, i.e. http://127.0.0.1:8000/mcp/")
    ap.add_argument("--no-stream", action="store_true", help="Force disabling of streaming messages")
    ap.add_argument("--history", default=chat_history_default)
    ap.add_argument("--run-and-exit", required=False, nargs="+", type=str, help="Run the prompts and exit (intended for demos)")
    args = ap.parse_args()

    if args.verbose:
        configure_logging(logging.INFO)
    else:
        configure_logging(logging.CRITICAL)

    generator_config = GeneratorConfig.from_args(args).apply_reasoning_default().check()
    set_generator_config(generator_config)

    raw_tools = create_tools(args.mcp_url)
    tools: List[Tool] = []
    prompt_chooser_tool = None
    prompt_titles = []
    for tool in raw_tools:
        if tool.name == "prompt_chooser":
            prompt_chooser_tool = tool
        elif tool.name == "prompt_list":
            prompt_titles = json.loads(tool.invoke()).get("structuredContent", {}).get("titles", [])
        else:
            # filter out the prompt tools because some LLMs aren't smart enough to ignore them
            tools.append(tool)
    if not prompt_chooser_tool:
        console.print("[red]No prompt_chooser tool found[/red]")
        sys.exit(1)

    def chat_logger(line, output_timestamp: bool = False):
        if not line:
            return
        Path(args.history).touch(mode=0o644, exist_ok=True)
        with open(args.history, "a", encoding="utf-8") as f:
            if output_timestamp:
                f.write("\n`")
                f.write(datetime.datetime.now().astimezone().isoformat())
                f.write("`\n\n")
            f.write(line)

    def streaming_chunk_printer(line: str):
        console.print(line, end="")
        chat_logger(line, output_timestamp=True)

    def create_pipeline(system_prompt: str, tools: List[Tool]) -> Tuple[Pipeline, Component, List[Tool]]:
        system_prompt_lower = system_prompt.lower()
        if "autonomous" in system_prompt_lower or "automated" in system_prompt_lower:
            pipe, generator, _ = build_agent_pipeline(generator_config, system_prompt, args.mcp_url, tools)
        else:
            pipe, generator, _ = build_chat_pipeline(generator_config, system_prompt, args.mcp_url, tools)

        if not args.no_stream and generator is not None:
            generator.streaming_callback = StreamingChunkWriter(printer=streaming_chunk_printer,
                                                                verbose=bool(args.verbose)).callback

        return pipe, generator, tools

    pipe = None

    prompt_history_path = Path(Path.home(), ".local", "state", "shyhurricane", "prompt_history")
    os.makedirs(prompt_history_path.parent, mode=0o755, exist_ok=True)
    sess = PromptSession(history=FileHistory(os.fspath(prompt_history_path)),
                         # completer=WordCompleter(["/set","/show","/reload","/exit","/quit"], ignore_case=True)
                         )
    console.print(f"""
This is a penetration test assistant using {generator_config.describe()}. You can say things like:
- Solve the CTF challenge on 192.168.1.1
- Look for vulnerabilities on http://192.168.1.1
- Multi-line prompts can be entered by starting and ending with \"\"\"
- Available prompts (chosen automatically): {", ".join(prompt_titles)}
""")
    console.print("🛡️  Ready. Commands: /show • /tools • /exit\n")

    chat_logger(f"Assistant Info\n\n{generator_config.describe()}", output_timestamp=True)

    if args.run_and_exit:
        prompt_queue = list(args.run_and_exit)
    else:
        prompt_queue = None

    try:
        while prompt_queue is None or len(prompt_queue) > 0:
            try:
                if prompt_queue is not None:
                    user_in = prompt_queue.pop(0)
                    console.print("💬 "+user_in)
                else:
                    user_in = prompt_multiline(sess)
                if not user_in.strip():
                    continue
                if user_in.lower() in {"/exit", "/quit"}:
                    break
                if user_in.startswith("/show"):
                    console.print(Markdown(f"""
## Config
- Ollama Host `{generator_config.ollama_host}`
- Ollama Model `{generator_config.ollama_model}`
- Gemini Model `{generator_config.gemini_model}`
- OpenAI Model `{generator_config.openai_model}`

## Prompts
{"\n".join(['- ' + title for title in prompt_titles])}
"""))
                    continue
                if user_in.startswith("/tools"):
                    console.print(Markdown(f"""
## Tools
{"\n".join(['- **' + tool.name + '(' + ', '.join(tool.parameters.keys()) + ')**: ' + tool.description for tool in tools])}
"""))
                    continue

                chat_logger(f"\n\n---\n\n# {datetime.datetime.now().isoformat()} Q: {user_in}\n\n",
                            output_timestamp=True)

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
                    tb = traceback.TracebackException.from_exception(e)
                    print(''.join(tb.format()), file=sys.stderr)
                    continue
                except KeyboardInterrupt:
                    console.print("[red]\nUser stopped the current agent run, Ctrl-C again to exit or continue with more instructions.")
                    continue

                # Process the output
                if "response_llm" in res:
                    replies = res["response_llm"]["replies"]
                elif "agent" in res:
                    replies = res["agent"]["messages"]
                else:
                    replies = []

                ans_md = "\n".join([text for reply in replies for text in reply.texts])
                console.print("")
                console.print("")
                if args.no_stream:
                    console.print(Markdown(ans_md))
                chat_logger(ans_md, output_timestamp=True)
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
