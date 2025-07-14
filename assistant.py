#!/usr/bin/env python3
"""
Cybersecurity offense assistant.
"""
import argparse
import logging
import os
import sys
from pathlib import Path

from haystack.core.errors import PipelineRuntimeError
from haystack.dataclasses import ChatMessage, StreamingChunk
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from rich import get_console
from rich.markdown import Markdown

from pipeline import build_chat_pipeline, build_agent_pipeline
from utils import add_generator_args, GeneratorConfig

os.environ['PYTORCH_ENABLE_MPS_FALLBACK'] = '1'
os.environ['ANONYMIZED_TELEMETRY'] = "False"
os.environ['HAYSTACK_TELEMETRY_ENABLED'] = "False"
os.environ['HAYSTACK_TELEMETRY_DISABLED'] = "1"

logger = logging.getLogger(__name__)

console = get_console()


def configure_logging(level=logging.CRITICAL):
    for name in [
        "haystack",  # core
        "haystack_integrations",  # all integrations
        "haystack_telemetry",  # optional telemetry
        "chromadb",  # Chroma client (can be noisy)
        "sentence_transformers",
    ]:
        logging.getLogger(name).setLevel(level)


def streaming_chunk_callback(chunk: StreamingChunk):
    console.print(chunk.content, end="")
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
        console.print(f"\n🛑 {chunk.finish_reason}")


def main():
    ap = argparse.ArgumentParser()
    # ap.add_argument("--db", default="chroma_store")
    ap.add_argument(
        "--mode",
        choices=["chat", "agent"],
        default="chat",
        help="AI mode to use: chat or agent"
    )
    ap.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")
    add_generator_args(ap)
    ap.add_argument("--mcp-url", required=False, help="URL for the MCP server, i.e. http://127.0.0.1:8000/mcp/")
    ap.add_argument("--stream", action="store_true")
    ap.add_argument("--history", default="chat_history.md")
    args = ap.parse_args()

    if args.verbose:
        configure_logging(logging.INFO)
    else:
        configure_logging(logging.CRITICAL)

    generator_config = GeneratorConfig.from_args(args)

    if args.mode == "agent":
        args.stream = True
        pipe, generator, tools = build_agent_pipeline(generator_config, args.mcp_url)
    else:
        pipe, generator, tools = build_chat_pipeline(generator_config, args.mcp_url)

    if args.stream and generator is not None:
        generator.streaming_callback = streaming_chunk_callback

    prompt_history_path = Path(Path.home(), ".local", "state", "web_rag", "prompt_history")
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

    def chat_logger(q, a):
        Path(args.history).touch(mode=0o644, exist_ok=True)
        with open(args.history, "a", encoding="utf-8") as f:
            f.write(f"# Q: {q}\n\n{a}\n\n---\n\n")

    chat_logger("Assistant Info", f"{args.mode} mode using {generator_config.describe()}")

    while True:
        try:
            user_in = sess.prompt("💬 ")
            # TODO: clear tool cache
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

            console.print("🧠 ", end="")

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
            if not args.stream:
                console.print(Markdown(ans_md))
            chat_logger(user_in, ans_md)
        except (KeyboardInterrupt, EOFError):
            break
        # except Exception as e:
        #     console.print(f"[red]Error: {e}")
    console.print(f"[green]\n📜 History has been written to {args.history}")


if __name__ == "__main__":
    main()
