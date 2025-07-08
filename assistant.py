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
from haystack.dataclasses import ChatMessage
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from rich import get_console
from rich.markdown import Markdown

from pipeline import build_chat_pipeline, build_agent_pipeline

# 1. Mute Haystack and integrations
for name in [
    "haystack",  # core
    "haystack_integrations",  # all integrations
    "haystack_telemetry",  # optional telemetry
    "chromadb",  # Chroma client (can be noisy)
    "sentence_transformers",
]:
    logging.getLogger(name).setLevel(logging.CRITICAL)  # or logging.CRITICAL

os.environ['PYTORCH_ENABLE_MPS_FALLBACK'] = '1'
os.environ['ANONYMIZED_TELEMETRY'] = "False"
os.environ['HAYSTACK_TELEMETRY_ENABLED'] = "False"
os.environ['HAYSTACK_TELEMETRY_DISABLED'] = "1"

logger = logging.getLogger(__name__)

console = get_console()


def main():
    ap = argparse.ArgumentParser()
    # ap.add_argument("--db", default="chroma_store")
    ap.add_argument(
        "--mode",
        choices=["chat", "agent"],
        default="chat",
        help="AI mode to use: chat or agent"
    )
    ap.add_argument("--ollama-url", default="http://localhost:11434")
    ap.add_argument("--ollama-model", default="llama3.1")
    ap.add_argument("--stream", action="store_true")
    ap.add_argument("--history", default="chat_history.md")
    args = ap.parse_args()

    top_k = 100

    if args.mode == "agent":
        pipe, generator, tools = build_agent_pipeline(args.ollama_url, args.ollama_model)
    else:
        pipe, generator, tools = build_chat_pipeline(args.ollama_url, args.ollama_model)

    if args.stream and generator is not None:
        generator.streaming_callback = lambda chunk: print(chunk.content, end="")

    prompt_history_path = Path(Path.home(), ".local", "state", "web_rag", "prompt_history")
    os.makedirs(prompt_history_path.parent, mode=0o755, exist_ok=True)
    sess = PromptSession(history=FileHistory(os.fspath(prompt_history_path)),
                         # completer=WordCompleter(["/set","/show","/reload","/exit","/quit"], ignore_case=True)
                         )
    console.print("🛡️  Ready. Commands: /show • /exit\n")

    def chat_logger(q, a):
        Path(args.history).touch(mode=0o644, exist_ok=True)
        with open(args.history, "a", encoding="utf-8") as f:
            f.write(f"# Q: {q}\n\n{a}\n\n---\n\n")

    messages: list[ChatMessage] = []

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
- DB `{args.db}`
- Ollama URL `{args.ollama_url}`
- Ollama Model `{args.ollama_model}`

## Tools
{"\n".join(['- **' + tool.name + '(' + ', '.join(tool.parameters.keys()) + ')**: ' + tool.description for tool in tools])}
"""))
                continue

            print("🧠 ", end="", flush=True)

            # Build the pipeline input
            user_in_message = ChatMessage.from_user(user_in)
            messages.append(user_in_message)
            run_input = {}
            # TODO: use haystack-ai to introspect inputs/outputs
            try:
                pipe.get_component("llm")
                run_input["llm"] = {"messages": messages}
            except ValueError:
                pass
            try:
                pipe.get_component("list_joiner")
                run_input["list_joiner"] = {"values": [user_in_message]}
            except ValueError:
                pass
            try:
                pipe.get_component("prompt_builder")
                run_input["prompt_builder"] = {"template": [user_in_message]}
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
                messages = res["response_llm"]["replies"]
            elif "agent" in res:
                messages = res["agent"]["messages"]
            ans_md = "\n".join(messages[-1].texts)
            if args.stream:
                print()
            else:
                console.print(Markdown(ans_md))
            chat_logger(user_in, ans_md)
        except (KeyboardInterrupt, EOFError):
            break
        # except Exception as e:
        #     console.print(f"[red]Error: {e}")
    console.print(f"[green]\n📜 History has been written to {args.history}")


if __name__ == "__main__":
    main()
