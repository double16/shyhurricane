from enum import Enum
from typing import Callable, Dict, Optional

from haystack.dataclasses import StreamingChunk, ToolCallResult, ToolCallDelta


class ToolProcessState(Enum):
    PENDING = 0
    RUNNING = 1
    FINISHED = 2
    FAILED = 3


class LastOutputSource(Enum):
    NONE = 0
    CONTENT = 1
    TOOL = 2
    SYSTEM = 3


class ToolProcess:
    def __init__(self, tool_name: str, index: int):
        self.tool_name = tool_name
        self.index = index
        self.arguments = ""
        self.state = ToolProcessState.PENDING

    def key(self):
        return self.index

    def function_call(self) -> str:
        result = f"{self.tool_name}({self.arguments})"
        if self.state == ToolProcessState.PENDING:
            result = "🕰 " + result
        elif self.state == ToolProcessState.RUNNING:
            result = "🔄 " + result
        elif self.state == ToolProcessState.FINISHED:
            result = "✅ " + result
        elif self.state == ToolProcessState.FAILED:
            result = "❌ " + result

        return result


class StreamingChunkWriter:
    def __init__(self, printer: Callable[[str], None], verbose: bool = False):
        self.printer = printer
        self.verbose = verbose
        self.tool_call_str = ""
        self.tool_call_index = -1
        self.processes: Dict[int, ToolProcess] = {}
        self.on_newline = True
        self.on_doublespace = False
        self.last_output_source: LastOutputSource = LastOutputSource.NONE

    def output(self, content: str, force_newline: bool = False):
        if not content:
            return

        # prevent excessive new lines
        if self.on_newline and content == "\n":
            return

        if force_newline and not self.on_newline:
            self.printer("\n")
            self.on_newline = True

        self.on_newline = content.endswith("\n")
        self.on_doublespace = False
        self.printer(content)

    def double_space(self, output_source: LastOutputSource):
        if self.last_output_source == LastOutputSource.NONE:
            self.last_output_source = output_source
            return
        if self.last_output_source == output_source:
            return
        self.last_output_source = output_source
        if self.on_doublespace:
            return
        if not self.on_newline:
            self.printer("\n\n")
            self.on_newline = True
        else:
            self.printer("\n")
        self.on_doublespace = True

    def _running(self, tool: ToolCallDelta) -> ToolProcess:
        return self.processes.setdefault(tool.index, ToolProcess(tool.tool_name, tool.index))

    def _finished(self, index: int, tool: ToolCallResult) -> Optional[ToolProcess]:
        try:
            return self.processes.pop(index)
        except KeyError:
            return None

    def callback(self, chunk: StreamingChunk):
        # with open("streaming.log", "at") as f:
        #     f.write(repr(chunk))
        #     f.write("\n")

        content = ' '.join(filter(bool, [chunk.content, chunk.meta.get("thinking", None)]))
        if content:
            self.double_space(LastOutputSource.CONTENT)
            self.output(content)

        for tool_call in (chunk.tool_calls or []):
            if chunk.start:
                tool_process = self._running(tool_call)
                tool_process.arguments = tool_call.arguments or ""
            else:
                tool_process = self.processes.get(tool_call.index, None)
                if tool_process:
                    tool_process.arguments += tool_call.arguments

        if chunk.tool_call_result:
            tool_process = self._finished(chunk.index, chunk.tool_call_result)
            if chunk.tool_call_result.error:
                tool_process.state = ToolProcessState.FAILED
            else:
                tool_process.state = ToolProcessState.FINISHED
            self.double_space(LastOutputSource.TOOL)
            self.output(f"{tool_process.function_call()}\n", force_newline=True)

        if chunk.finish_reason in ["tool_calls", "stop"]:
            for tool_process in self.processes.values():
                tool_process.state = ToolProcessState.RUNNING
                self.double_space(LastOutputSource.TOOL)
                self.output(f"{tool_process.function_call()}\n", force_newline=True)

        if chunk.finish_reason == "stop":
            self.output("\n")

        if chunk.finish_reason == "length":
            self.double_space(LastOutputSource.SYSTEM)
            self.output("🛑 run out of model context\n", force_newline=True)
