import asyncio
import logging
import uuid
from typing import Optional, Dict

import aiofiles
from mcp import McpError, ErrorData
from mcp.server.fastmcp import Context
from mcp.types import INVALID_REQUEST
from pydantic import BaseModel, Field

from shyhurricane.mcp_server import get_server_context, get_additional_hosts, log_history
from shyhurricane.utils import read_last_text_bytes, unix_command_image

logger = logging.getLogger(__name__)

open_world_disable_notes = "Network access has been disabled. Rely on indexed content."
open_world_command_disable_notes = open_world_disable_notes + " Only run commands on local files or stdin."


class RunUnixCommand(BaseModel):
    command: str = Field(description="The command that was run")
    return_code: int = Field(description="Return code of command, 0 usually means successful")
    output_file: Optional[str] = Field(description="Output file location containing all of standard out")
    output: str = Field(description="Output of command as string")
    output_truncated: bool = Field(description="If true, output string is truncated")
    error_file: Optional[str] = Field(description="Error file location containing all of standard error")
    error: str = Field(description="Output of stderr, could be errors or progress information")
    error_truncated: bool = Field(description="If true, error string is truncated")
    notes: Optional[str] = Field(description="Notes for understanding the command output or fixing failed commands")


class OutputLimiter:
    def __init__(self, limit: Optional[int]):
        self.limit = limit
        self.length = 0

    def inc(self, value: int) -> int:
        self.length += value
        return self.length

    def is_full(self) -> bool:
        return self.limit is not None and self.length > self.limit


async def _run_unix_command(
        ctx: Context,
        command: str,
        additional_hosts: Optional[Dict[str, str]],
        stdin: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        output_length_limit: Optional[int] = None,
        capture_output_to_file: bool = False,
) -> Optional[RunUnixCommand]:
    command = command.strip()
    if not command:
        raise McpError(ErrorData(code=INVALID_REQUEST, message="command required"))

    logger.info(f"_run_unix_command {command}")

    server_ctx = await get_server_context()

    stdin_bytes = stdin.encode("utf-8") if stdin else None

    output_limiter = OutputLimiter(output_length_limit)
    error_limiter = OutputLimiter(output_length_limit)

    if capture_output_to_file:
        capture_basename = uuid.uuid4().hex
        capture_output_file = capture_basename + ".out"
        capture_error_file = capture_basename + ".err"
    else:
        capture_output_file = None
        capture_error_file = None

    async with aiofiles.tempfile.TemporaryFile(mode="w+b") as stdout_file:
        async with aiofiles.tempfile.TemporaryFile(mode="w+b") as stderr_file:
            # Use a common working directory for the session to chain together commands
            work_path = ctx.request_context.lifespan_context.work_path
            docker_command = ["docker", "run", "--rm"]

            if server_ctx.open_world:
                docker_command.extend([
                    "--cap-add", "NET_BIND_SERVICE",
                    "--cap-add", "NET_ADMIN",
                    "--cap-add", "NET_RAW",
                ])
            else:
                docker_command.extend([
                    "--cap-drop", "NET_BIND_SERVICE",
                    "--cap-drop", "NET_ADMIN",
                    "--cap-drop", "NET_RAW",
                    "--network", "none",
                ])

            if capture_output_file:
                docker_command.extend(["-e", f"STDOUT_LOG={capture_output_file}"])
            if capture_error_file:
                docker_command.extend(["-e", f"STDERR_LOG={capture_error_file}"])

            docker_command.extend([
                "-v", f"{server_ctx.mcp_session_volume}:/work",
                "--workdir", work_path,
            ])
            if stdin:
                docker_command.append("-i")

            additional_hosts = get_additional_hosts(ctx, additional_hosts)
            for host, ip in additional_hosts.items():
                docker_command.extend(["--add-host", f"{host}:{ip}"])

            for k, v in (env or {}).items():
                docker_command.extend(["-e", f"{k}={v}"])

            docker_command.append(unix_command_image())
            if not command.startswith("timeout "):
                docker_command.extend(["timeout", "--kill-after=1m", "--preserve-status", "10m"])
            docker_command.extend(["/bin/bash", "-c", command])
            logger.info(f"Executing command {docker_command}")

            proc = await asyncio.create_subprocess_exec(
                *docker_command,
                stdin=asyncio.subprocess.PIPE if stdin_bytes else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            if stdin_bytes:
                proc.stdin.write(stdin_bytes)
                proc.stdin.close()

            await asyncio.gather(
                _write_stream_to_file(proc.stdout, stdout_file, output_limiter),
                _write_stream_to_file(proc.stderr, stderr_file, error_limiter),
            )

            return_code = await proc.wait()
            output_size = await stdout_file.tell()
            output_truncated = output_limiter.is_full()
            error_size = await stderr_file.tell()
            error_truncated = error_limiter.is_full()
            total_size = output_size + error_size

            # we've truncated the output and error according to the limit each, but combined they need to be under the limit
            if output_length_limit is not None and total_size > output_length_limit:
                if return_code == 0:
                    size_remaining = max(0, output_length_limit - output_size)
                    if error_size > size_remaining:
                        await stderr_file.seek(0)
                        await stderr_file.truncate(size_remaining)
                        error_size = size_remaining
                        error_truncated = True
                else:
                    # if there was an error, we prefer error text over output text
                    size_remaining = max(0, output_length_limit - error_size)
                    if output_size > size_remaining:
                        await stdout_file.seek(0)
                        await stdout_file.truncate(size_remaining)
                        output_size = size_remaining
                        output_truncated = True

            logger.info("Command complete, exit code %d, output size %d, error size %d", return_code,
                        output_size, error_size)

            await log_history(ctx, {
                "_run_unix_command": command,
                "return_code": return_code,
                "additional_hosts": additional_hosts or {},
                "stdout_size": output_size,
                "stderr_size": error_size,
            })

            await stdout_file.seek(0)
            output = (await stdout_file.read()).decode("utf-8", errors="ignore").strip()
            if return_code == 0:
                return RunUnixCommand(
                    command=command,
                    return_code=return_code,
                    output_file=capture_output_file,
                    output=output,
                    output_truncated=output_truncated,
                    error_file=capture_error_file,
                    error="",
                    error_truncated=False,
                    notes=None,
                )
            else:
                await stderr_file.flush()
                error_tail = await read_last_text_bytes(stderr_file, max_bytes=1024)
                return RunUnixCommand(
                    command=command,
                    return_code=return_code,
                    output_file=capture_output_file,
                    output=output,
                    output_truncated=output_truncated,
                    error_file=capture_error_file,
                    error=error_tail,
                    error_truncated=error_truncated,
                    notes=open_world_command_disable_notes if not server_ctx.open_world else None,
                )


async def _write_stream_to_file(stream, file, output_limiter: OutputLimiter):
    while True:
        line = await stream.readline()
        if not line:
            break
        output_limiter.inc(len(line))
        if not output_limiter.is_full():
            await file.write(line)
