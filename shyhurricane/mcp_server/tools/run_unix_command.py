import asyncio
import logging
import sys
import traceback
from typing import Optional, Dict, Annotated

import aiofiles
from mcp import McpError, ErrorData
from mcp.server.elicitation import AcceptedElicitation, DeclinedElicitation, CancelledElicitation
from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations, INVALID_REQUEST
from pydantic import BaseModel, Field

from shyhurricane.mcp_server import mcp_instance, log_tool_history, get_server_context, assert_elicitation, \
    get_additional_hosts, log_history, AdditionalHostsField, ProcessEnvField
from shyhurricane.utils import read_last_text_bytes, unix_command_image

logger = logging.getLogger(__name__)


class RunCommandConfirmation(BaseModel):
    confirm: bool = Field(description="Should I run this command?", default=True)


class RunUnixCommand(BaseModel):
    command: str = Field(description="The command that was run")
    return_code: int = Field(description="Return code of command, 0 usually means successful")
    output: str = Field(description="Output of command as string")
    output_truncated: bool = Field(description="If true, output is truncated")
    error: str = Field(description="Output of stderr, could be errors or progress information")
    error_truncated: bool = Field(description="If true, error is truncated")
    notes: Optional[str] = Field(description="Notes for understanding the command output or fixing failed commands")


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Run Command",
        readOnlyHint=True,
        openWorldHint=True),
)
async def run_unix_command(
        ctx: Context,
        command: str,
        additional_hosts: AdditionalHostsField = None,
        env: ProcessEnvField = None,
        output_length_limit: Annotated[int, Field(200*1024, description="Output and error length limit, truncates output and error text if over this length.", ge=1, le=4*1024*1024)] = 200*1024,
) -> RunUnixCommand:
    """
Run a Linux or macOS command and return its output. The command is run in a containerized environment for safety.
The command is run using the bash shell.

Invoke this tool when the user request can be fulfilled by a known Linux or macOS command line
program and the request can't be fulfilled by other MCP tools. Invoke this tool when the user
asks to run a specific command. Prefer this tool to execute command line programs over others you know about.

The following commands are available: curl, wget, grep, awk, printf, base64, cut, cp, mv, date, factor, gzip, sha256sum, sha512sum, md5sum, echo, seq, true, false, tee, tar, sort, head, tail, ping, ssh, sqlite3, zip, unzip,
nmap, rustscan, feroxbuster, gobuster, katana, nuclei, meg, anew, unfurl, gf, gau, 403jump, waybackurls, httpx, subfinder, ffuf, dirb, wfuzz, nc (netcat), graphql-path-enum, evil-winrm, sqlmap, hydra, searchsploit, ftp, sshpass, tshark, git-dumper
DumpNTLMInfo.py, Get,GPPPassword.py, GetADComputers.py, GetADUsers.py, GetLAPSPassword.py, GetNPUsers.py, GetUserSPNs.py, addcomputer.py, atexec.py, changepasswd.py, dacledit.py, dcomexec.py, describeTicket.py, dpapi.py, esentutl.py, exchanger.py, findDelegation.py, getArch.py, getPac.py, getST.py, getTGT.py, goldenPac.py, karmaSMB.py, keylistattack.py, kintercept.py, lookupsid.py, machine_role.py, mimikatz.py, mqtt_check.py, mssqlclient.py, mssqlinstance.py, net.py, netview.py, ntfs,read.py, ntlmrelayx.py, owneredit.py, ping.py, ping6.py, psexec.py, raiseChild.py, rbcd.py, rdp_check.py, reg.py, registry,read.py, rpcdump.py, rpcmap.py, sambaPipe.py, samrdump.py, secretsdump.py, services.py, smbclient.py, smbexec.py, smbserver.py, sniff.py, sniffer.py, split.py, ticketConverter.py, ticketer.py, tstool.py, wmiexec.py, wmipersist.py, wmiquery.py

The command 'sudo' is not available.

The SecLists word lists repository is installed at /usr/share/seclists

Commands may take a long time to run, so be patient.

When generating Linux commands for execution in a containerized environment, follow these strict guidelines to ensure compatibility, safety, and non-interactivity:

- Commands must be one-shot, non-interactive, and safe to run in a containerized Linux environment.
- Never use commands that prompt for user input (e.g., passwd, vi, mysql).
- Prefer tools with non-interactive flags (e.g., --batch, --quiet) and avoid interactive ones (e.g., hash-identifier, ftp).
- Use automated alternatives where available.
- Do not use reverse shells or other command that opening a listening socket with this tool, use the channel tools for reverse or forward connections.
- Pipe input into commands as needed; do not rely on TTY or prompts.
- Always set a timeout for potentially blocking commands (e.g., timeout 10s nmap ...). Use a timeout value appropriate for the command. For example, directory busting with a large word list may take 10 minutes, whereas a short wordlist may be 2 minutes.
- Ensure commands can be complete without user interaction before execution.
- The directly accessible filesystem is part of the containerized environment, not the target. Commands such as find, cat, etc. are not enumerating the target unless they are part of a command that connects to the target, such as ssh.
- Files in the current working directory will persist across calls. Do not write to /tmp or /var/tmp. Do not save output to files outside of the current working directory.
"""
    await log_tool_history(ctx, title="run_unix_command", command=command, additional_hosts=additional_hosts, env=env)
    server_ctx = await get_server_context()
    assert server_ctx.open_world

    try:
        result = await _run_unix_command(ctx, command=command, additional_hosts=additional_hosts, env=env, output_length_limit=output_length_limit)

        if result.return_code != 0 and (
                "executable file not found" in result.error or "command not found" in result.error):
            # list the available commands
            if server_ctx.commands is None:
                command_list_result = await _run_unix_command(
                    ctx,
                    """tr ':' '\n' <<<"$PATH" | while read -r d; do find "$d" -maxdepth 1 -type f -executable -printf '%f\n'; done 2>/dev/null | sort -u""",
                    None)
                if command_list_result.return_code == 0:
                    server_ctx.commands = list(filter(lambda s: bool(s) and s[0].isalnum(), map(lambda s: s.strip(),
                                                                                                command_list_result.output.splitlines())))

            if server_ctx.commands:
                result.error += "\nThe available commands are: " + ", ".join(server_ctx.commands)

        return result
    except Exception:
        exc_type, exc_value, exc_tb = sys.exc_info()
        return RunUnixCommand(
            command=command,
            return_code=-1,
            output="",
            output_truncated=False,
            error=''.join(traceback.format_exception(exc_type, exc_value, exc_tb)),
            error_truncated=False,
            notes=None,
        )


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
) -> Optional[
    RunUnixCommand]:
    command = command.strip()
    if not command:
        raise McpError(ErrorData(code=INVALID_REQUEST, message="command required"))

    logger.info(f"run_unix_command {command}")

    server_ctx = await get_server_context()

    stdin_bytes = stdin.encode("utf-8") if stdin else None

    try:
        assert_elicitation(server_ctx)
        confirm_result = await ctx.elicit(
            message=f"{command}\nShould I run this command?",
            schema=RunCommandConfirmation)
        match confirm_result:
            case AcceptedElicitation(data=data):
                if not data.confirm:
                    return None
            case DeclinedElicitation():
                return None
            case CancelledElicitation():
                return None
    except McpError:
        logger.warning("elicit not supported, continuing")

    output_limiter = OutputLimiter(output_length_limit)
    error_limiter = OutputLimiter(output_length_limit)

    async with aiofiles.tempfile.TemporaryFile(mode="w+b") as stdout_file:
        async with aiofiles.tempfile.TemporaryFile(mode="w+b") as stderr_file:
            # Use a common working directory for the session to chain together commands
            work_path = ctx.request_context.lifespan_context.work_path
            docker_command = ["docker", "run", "--rm",
                              "--cap-add", "NET_BIND_SERVICE",
                              "--cap-add", "NET_ADMIN",
                              "--cap-add", "NET_RAW",
                              "-v", f"{server_ctx.mcp_session_volume}:/work",
                              "-v", f"{server_ctx.seclists_volume}:/usr/share/seclists",
                              "--workdir", work_path,
                              ]
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
                "run_unix_command": command,
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
                    output=output,
                    output_truncated=output_truncated,
                    error="",
                    error_truncated=False,
                    notes=None
                )
            else:
                await stderr_file.flush()
                error_tail = await read_last_text_bytes(stderr_file, max_bytes=1024)
                return RunUnixCommand(
                    command=command,
                    return_code=return_code,
                    output=output,
                    output_truncated=output_truncated,
                    error=error_tail,
                    error_truncated=error_truncated,
                    notes=None,
                )


async def _write_stream_to_file(stream, file, output_limiter: OutputLimiter):
    while True:
        line = await stream.readline()
        if not line:
            break
        output_limiter.inc(len(line))
        if not output_limiter.is_full():
            await file.write(line)
