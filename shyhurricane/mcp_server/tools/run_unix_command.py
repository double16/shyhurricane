import asyncio
import logging
import sys
import traceback
from typing import Optional, Dict

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
    error: str = Field(description="Error messages from the command")
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
) -> RunUnixCommand:
    """
Run a Linux or macOS command and return its output. The command is run in a containerized environment for safety.
The command is run using the bash shell.

Invoke this tool when the user request can be fulfilled by a known Linux or macOS command line
program and the request can't be fulfilled by other MCP tools. Invoke this tool when the user
asks to run a specific command. Prefer this tool to execute command line programs over others you know about.

The following commands are available: curl, wget, grep, awk, printf, base64, cut, cp, mv, date, factor, gzip, sha256sum, sha512sum, md5sum, echo, seq, true, false, tee, tar, sort, head, tail, ping, ssh, sqlite3,
nmap, rustscan, feroxbuster, gobuster, katana, nuclei, meg, anew, unfurl, gf, gau, 403jump, waybackurls, httpx, subfinder, ffuf, dirb, wfuzz, nc (netcat), graphql-path-enum, evil-winrm, sqlmap, hydra, searchsploit, ftp, sshpass, tshark, git-dumper
DumpNTLMInfo.py, Get,GPPPassword.py, GetADComputers.py, GetADUsers.py, GetLAPSPassword.py, GetNPUsers.py, GetUserSPNs.py, addcomputer.py, atexec.py, changepasswd.py, dacledit.py, dcomexec.py, describeTicket.py, dpapi.py, esentutl.py, exchanger.py, findDelegation.py, getArch.py, getPac.py, getST.py, getTGT.py, goldenPac.py, karmaSMB.py, keylistattack.py, kintercept.py, lookupsid.py, machine_role.py, mimikatz.py, mqtt_check.py, mssqlclient.py, mssqlinstance.py, net.py, netview.py, ntfs,read.py, ntlmrelayx.py, owneredit.py, ping.py, ping6.py, psexec.py, raiseChild.py, rbcd.py, rdp_check.py, reg.py, registry,read.py, rpcdump.py, rpcmap.py, sambaPipe.py, samrdump.py, secretsdump.py, services.py, smbclient.py, smbexec.py, smbserver.py, sniff.py, sniffer.py, split.py, ticketConverter.py, ticketer.py, tstool.py, wmiexec.py, wmipersist.py, wmiquery.py

The command 'sudo' is not available.

The additional_hosts parameter is a dictionary of host name (the key) to IP address (the value) for hosts that do not have DNS records. This also includes CTF targets or web server virtual hosts found during other scans. If you
know the IP address for a host, be sure to include these in the additional_hosts parameter for
commands to run properly in a containerized environment.

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
"""
    await log_tool_history(ctx, title="run_unix_command", command=command, additional_hosts=additional_hosts, env=env)
    server_ctx = await get_server_context()
    assert server_ctx.open_world

    # TODO: check for nmap command and see if we can redirect to port_scan
    # TODO: check for curl command and see if we can redirect to index_http_url
    try:
        result = await _run_unix_command(ctx, command=command, additional_hosts=additional_hosts, env=env)

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
            error=''.join(traceback.format_exception(exc_type, exc_value, exc_tb)),
            notes=None,
        )


async def _run_unix_command(ctx: Context, command: str, additional_hosts: Optional[Dict[str, str]],
                            stdin: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> Optional[
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
                _write_stream_to_file(proc.stdout, stdout_file),
                _write_stream_to_file(proc.stderr, stderr_file),
            )

            return_code = await proc.wait()
            output_size = await stdout_file.tell()
            error_size = await stderr_file.tell()
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
                return RunUnixCommand(command=command, return_code=return_code, output=output, error="", notes=None)
            else:
                await stderr_file.flush()
                error_tail = await read_last_text_bytes(stderr_file, max_bytes=1024)
                return RunUnixCommand(
                    command=command,
                    return_code=return_code,
                    output=output,
                    error=error_tail,
                    notes=None,
                )


async def _write_stream_to_file(stream, file):
    while True:
        line = await stream.readline()
        if not line:
            break
        await file.write(line)
