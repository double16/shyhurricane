import asyncio
import base64
import logging
import time
from typing import Dict, Optional, List, Literal, Annotated

from pydantic import BaseModel, Field
from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations

from shyhurricane.channels import PollEvent, Channel, ChannelManager
from shyhurricane.mcp_server import mcp_instance, log_tool_history, AdditionalHostsField, get_server_context, \
    get_additional_hosts, ProcessEnvField
from shyhurricane.pick_nic import pick_local_addr
from shyhurricane.utils import b64, unix_command_image, coerce_to_dict

logger = logging.getLogger(__name__)


class CreateForwardResult(BaseModel):
    channel_id: str = Field(description="New channel id; persist this for later calls.")
    kind: Literal["forward", "reverse"] = Field(description="Channel type.")
    created_at: float = Field(description="Unix epoch seconds.")
    pid: int = Field(description="Process ID holding the forward channel.")


class CreateReverseResult(BaseModel):
    channel_id: str = Field(description="New channel id; persist this for later calls.")
    kind: Literal["forward", "reverse"] = Field(description="Channel type.")
    created_at: float = Field(description="Unix epoch seconds.")
    listen_address: str = Field(description="Address on which the reverse channel is listening")
    listen_port: int = Field(description="Port on which the reverse channel is listening")


class PollResult(BaseModel):
    channel_id: str = Field(description="Echo channel id.")
    closed: bool = Field(description="True if channel has been closed.")
    events: List[PollEvent] = Field(description="Events since last poll (consumed on delivery).")


class SendResult(BaseModel):
    channel_id: str = Field(description="Echo channel id.")
    bytes_sent: int = Field(description="Bytes written to stdin.")


class CloseResult(BaseModel):
    channel_id: str = Field(description="Echo channel id.")
    success: bool = Field(description="True if the channel existed and is now closed.")


class StatusResult(BaseModel):
    channel_id: str = Field(description="Echo channel id.")
    kind: Literal["forward", "reverse"] = Field(description="Channel type.")
    connected: bool = Field(
        description=(
            "Forward: True if process started and not closed. "
            "Reverse: True if a client is currently connected."
        )
    )
    ready_for_send: bool = Field(
        description=(
            "True if writing to stdin should succeed now. "
            "Forward: stdin pipe open; Reverse: client connected."
        )
    )
    details: Dict[str, str] = Field(
        description=(
            "Additional state hints. Forward includes {'pid': '<pid>', 'proc_alive': 'true/false'}. "
            "Reverse includes {'listening': 'true/false', 'client_connected': 'true/false', 'port': '<port>'} when known."
        )
    )


async def _read_output(reader: asyncio.StreamReader, ch: Channel, chunk: int = 65536):
    try:
        while True:
            data = await reader.read(chunk)
            if not data:
                break
            await ch.put_event(PollEvent(ts=time.time(), stream="output", data_b64=b64(data)))
    except asyncio.CancelledError:
        raise
    except Exception as e:
        await ch.mark_status(f"output_reader_error: {e!r}")
    finally:
        await ch.mark_status("output_eof")
        await ch.close()


def _mgr(ctx: Context) -> ChannelManager:
    return ctx.request_context.lifespan_context.channel_manager


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Create a forward Channel",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True),
)
async def channel_create_forward(
        ctx: Context,
        command: Annotated[str, Field(
            description=(
                    "Command to execute in a bash shell, shell expansion is supported. "
                    "Example: 'sshpass -p passw0rd ssh user@host'.\n"
                    "Usage: channel_create_forward → save channel_id → loop channel_poll for output → "
                    "channel_send to write stdin → channel_close when done."
            ),
        )],
        env: ProcessEnvField = None,
        additional_hosts: AdditionalHostsField = None,
) -> CreateForwardResult:
    """
  ## Forward Channel Instructions

  To create and use a forward channel backed by a local subprocess (stdout and stderr merged), follow this sequence of MCP tool calls:

  1. **Create forward channel**
     - Tool: `channel_create_forward`
     - Args: `cmd=['nc','target.local','8080']`
     - Response: use the returned `channel_id`.

  2. **Check status (optional)**
     - Tool: `channel_status`
     - Args: `channel_id`
     - Use to confirm readiness if needed.

  3. **Receive output**
     - Tool: `channel_poll`
     - Args: `channel_id`, `timeout=5`, `min_events=1`

  4. **Send data**
     - Tool: `channel_send`
     - Args: `channel_id`, `mode='text'`, `data='help'`, `append_newline=True`

  5. **Close channel**
     - Tool: `channel_close`
     - Args: `channel_id`

  ## Important
  - Never output example code.
  - Always use tool calls directly.
  - Treat the above as a required sequence of MCP operations, not programming tasks.
  - Commands are run on the local machine, not the target. Only use commands that will connect to the target such as ssh, nc, etc.
"""

    # coerce types
    additional_hosts = coerce_to_dict(additional_hosts)
    env = coerce_to_dict(env)

    await log_tool_history(ctx, "channel_create_forward", command=command, env=env, additional_hosts=additional_hosts)
    server_ctx = await get_server_context()

    mgr = _mgr(ctx)
    cid = mgr.new_id()

    # Use a common working directory for the session to chain together commands
    work_path = ctx.request_context.lifespan_context.work_path
    docker_command = ["docker", "run", "--rm",
                      "--cap-add", "NET_BIND_SERVICE",
                      "--cap-add", "NET_ADMIN",
                      "--cap-add", "NET_RAW",
                      "-v", f"{server_ctx.mcp_session_volume}:/work",
                      "-v", f"{server_ctx.seclists_volume}:/usr/share/seclists",
                      "--workdir", work_path,
                      "-i",
                      ]
    additional_hosts = get_additional_hosts(ctx, additional_hosts)
    for host, ip in additional_hosts.items():
        docker_command.extend(["--add-host", f"{host}:{ip}"])

    for k, v in (env or {}).items():
        docker_command.extend(["-e", f"{k}={v}"])

    docker_command.append(unix_command_image())
    docker_command.extend(["/bin/bash", "-c", command])

    logger.info("Creating a forward channel with command: %s", ' '.join(docker_command))

    proc = await asyncio.create_subprocess_exec(
        *docker_command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,  # merge
    )

    ch = Channel(id=cid, kind="forward", proc=proc)
    await ch.mark_status(f"process_started_pid_{proc.pid}")

    if proc.stdout:
        ch._output_task = asyncio.create_task(_read_output(proc.stdout, ch))

    mgr.add(ch)
    return CreateForwardResult(
        channel_id=cid,
        kind="forward",
        created_at=ch.created_at,
        pid=proc.pid,
    )


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Wait for a reverse Channel",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True),
)
async def channel_create_reverse(
        ctx: Context,
        listener_host: Annotated[str, Field(
            "0.0.0.0",
            description=(
                    "Interface to bind the reverse channel listener (single duplex client).\n"
                    "Usage: channel_create_reverse → get {host,port} → remote connects → "
                    "wait for 'client_connected' via channel_poll → exchange data via channel_send/poll."
            ),
        )],
        listener_port: Annotated[int, Field(
            0,
            description=(
                    "TCP port to listen on (0 = ephemeral; actual port in result.listen_port). "
                    "Poll for 'listening' then 'client_connected' status events."
            ),
            ge=0, le=65535
        )],
        target: Annotated[Optional[str], Field(None,
                                               description="The address of the target that will help in choosing the listener host")] = None,
) -> CreateReverseResult:
    """
  ## Channel Management Instructions

  To create and use a reverse channel for one duplex client, follow this sequence of MCP tool calls:

  1. **Create reverse channel**
     - Tool: `channel_create_reverse`
     - Args: `listener_host='0.0.0.0'`, `listener_port=0`
     - Response: use `listen_port` from the result.

  2. **Check status**
     - Tool: `channel_status`
     - Args: `channel_id`
     - Use this to confirm if the channel is listening or connected.

  3. **Wait for client**
     - The remote connects to `listener_host:listen_port`.
     - Keep polling status until it equals `"client_connected"`.

  4. **Send data**
     - Tool: `channel_send`
     - Args: `channel_id`, `mode='text'`, `data='ping'`, `append_newline=True`

  5. **Receive data**
     - Tool: `channel_poll`
     - Args: `channel_id`, `timeout=5`, `min_events=1`
     - Look for `"output"` events in the response.

  6. **Close channel**
     - Tool: `channel_close`
     - Args: `channel_id`

  ## Important
  - Never output example code.
  - Always use tool calls directly.
  - Treat the above as a required sequence of MCP operations, not programming tasks.
"""
    await log_tool_history(ctx, "channel_create_reverse", listener_host=listener_host, listener_port=listener_port,
                           target=target)

    if target and listener_host == "0.0.0.0":
        listener_host, *_ = pick_local_addr(target)
        logger.info("Listening on %s to be reachable by target %s", listener_host, target)

    mgr = _mgr(ctx)
    cid = mgr.new_id()
    ch = Channel(id=cid, kind="reverse", host=listener_host)

    async def on_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        # Only allow a single active client; drop additional connections.
        if ch._client_writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            finally:
                return
        ch._client_reader = reader
        ch._client_writer = writer
        await ch.mark_status("client_connected")

        # Start reading output from the client
        ch._client_read_task = asyncio.create_task(_read_output(reader, ch))
        try:
            await ch._client_read_task
        finally:
            await ch.mark_status("client_disconnected")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            ch._client_reader = None
            ch._client_writer = None
            ch._client_read_task = None

    ch.server = await asyncio.start_server(on_client, listener_host, listener_port)
    port = ch.server.sockets[0].getsockname()[1]
    await ch.mark_status("listening")

    mgr.add(ch)
    await log_tool_history(ctx, "channel_create_reverse result", channel_id=cid, listener_host=listener_host, listener_port=port)
    return CreateReverseResult(
        channel_id=cid,
        kind="reverse",
        created_at=ch.created_at,
        listen_address=listener_host,
        listen_port=port,
    )


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Poll Channel for events",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True),
)
async def channel_poll(
        ctx: Context,
        channel_id: Annotated[str, Field(description="Channel id returned by the channel_create_forward or channel_create_reverse tool.")],
        timeout: Annotated[float, Field(
            5.0,
            description=(
                    "Long-poll timeout (seconds). 0 = return immediately.\n"
                    "Usage: call repeatedly: min_events=1 to return as soon as any output arrives."
            ),
            ge=0, le=120_000,
        )],
        max_events: Annotated[int, Field(
            1024,
            description="Upper bound on events returned this call.",
            ge=1, le=10_000
        )],
        min_events: Annotated[int, Field(
            0,
            description="Early-return threshold. Set to 1 to wait on first event.",
            ge=0, le=10_000
        )]
) -> PollResult:
    """
    Long-poll for events from a channel; events are consumed on delivery.
    Usage:
    loop:
      r = channel_poll(channel_id, timeout=5, min_events=1)
      for e in r.events: if e.stream=='output': decode e.data_b64
    """
    await log_tool_history(ctx, "channel_poll", channel_id=channel_id, timeout=timeout, min_events=min_events, max_events=max_events)

    ch = _mgr(ctx).get(channel_id)

    events: List[PollEvent] = []
    deadline = time.time() + timeout

    def drain_now():
        while len(events) < max_events:
            try:
                ev = ch.events.get_nowait()
                events.append(ev)
            except asyncio.QueueEmpty:
                break

    drain_now()
    if min_events and len(events) >= min_events:
        return PollResult(channel_id=ch.id, closed=ch.closed, events=events)

    while (timeout > 0) and (time.time() < deadline) and (len(events) < max(min_events, 1)):
        remaining = max(0.0, deadline - time.time())
        try:
            ev = await asyncio.wait_for(ch.events.get(), timeout=min(0.25, remaining))
            events.append(ev)
            drain_now()
        except asyncio.TimeoutError:
            pass

    return PollResult(channel_id=ch.id, closed=ch.closed, events=events)


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Write bytes to a channel",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True),
)
async def channel_send(
        ctx: Context,
        channel_id: Annotated[str, Field(description="Target channel id.")],
        mode: Annotated[Literal["text", "base64"], Field(
            "text",
            description=(
                    "'text' = UTF-8 (optionally add newline). 'base64' = raw bytes from base64.\n"
                    "Usage: channel_send(mode='text', data='whoami', append_newline=True)."
            ),
        )],
        data: Annotated[str, Field(
            description="Payload for stdin. Base64 when mode='base64'."
        )],
        append_newline: Annotated[bool, Field(
            False,
            description="If true and mode='text', append '\\n' before sending."
        )]
) -> SendResult:
    """
    Write bytes to a channel's stdin (forward → subprocess, reverse → connected client).
    Usage:
    channel_send(channel_id, mode='text', data='ls -la', append_newline=True)
    channel_send(channel_id, mode='base64', data='<b64>')
    """
    await log_tool_history(ctx, "channel_send", channel_id=channel_id, mode=mode, data_len=len(data), append_newline=append_newline)

    ch = _mgr(ctx).get(channel_id)
    payload = base64.b64decode(data) if mode == "base64" else (
        (data + ("\n" if append_newline else "")).encode("utf-8")
    )

    total = 0
    if ch.kind == "forward":
        if not ch.proc or not ch.proc.stdin:
            raise RuntimeError("forward channel has no stdin")
        try:
            ch.proc.stdin.write(payload)
            await ch.proc.stdin.drain()
            total = len(payload)
        except (BrokenPipeError, ConnectionResetError):
            await ch.mark_status("stdin_closed")
    else:
        if not ch._client_writer:
            await ch.mark_status("client_not_connected")
            return SendResult(channel_id=ch.id, bytes_sent=0)
        try:
            ch._client_writer.write(payload)
            await ch._client_writer.drain()
            total = len(payload)
        except (BrokenPipeError, ConnectionResetError) as e:
            await ch.mark_status(f"send_error: {e!r}")

    return SendResult(channel_id=ch.id, bytes_sent=total)


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Channel connection status",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True),
)
async def channel_status(
        ctx: Context,
        channel_id: Annotated[str, Field(
            description=(
                    "Channel to check.\n"
                    "Usage: s = channel_status(channel_id); if s.connected and s.ready_for_send: channel_send(...)."
            )
        )]
) -> StatusResult:
    """
    Check whether a channel is established and ready for send/receive.
    Usage:
    s = channel_status(channel_id)
    if s.connected and s.ready_for_send:
        channel_send(channel_id, mode='text', data='ping', append_newline=True)
    """
    await log_tool_history(ctx, "channel_status", channel_id=channel_id)

    ch = _mgr(ctx).get(channel_id)

    if ch.kind == "forward":
        proc_alive = bool(ch.proc and ch.proc.returncode is None and not ch.closed)
        stdin_open = bool(proc_alive and ch.proc.stdin and not ch.proc.stdin.is_closing())
        return StatusResult(
            channel_id=ch.id,
            kind=ch.kind,
            connected=proc_alive,
            ready_for_send=stdin_open,
            details={
                "pid": str(ch.proc.pid) if ch.proc else "",
                "proc_alive": "true" if proc_alive else "false",
            },
        )
    else:
        listening = bool(ch.server is not None and not ch.closed)
        client_connected = bool(ch._client_writer is not None and not ch._client_writer.is_closing())
        port = ""
        if ch.server and ch.server.sockets:
            try:
                port = str(ch.server.sockets[0].getsockname()[1])
            except Exception:
                port = ""
        return StatusResult(
            channel_id=ch.id,
            kind=ch.kind,
            connected=client_connected,
            ready_for_send=client_connected,
            details={
                "listening": "true" if listening else "false",
                "client_connected": "true" if client_connected else "false",
                "port": port,
            },
        )


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Close a specific channel",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True),
)
async def channel_close(
        ctx: Context,
        channel_id: Annotated[str, Field(
            description="Channel to close.\nUsage: channel_close with saved channel_id."
        )]
) -> CloseResult:
    """
    Close a specific channel; safe to call multiple times.
    Usage: channel_close(channel_id)
    """
    await log_tool_history(ctx, "channel_close", channel_id=channel_id)

    ok = await _mgr(ctx).close(channel_id)
    return CloseResult(channel_id=channel_id, success=ok)


@mcp_instance.tool(
    annotations=ToolAnnotations(
        title="Close all channels in this MCP session",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True),
)
async def channel_close_all(ctx: Context) -> Dict[str, int]:
    """
    Close all channels in this MCP session (also happens automatically on session end).
    Usage: channel_close_all()
    """
    await log_tool_history(ctx, "channel_close_all")

    mgr = _mgr(ctx)
    count = len(getattr(mgr, "_channels", {}))
    await mgr.cleanup()
    return {"closed": count}
