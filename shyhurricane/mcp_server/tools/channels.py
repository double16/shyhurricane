from __future__ import annotations

import asyncio
import base64
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Literal

from pydantic import BaseModel, Field, conint, validator
from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations

from shyhurricane.mcp_server import mcp_instance, log_tool_history
from shyhurricane.utils import b64


# ──────────────────────────────────────────────────────────────────────────────
# Schemas
# ──────────────────────────────────────────────────────────────────────────────


class CreateForwardArgs(BaseModel):
    cmd: List[str] = Field(
        ...,
        description=(
            "Command to execute as argv list (no shell expansion). "
            "Example: ['bash','-lc','python3 -u script.py'].\n"
            "Usage: channels.create_forward → save channel_id → loop channels.poll for output → "
            "channels.send to write stdin → channels.close when done."
        ),
    )
    cwd: Optional[str] = Field(
        None,
        description="Working directory for the process. If null, inherits server CWD."
    )
    env: Optional[Dict[str, str]] = Field(
        None,
        description="Environment variables to set/override for the process."
    )


class CreateReverseArgs(BaseModel):
    host: str = Field(
        "0.0.0.0",
        description=(
            "Interface to bind the reverse channel listener (single duplex client).\n"
            "Usage: channels.create_reverse → get {host,port} → remote connects → "
            "wait for 'client_connected' via channels.poll → exchange data via channels.send/poll."
        ),
    )
    port: conint(ge=0, le=65535) = Field(
        0,
        description=(
            "TCP port to listen on (0 = ephemeral; actual port in result.details.port). "
            "Poll for 'listening' then 'client_connected' status events."
        ),
    )


class PollArgs(BaseModel):
    channel_id: str = Field(..., description="Channel id returned by a create_* tool.")
    timeout_ms: conint(ge=0, le=120_000) = Field(
        5000,
        description=(
            "Long-poll timeout (ms). 0 = return immediately.\n"
            "Usage: call repeatedly: min_events=1 to return as soon as any output arrives."
        ),
    )
    max_events: conint(ge=1, le=10_000) = Field(
        1024,
        description="Upper bound on events returned this call."
    )
    min_events: conint(ge=0, le=10_000) = Field(
        0,
        description="Early-return threshold. Set to 1 to wake on first event."
    )


class SendArgs(BaseModel):
    channel_id: str = Field(..., description="Target channel id.")
    mode: Literal["text", "base64"] = Field(
        "text",
        description=(
            "'text' = UTF-8 (optionally add newline). 'base64' = raw bytes from base64.\n"
            "Usage: channels.send(mode='text', data='whoami', append_newline=True)."
        ),
    )
    data: str = Field(
        ...,
        description="Payload for stdin. Base64 when mode='base64'."
    )
    append_newline: bool = Field(
        False,
        description="If true and mode='text', append '\\n' before sending."
    )

    @validator("data")
    def not_empty(cls, v):
        if v == "":
            raise ValueError("data must not be empty")
        return v


class CloseArgs(BaseModel):
    channel_id: str = Field(
        ...,
        description="Channel to close (idempotent).\nUsage: channels.close with saved channel_id."
    )


class StatusArgs(BaseModel):
    channel_id: str = Field(
        ...,
        description=(
            "Channel to check.\n"
            "Usage: s = channels.status(channel_id); if s.connected and s.ready_for_send: channels.send(...)."
        )
    )


class CreateResult(BaseModel):
    channel_id: str = Field(..., description="New channel id; persist this for later calls.")
    kind: Literal["forward", "reverse"] = Field(..., description="Channel type.")
    created_at: float = Field(..., description="Unix epoch seconds.")
    details: Dict[str, str] = Field(
        ...,
        description="Forward: {'pid': '<pid>'}. Reverse: {'host': '<host>', 'port': '<port>'}."
    )


class PollEvent(BaseModel):
    ts: float = Field(..., description="Unix epoch seconds.")
    stream: Literal["output", "status"] = Field(
        ..., description="'output' has bytes (data_b64). 'status' has a human-readable note."
    )
    data_b64: Optional[str] = Field(
        None, description="Base64 bytes for 'output' events."
    )
    note: Optional[str] = Field(
        None,
        description=(
            "Status message (e.g., 'process_started_pid_<pid>', 'listening', 'client_connected', "
            "'output_eof', 'client_disconnected', 'channel_closed')."
        ),
    )


class PollResult(BaseModel):
    channel_id: str = Field(..., description="Echo channel id.")
    closed: bool = Field(..., description="True if channel has been closed.")
    events: List[PollEvent] = Field(
        ..., description="Events since last poll (consumed on delivery)."
    )


class SendResult(BaseModel):
    channel_id: str = Field(..., description="Echo channel id.")
    bytes_sent: int = Field(..., description="Bytes written to stdin.")


class CloseResult(BaseModel):
    channel_id: str = Field(..., description="Echo channel id.")
    success: bool = Field(..., description="True if the channel existed and is now closed.")


class StatusResult(BaseModel):
    channel_id: str = Field(..., description="Echo channel id.")
    kind: Literal["forward", "reverse"] = Field(..., description="Channel type.")
    connected: bool = Field(
        ...,
        description=(
            "Forward: True if process started and not closed. "
            "Reverse: True if a client is currently connected."
        )
    )
    ready_for_send: bool = Field(
        ...,
        description=(
            "True if writing to stdin should succeed now. "
            "Forward: stdin pipe open; Reverse: client connected."
        )
    )
    details: Dict[str, str] = Field(
        ...,
        description=(
            "Additional state hints. Forward includes {'pid': '<pid>', 'proc_alive': 'true/false'}. "
            "Reverse includes {'listening': 'true/false', 'client_connected': 'true/false', 'port': '<port>'} when known."
        )
    )


# ──────────────────────────────────────────────────────────────────────────────
# Runtime
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Channel:
    id: str
    kind: Literal["forward", "reverse"]
    created_at: float = field(default_factory=time.time)
    closed: bool = False

    events: "asyncio.Queue[PollEvent]" = field(default_factory=asyncio.Queue)

    # forward
    proc: Optional[asyncio.subprocess.Process] = None
    _output_task: Optional[asyncio.Task] = None

    # reverse (single duplex connection)
    host: Optional[str] = None
    server: Optional[asyncio.AbstractServer] = None
    _client_reader: Optional[asyncio.StreamReader] = None
    _client_writer: Optional[asyncio.StreamWriter] = None
    _client_read_task: Optional[asyncio.Task] = None

    async def put_event(self, ev: PollEvent):
        # simple cap to avoid unbounded growth
        if self.events.qsize() > 50_000:
            try:
                _ = self.events.get_nowait()
            except asyncio.QueueEmpty:
                pass
        await self.events.put(ev)

    async def mark_status(self, note: str):
        await self.put_event(PollEvent(ts=time.time(), stream="status", note=note))

    async def close(self):
        if self.closed:
            return
        self.closed = True

        # cancel tasks
        for t in [self._output_task, self._client_read_task]:
            if t and not t.done():
                t.cancel()

        # close server and client
        if self.server:
            self.server.close()
            try:
                await self.server.wait_closed()
            except Exception:
                pass
        if self._client_writer:
            try:
                self._client_writer.close()
                await self._client_writer.wait_closed()
            except Exception:
                pass

        # kill process
        if self.proc and self.proc.returncode is None:
            try:
                self.proc.terminate()
                try:
                    await asyncio.wait_for(self.proc.wait(), timeout=2)
                except asyncio.TimeoutError:
                    self.proc.kill()
            except ProcessLookupError:
                pass

        await self.mark_status("channel_closed")


class ChannelManager:
    def __init__(self):
        self._channels: Dict[str, Channel] = {}

    def new_id(self) -> str:
        return str(uuid.uuid4())

    def add(self, ch: Channel) -> Channel:
        self._channels[ch.id] = ch
        return ch

    def get(self, cid: str) -> Channel:
        ch = self._channels.get(cid)
        if not ch:
            raise KeyError(f"unknown channel_id {cid}")
        return ch

    async def close(self, cid: str) -> bool:
        ch = self._channels.pop(cid, None)
        if not ch:
            return False
        await ch.close()
        return True

    async def cleanup(self):
        ids = list(self._channels.keys())
        for cid in ids:
            await self.close(cid)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

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


def _mgr(ctx: Context) -> ChannelManager:
    mgr = ctx.session.get("channel_manager")
    if mgr is None:
        mgr = ChannelManager()
        ctx.session["channel_manager"] = mgr

        async def _cleanup():
            try:
                await mgr.cleanup()
            except Exception:
                pass

        ctx.on_session_ended(_cleanup)
    return mgr


# ──────────────────────────────────────────────────────────────────────────────
# Tools
# ──────────────────────────────────────────────────────────────────────────────

@mcp_instance.tool("channels.create_forward")
async def create_forward(ctx: Context, args: CreateForwardArgs) -> CreateResult:
    """
    Create a new channel backed by a local subprocess. Output is stdout+stderr merged.
    Usage:
    1) channels.create_forward(cmd=['bash','-lc','python3 -u script.py']) → channel_id
    2) channels.status(channel_id)  # optional, check readiness
    3) channels.poll(channel_id, timeout_ms=5000, min_events=1)
    4) channels.send(channel_id, mode='text', data='help', append_newline=True)
    5) channels.close(channel_id)
    """
    await log_tool_history(ctx, "create_forward")

    mgr = _mgr(ctx)
    cid = mgr.new_id()

    env = os.environ.copy()
    if args.env:
        env.update(args.env)

    proc = await asyncio.create_subprocess_exec(
        *args.cmd,
        cwd=args.cwd or None,
        env=env,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,  # merge
        limit=0,
    )

    ch = Channel(id=cid, kind="forward", proc=proc)
    await ch.mark_status(f"process_started_pid_{proc.pid}")

    if proc.stdout:
        ch._output_task = asyncio.create_task(_read_output(proc.stdout, ch))

    mgr.add(ch)
    return CreateResult(
        channel_id=cid,
        kind="forward",
        created_at=ch.created_at,
        details={"pid": str(proc.pid)}
    )


@mcp_instance.tool("channels.create_reverse")
async def create_reverse(ctx: Context, args: CreateReverseArgs) -> CreateResult:
    """
    Create a reverse channel that listens on a single TCP port for one duplex client.
    Usage:
    1) r = channels.create_reverse(host='0.0.0.0', port=0) → port in r.details.port
    2) channels.status(channel_id)  # check listening/connected
    3) Remote connects to host:port; poll until status 'client_connected'
    4) channels.send(channel_id, mode='text', data='ping', append_newline=True)
    5) channels.poll(channel_id, timeout_ms=5000, min_events=1) → 'output' events
    6) channels.close(channel_id)
    """
    await log_tool_history(ctx, "create_reverse")

    mgr = _mgr(ctx)
    cid = mgr.new_id()
    ch = Channel(id=cid, kind="reverse", host=args.host)

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

    ch.server = await asyncio.start_server(on_client, args.host, args.port)
    port = ch.server.sockets[0].getsockname()[1]
    await ch.mark_status("listening")

    mgr.add(ch)
    return CreateResult(
        channel_id=cid,
        kind="reverse",
        created_at=ch.created_at,
        details={"host": args.host, "port": str(port)},
    )


@mcp_instance.tool("channels.poll", desc="Async long-poll for output/status events.")
async def poll(ctx: Context, args: PollArgs) -> PollResult:
    """
    Long-poll for events from a channel; events are consumed on delivery.
    Usage:
    loop:
      r = channels.poll(channel_id, timeout_ms=5000, min_events=1)
      for e in r.events: if e.stream=='output': decode e.data_b64
    """
    await log_tool_history(ctx, "poll")

    ch = _mgr(ctx).get(args.channel_id)

    events: List[PollEvent] = []
    deadline = time.time() + (args.timeout_ms / 1000.0)

    def drain_now():
        while len(events) < args.max_events:
            try:
                ev = ch.events.get_nowait()
                events.append(ev)
            except asyncio.QueueEmpty:
                break

    drain_now()
    if args.min_events and len(events) >= args.min_events:
        return PollResult(channel_id=ch.id, closed=ch.closed, events=events)

    while (args.timeout_ms > 0) and (time.time() < deadline) and (len(events) < max(args.min_events, 1)):
        remaining = max(0.0, deadline - time.time())
        try:
            ev = await asyncio.wait_for(ch.events.get(), timeout=min(0.25, remaining))
            events.append(ev)
            drain_now()
        except asyncio.TimeoutError:
            pass

    return PollResult(channel_id=ch.id, closed=ch.closed, events=events)


@mcp_instance.tool("channels.send",
                   annotations=ToolAnnotations(
                       title="Write bytes to a channel",
                       readOnlyHint=True,
                       destructiveHint=False,
                       idempotentHint=False,
                       openWorldHint=True),
                   )
async def send(ctx: Context, args: SendArgs) -> SendResult:
    """
    Write bytes to a channel's stdin (forward → subprocess, reverse → connected client).
    Usage:
    channels.send(channel_id, mode='text', data='ls -la', append_newline=True)
    channels.send(channel_id, mode='base64', data='<b64>')
    """
    await log_tool_history(ctx, "send")

    ch = _mgr(ctx).get(args.channel_id)
    payload = base64.b64decode(args.data) if args.mode == "base64" else (
        (args.data + ("\n" if args.append_newline else "")).encode("utf-8")
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
    "channels.status",
    annotations=ToolAnnotations(
        title="Channel connection status",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True),
)
async def status(ctx: Context, args: StatusArgs) -> StatusResult:
    """
    Check whether a channel is established and ready for send/receive.
    Usage:
    s = channels.status(channel_id)
    if s.connected and s.ready_for_send:
        channels.send(channel_id, mode='text', data='ping', append_newline=True)
    """
    await log_tool_history(ctx, "status")

    ch = _mgr(ctx).get(args.channel_id)

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


@mcp_instance.tool("channels.close",
                   annotations=ToolAnnotations(
                       title="Close a specific channel",
                       readOnlyHint=False,
                       destructiveHint=False,
                       idempotentHint=False,
                       openWorldHint=True),
                   )
async def close(ctx: Context, args: CloseArgs) -> CloseResult:
    """
    Close a specific channel; safe to call multiple times.
    Usage: channels.close(channel_id)
    """
    await log_tool_history(ctx, "close")

    ok = await _mgr(ctx).close(args.channel_id)
    return CloseResult(channel_id=args.channel_id, success=ok)


@mcp_instance.tool("channels.close_all",
                   annotations=ToolAnnotations(
                       title="Close all channels in this MCP session",
                       readOnlyHint=False,
                       destructiveHint=False,
                       idempotentHint=False,
                       openWorldHint=True),
                   )
async def close_all(ctx: Context) -> Dict[str, int]:
    """
    Close all channels in this MCP session (also happens automatically on session end).
    Usage: channels.close_all()
    """
    await log_tool_history(ctx, "close_all")

    mgr = _mgr(ctx)
    count = len(getattr(mgr, "_channels", {}))
    await mgr.cleanup()
    return {"closed": count}
