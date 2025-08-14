import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Literal, Optional, Dict

from pydantic import BaseModel, Field


class PollEvent(BaseModel):
    ts: float = Field(description="Unix epoch seconds.")
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
