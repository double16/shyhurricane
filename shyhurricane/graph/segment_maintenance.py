"""Bounded shard reclamation and compaction of shared payload segment files."""

import logging
import os
import time
from pathlib import Path

from shyhurricane.graph.payload_store import NAME, PayloadStore
from shyhurricane.graph.performance import commit_timing, count, label, measured, phase

logger = logging.getLogger(__name__)

GRACE_SECONDS = 3600
COPY_BYTES = 4 * 1024 * 1024


class SegmentMaintenance:
    def __init__(self, root):
        self.root = Path(root) / "payload_segments"
        self.entries = None
        self.after = ""
        self.pending = False

    @measured("segment_maintenance", logger, quiet=True)
    def tick(self, connection, *, deadline=None, limit=64):
        if not isinstance(limit, int) or limit < 1:
            raise ValueError("Graph segment maintenance limit must be positive")
        if deadline is not None and time.monotonic() >= deadline:
            return 0
        changed = 0
        self.pending = False
        with commit_timing(connection):
            with phase("sqlite_lock"):
                connection.execute("BEGIN IMMEDIATE")
            with phase("shard_gc"):
                rows = connection.execute(
                    "SELECT s.ref FROM graph_shards s WHERE s.created<? AND NOT EXISTS "
                    "(SELECT 1 FROM graph_inventory_outbox o WHERE o.shard=s.ref) "
                    "ORDER BY s.created,s.ref LIMIT ?", (time.time() - GRACE_SECONDS, limit),
                ).fetchall()
                connection.executemany("DELETE FROM graph_shards WHERE ref=?", rows)
                changed += len(rows)
                count("shards_deleted", len(rows))
                self.pending = len(rows) == limit
            with phase("segment_lookup"):
                candidate = connection.execute(
                    "SELECT name,bytes,state FROM graph_payload_segments "
                    "WHERE state='compacting' OR (name>? AND state IN ('sealed','writable')) "
                    "ORDER BY CASE state WHEN 'compacting' THEN 0 ELSE 1 END,name LIMIT 1", (self.after,),
                ).fetchone()
            if candidate:
                name, stored, state = candidate
                self.after = name
                with phase("segment_lookup"):
                    live = connection.execute(
                        "SELECT coalesce((SELECT sum(stored) FROM graph_blobs WHERE segment=?),0)"
                        "+coalesce((SELECT sum(stored) FROM graph_shards WHERE segment=?),0)", (name, name),
                    ).fetchone()[0]
                if live == 0:
                    connection.execute(
                        "UPDATE graph_payload_segments SET state='retired',retired_at=? WHERE name=?",
                        (time.time(), name),
                    )
                    changed += 1
                    count("segments_retired")
                elif state == "compacting" or (state == "sealed" and live < stored // 2):
                    connection.execute("UPDATE graph_payload_segments SET state='compacting' WHERE name=?", (name,))
                    label(stage="compaction")
                    payloads = PayloadStore(connection)
                    self.pending = True
                    copied, items = 0, 0
                    for table, key in (("graph_blobs", "digest"), ("graph_shards", "ref")):
                        entries = connection.execute(
                            f"SELECT {key},offset,stored FROM {table} WHERE segment=? ORDER BY {key} LIMIT ?",
                            (name, limit - items),
                        ).fetchall()
                        for identity, offset, size in entries:
                            if (deadline is not None and time.monotonic() >= deadline) or (
                                copied and copied + size > COPY_BYTES
                            ):
                                break
                            with phase("segment_copy"):
                                data = payloads.read(None, name, offset, size)
                                inline, segment, new_offset = payloads.put(data)
                                connection.execute(
                                    f"UPDATE {table} SET payload=?,segment=?,offset=? WHERE {key}=?",
                                    (inline, segment, new_offset, identity),
                                )
                            count("copy_bytes", size)
                            count("copy_records")
                            copied += size
                            items += 1
                        if items >= limit or copied >= COPY_BYTES or (
                            deadline is not None and time.monotonic() >= deadline
                        ):
                            break
                    changed += items
            else:
                self.after = ""
            with phase("segment_retire"):
                retired = connection.execute(
                    "SELECT name FROM graph_payload_segments WHERE state='retired' AND retired_at<? "
                    "ORDER BY retired_at LIMIT ?", (time.time() - GRACE_SECONDS, limit),
                ).fetchall()
                for (name,) in retired:
                    path = self.root / name
                    path.unlink(missing_ok=True)
                    count("segments_deleted")
                    connection.execute("DELETE FROM graph_payload_segments WHERE name=?", (name,))
                    changed += 1
                if retired and self.root.exists():
                    PayloadStore.sync_directory(self.root)
            # In-flight appends hold this same SQLite write lock. No committed reference can
            # point into an uncommitted tail or into a segment absent from the catalog.
            with phase("segment_scan"):
                if self.root.exists():
                    if self.entries is None:
                        self.entries = os.scandir(self.root)
                    for _ in range(limit):
                        if deadline is not None and time.monotonic() >= deadline:
                            break
                        entry = next(self.entries, None)
                        if entry is None:
                            self.entries.close()
                            self.entries = None
                            break
                        count("scanned_files")
                        if not NAME.fullmatch(entry.name) or not entry.is_file(follow_symlinks=False):
                            continue
                        row = connection.execute(
                            "SELECT bytes FROM graph_payload_segments WHERE name=?", (entry.name,),
                        ).fetchone()
                        if row is None:
                            Path(entry.path).unlink(missing_ok=True)
                            count("orphan_files_deleted")
                            changed += 1
                        elif entry.stat(follow_symlinks=False).st_size > row[0]:
                            count("tail_bytes_trimmed", entry.stat(follow_symlinks=False).st_size - row[0])
                            with Path(entry.path).open("r+b") as stream:
                                stream.truncate(row[0])
                                stream.flush()
                                os.fsync(stream.fileno())
                                connection.execute(
                                    "UPDATE graph_payload_segments SET allocated=? WHERE name=?",
                                    (os.fstat(stream.fileno()).st_blocks * 512, entry.name),
                                )
                            changed += 1
        self.pending = self.pending or self.entries is not None
        return changed

    def close(self):
        if self.entries is not None:
            self.entries.close()
            self.entries = None
