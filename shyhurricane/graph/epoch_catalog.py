"""Revision-filtered artifact views and dependency-scoped epoch membership."""

import json
import sqlite3
from collections import deque

from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.manifest import ManifestStore
from shyhurricane.graph.model import identity


class SnapshotArtifacts(ArtifactStore):
    def __init__(self, root, path):
        state = json.loads(path.read_text())
        self.root = root
        self.connection = sqlite3.connect(root / "artifacts.sqlite", timeout=30)
        self.reference_epoch = state["epoch"]
        self.map_reads = set()
        self.map_owner = None
        self.manifest = ManifestStore(self.connection, self.root)
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS graph_pinned_source_maps (epoch_id INTEGER,id TEXT,content TEXT,"
            "PRIMARY KEY(epoch_id,id))"
        )
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS graph_source_map_reads (epoch_id INTEGER,capture_id TEXT,map_id TEXT,"
            "PRIMARY KEY(epoch_id,capture_id,map_id))"
        )
        self.connection.execute(
            f"CREATE TEMP VIEW captures AS SELECT id,url,stamp,path FROM main.captures "
            f"WHERE rowid<={int(state['watermark'])}"
        )
        self.connection.execute(
            "CREATE TEMP TABLE analysis_policies(capture_id TEXT PRIMARY KEY,mode TEXT,"
            "completed_version INTEGER,completed_mode TEXT)"
        )
        self.connection.execute("CREATE TEMP TABLE epoch_explicit_policies(capture_id TEXT PRIMARY KEY)")
        self.connection.execute(
            "CREATE TEMP VIEW refs AS SELECT r.url,r.capture_id FROM main.refs r "
            "LEFT JOIN main.graph_reference_revisions v ON v.url=r.url AND v.capture_id=r.capture_id "
            f"WHERE coalesce(v.epoch_id,0)<={int(state['epoch'])}"
        )
        with self.connection:
            for capture, mode, explicit in state["policies"]:
                self.connection.execute("INSERT INTO analysis_policies VALUES (?,?,NULL,NULL)", (capture, mode))
                if explicit:
                    self.connection.execute("INSERT INTO epoch_explicit_policies VALUES (?)", (capture,))

    def source_map(self, url, source, headers, open_world, **kwargs):
        key = identity(
            url, source, headers, kwargs.get("original_hash"), kwargs.get("response_headers"), kwargs.get("observed_at")
        )
        self.map_reads.add(key)
        if self.map_owner is not None:
            with self.connection:
                self.connection.execute(
                    "INSERT OR IGNORE INTO graph_source_map_reads VALUES (?,?,?)",
                    (self.reference_epoch, self.map_owner, key),
                )
        row = self.connection.execute(
            "SELECT content FROM graph_pinned_source_maps WHERE epoch_id=? AND id=?", (self.reference_epoch, key)
        ).fetchone()
        if row:
            return json.loads(row[0])
        content = super().source_map(url, source, headers, open_world, **kwargs)
        with self.connection:
            self.connection.execute(
                "INSERT INTO graph_pinned_source_maps VALUES (?,?,?)", (self.reference_epoch, key, json.dumps(content))
            )
        return content


def affected_captures(connection, roots, watermark):
    """Traverse actual script/load dependencies; navigation links do not invalidate analysis."""
    seen, reverse_seen = set(), set()
    pending = deque((capture, True) for capture in sorted(set(roots)))
    while pending:
        capture, reverse = pending.popleft()
        if capture in seen and (not reverse or capture in reverse_seen):
            continue
        first = capture not in seen
        seen.add(capture)
        row = connection.execute("SELECT url FROM captures WHERE id=? AND rowid<=?", (capture, watermark)).fetchone()
        if row is None:
            continue
        if first:
            for (url,) in connection.execute(
                "SELECT url FROM graph_manifest_dependencies WHERE capture_id=? ORDER BY url", (capture,)
            ):
                for (target,) in connection.execute(
                    "SELECT id FROM captures WHERE url=? AND rowid<=?", (url, watermark)
                ):
                    pending.append((target, False))
        # Loading a shared dependency does not invalidate every other consumer. A changed
        # dependency supplied as an input does invalidate its reverse dependency closure.
        if reverse:
            reverse_seen.add(capture)
            for (dependent,) in connection.execute(
                "SELECT d.capture_id FROM graph_manifest_dependencies d JOIN captures c ON c.id=d.capture_id "
                "WHERE d.url=? AND c.rowid<=? ORDER BY d.capture_id",
                (row[0], watermark),
            ):
                pending.append((dependent, True))
    return sorted(seen)
