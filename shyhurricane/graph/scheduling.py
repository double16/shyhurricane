"""Durable coalescing of new reanalysis work; legacy queue entries remain unchanged."""

import json
import logging
from pathlib import Path
from uuid import uuid4

logger = logging.getLogger(__name__)
MAX_RECONCILE_CAPTURES = 32


def merge_routes(left, right):
    if left is None:
        return right
    return {
        "visited": sorted(set(left["visited"]) & set(right["visited"])),
        "remaining": max(left["remaining"], right["remaining"]),
    }


class ReanalysisScheduler:
    def __init__(self, artifacts, queue):
        self.artifacts = artifacts
        self.queue = queue
        self.connection = artifacts.connection
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS reanalysis ("
            "capture_id TEXT PRIMARY KEY, ticket TEXT, state TEXT, generation INTEGER, "
            "running_generation INTEGER, pending TEXT, running TEXT, delivered INTEGER)"
        )
        self.connection.execute("CREATE INDEX IF NOT EXISTS reanalysis_delivery ON reanalysis(state,delivered)")
        self.connection.execute("CREATE TABLE IF NOT EXISTS reanalysis_obligations (id TEXT PRIMARY KEY)")
        self.connection.commit()

    def request(self, capture_id, visited, remaining, *, obligation_id=None):
        """Commit a routing obligation; the worker flushes the outbox after its scheduling pass."""
        route = {"visited": sorted(set(visited)), "remaining": remaining}
        if capture_id in visited or not 0 <= remaining <= MAX_RECONCILE_CAPTURES - 2:
            raise ValueError("Invalid reconciliation route")
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            if obligation_id is not None and not self.connection.execute(
                "INSERT OR IGNORE INTO reanalysis_obligations VALUES (?)", (obligation_id,)
            ).rowcount:
                return
            row = self.connection.execute(
                "SELECT state,pending FROM reanalysis WHERE capture_id=?", (capture_id,)
            ).fetchone()
            if row and row[0] in {"pending", "running"}:
                route = merge_routes(json.loads(row[1]) if row[1] else None, route)
                self.connection.execute(
                    "UPDATE reanalysis SET generation=generation+1,pending=? WHERE capture_id=?",
                    (json.dumps(route), capture_id),
                )
                action = "coalesced"
            else:
                self.connection.execute(
                    "INSERT OR REPLACE INTO reanalysis VALUES (?,?, 'pending',1,0,?,NULL,0)",
                    (capture_id, uuid4().hex, json.dumps(route)),
                )
                action = "created"
        logger.info("Graph reanalysis %s capture=%s", action, capture_id)

    def flush(self):
        # A crash after put and before delivered=1 can redeliver a ticket; claim is idempotent.
        with self.artifacts.lock("reanalysis-outbox"):
            rows = self.connection.execute(
                "SELECT capture_id,ticket FROM reanalysis WHERE state='pending' AND delivered=0 ORDER BY rowid"
            ).fetchall()
            for capture_id, ticket in rows:
                self.queue.put({"reanalysis_ticket": ticket, "id": capture_id})
                with self.connection:
                    self.connection.execute(
                        "UPDATE reanalysis SET delivered=1 WHERE capture_id=? AND ticket=?", (capture_id, ticket)
                    )

    def recover(self):
        has_jobs = self.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='graph_continuations'"
        ).fetchone()
        if has_jobs:
            for capture_id, ticket in self.connection.execute(
                "SELECT capture_id,ticket FROM graph_continuations WHERE state='failed' AND ticket IS NOT NULL"
            ).fetchall():
                self.finish({"id": capture_id, "reanalysis_ticket": ticket})
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            has_continuations = self.connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='graph_continuations'"
            ).fetchone()
            continuation_filter = (
                " AND NOT EXISTS (SELECT 1 FROM graph_continuations j "
                "WHERE j.capture_id=reanalysis.capture_id AND j.state IN ('pending','running','failed'))"
                if has_continuations else ""
            )
            rows = self.connection.execute(
                "SELECT capture_id,pending,running FROM reanalysis WHERE state='running'" + continuation_filter
            ).fetchall()
            for capture_id, pending, running in rows:
                route = merge_routes(json.loads(pending) if pending else None, json.loads(running))
                self.connection.execute(
                    "UPDATE reanalysis SET state='pending',pending=?,running=NULL,delivered=0 WHERE capture_id=?",
                    (json.dumps(route), capture_id),
                )
                logger.info("Graph reanalysis reclaimed capture=%s", capture_id)
        self.flush()

    def claim(self, item):
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.connection.execute(
                "SELECT pending FROM reanalysis WHERE capture_id=? AND ticket=? AND state='pending'",
                (item["id"], item["reanalysis_ticket"]),
            ).fetchone()
            if row is None:
                logger.info("Graph reanalysis skipped obsolete ticket capture=%s", item["id"])
                return None
            self.connection.execute(
                "UPDATE reanalysis SET state='running',running_generation=generation,running=pending,pending=NULL "
                "WHERE capture_id=?",
                (item["id"],),
            )
        path = self.connection.execute("SELECT path FROM captures WHERE id=?", (item["id"],)).fetchone()
        if path is None:
            raise ValueError("Reanalysis capture is unavailable")
        event = json.loads(Path(path[0]).read_text())
        route = json.loads(row[0])
        return {
            **event,
            "reconcile": True,
            "reconcile_chain": route["visited"],
            "reconcile_remaining": route["remaining"],
        }

    def retry(self, item):
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.connection.execute(
                "SELECT pending,running FROM reanalysis WHERE capture_id=? AND ticket=? AND state='running'",
                (item["id"], item["reanalysis_ticket"]),
            ).fetchone()
            if row:
                route = merge_routes(json.loads(row[0]) if row[0] else None, json.loads(row[1]))
                self.connection.execute(
                    "UPDATE reanalysis SET state='pending',pending=?,running=NULL WHERE capture_id=?",
                    (json.dumps(route), item["id"]),
                )

    def finish(self, item):
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.connection.execute(
                "SELECT generation,running_generation FROM reanalysis "
                "WHERE capture_id=? AND ticket=? AND state='running'",
                (item["id"], item["reanalysis_ticket"]),
            ).fetchone()
            if row is None:
                return
            if row[0] > row[1]:
                self.connection.execute(
                    "UPDATE reanalysis SET state='pending',ticket=?,running=NULL,delivered=0 WHERE capture_id=?",
                    (uuid4().hex, item["id"]),
                )
                logger.info("Graph reanalysis follow-up scheduled capture=%s", item["id"])
            else:
                self.connection.execute(
                    "UPDATE reanalysis SET state='done',running=NULL WHERE capture_id=?", (item["id"],)
                )
