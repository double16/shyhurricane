"""Transactional, body-free scope metadata for persistent indexing queues."""

import json
import sqlite3
import time
from pathlib import Path

import persistqueue


def item_scopes(item) -> list[tuple[str, str, str, int]]:
    """Return URL, document ID, capture ID and unresolved flag without changing payloads."""
    if item is None:
        return [("", "", "", 0)]
    if hasattr(item, "meta"):
        return [(item.meta.get("url", ""), item.id, "", int(not item.meta.get("url")))]
    if isinstance(item, dict):
        if "reanalysis_ticket" in item:
            return [("", "", item["id"], 0)]
        if isinstance(item.get("data"), dict) and item["data"].get("url"):
            return [(item["data"]["url"], "", item.get("id", ""), 0)]
        if item.get("request", {}).get("endpoint"):
            return [(item["request"]["endpoint"], "", "", 0)]
        if "log" in item:
            urls = {entry.get("request", {}).get("url") for entry in item["log"].get("entries", [])}
            return [(url, "", "", 0) for url in sorted(urls - {None, ""})] or [("", "", "", 1)]
        return [("", "", "", 1)]
    if isinstance(item, bytes):
        item = item.decode("utf-8", errors="replace")
    if isinstance(item, str):
        try:
            return item_scopes(json.loads(item))
        except ValueError:
            pass
        lines = item.splitlines()
        if len(lines) > 1 and all(line.lstrip().startswith("{") for line in lines if line.strip()):
            return sorted({scope for line in lines if line.strip() for scope in item_scopes(line)})
        # Raw HTTP uses the same parser as ingestion; import only for this legacy format.
        from shyhurricane.index.input_documents import HttpRawDocument

        responses = HttpRawDocument().run(item)["request_responses"]
        return [(response.url, "", "", 0) for response in responses] or [("", "", "", 1)]
    return [("", "", "", 1)]


class ScopedAckQueue(persistqueue.SQLiteAckQueue):
    """Keep scope metadata and payload changes in the same SQLite transaction."""

    def initialize_scopes(self):
        with self.tran_lock, self._putter as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS indexing_scope (queue_id INTEGER, url TEXT, doc_id TEXT, "
                "capture_id TEXT, unresolved INTEGER, PRIMARY KEY(queue_id,url,doc_id,capture_id))"
            )
            connection.execute("CREATE INDEX IF NOT EXISTS indexing_scope_url ON indexing_scope(url,queue_id)")
            connection.execute("CREATE INDEX IF NOT EXISTS indexing_scope_doc ON indexing_scope(doc_id,queue_id)")
            connection.execute(
                f"CREATE TRIGGER IF NOT EXISTS indexing_scope_delete AFTER DELETE ON {self._table_name} "
                "BEGIN DELETE FROM indexing_scope WHERE queue_id=OLD._id; END"
            )
            rows = connection.execute(
                f"SELECT _id,data FROM {self._table_name} q WHERE status IN (0,1,2,9) "
                "AND NOT EXISTS (SELECT 1 FROM indexing_scope s WHERE s.queue_id=q._id)"
            )
            for row_id, data in rows:
                self._write_scopes(connection, row_id, data)

    def _write_scopes(self, connection, row_id, data):
        try:
            scopes = item_scopes(self._serializer.loads(data))
        except Exception:
            # Preserve unreadable legacy payloads; retrieval must not claim they completed.
            scopes = [("", "", "", 1)]
        connection.execute("DELETE FROM indexing_scope WHERE queue_id=?", (row_id,))
        connection.executemany(
            "INSERT OR IGNORE INTO indexing_scope VALUES (?,?,?,?,?)",
            ((row_id, *scope) for scope in scopes),
        )

    def _insert_into(self, *record):
        budget = getattr(self, "request_budget", None)
        if budget is None:
            with self.tran_lock, self._putter as connection:
                row_id = connection.execute(self._sql_insert, record).lastrowid
                self._write_scopes(connection, row_id, record[0])
            return row_id
        while not self.tran_lock.acquire(timeout=0.05):
            budget.check()
        connection = self._putter
        try:
            budget.check()
            connection.execute("PRAGMA busy_timeout=50")
            connection.set_progress_handler(lambda: int(budget.remaining() <= 0), 1000)
            with connection:
                row_id = connection.execute(self._sql_insert, record).lastrowid
                self._write_scopes(connection, row_id, record[0])
                with budget.lock:
                    budget.check()
                    connection.commit()
        finally:
            connection.set_progress_handler(None, 0)
            self.tran_lock.release()
        return row_id

    def _update(self, key, *args):
        with self.tran_lock, self._putter as connection:
            connection.execute(self._sql_update, (*args, key))
            self._write_scopes(connection, key, args[0])
        return key


def scoped_queue_rows(path: Path, timeout: float) -> list[tuple]:
    """Read active/failed metadata without deserializing payloads or resuming workers."""
    database = path / "data.db"
    if not database.exists():
        return []
    deadline = time.monotonic() + timeout
    connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=timeout)
    try:
        connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        return connection.execute(
            "SELECT q._id,q.status,s.url,s.doc_id,s.capture_id,s.unresolved FROM ack_queue_default q "
            "LEFT JOIN indexing_scope s ON s.queue_id=q._id WHERE q.status IN (0,1,2,9)"
        ).fetchall()
    finally:
        connection.close()
