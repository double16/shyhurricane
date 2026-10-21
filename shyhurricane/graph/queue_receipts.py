"""Keep durable queue acknowledgements coupled to continuation outcomes."""


class QueueReceipts:
    def __init__(self, connection, queue):
        self.connection = connection
        self.queue = queue
        self.items = {}
        with connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS graph_queue_receipts ("
                "queue_id INTEGER PRIMARY KEY,continuation_id TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS graph_queue_receipts_job "
                "ON graph_queue_receipts(continuation_id)"
            )

    def contains(self, key):
        return bool(self.items.get(key)) or self.connection.execute(
            "SELECT 1 FROM graph_queue_receipts WHERE continuation_id=? LIMIT 1", (key,)
        ).fetchone() is not None

    def track(self, key, receipt):
        if "pqid" in receipt:
            with self.connection:
                self.connection.execute(
                    "INSERT OR IGNORE INTO graph_queue_receipts VALUES (?,?)", (receipt["pqid"], key)
                )
            # ID-based acknowledgement no longer needs the potentially large payload in memory.
            with self.queue.action_lock:
                self.queue._unack_cache.pop(receipt["pqid"], None)
        else:
            # Payload-only queue adapters can acknowledge by object identity within this process.
            self.items.setdefault(key, []).append(receipt)

    def settle(self, key, *, failed):
        acknowledge = self.queue.ack_failed if failed else self.queue.ack
        rows = self.connection.execute(
            "SELECT queue_id FROM graph_queue_receipts WHERE continuation_id=?", (key,)
        ).fetchall()
        for (queue_id,) in rows:
            acknowledge(id=queue_id)
            with self.connection:
                self.connection.execute("DELETE FROM graph_queue_receipts WHERE queue_id=?", (queue_id,))
        for item in self.items.pop(key, []):
            acknowledge(item)

    def recover(self):
        rows = self.connection.execute(
            "SELECT DISTINCT r.continuation_id,j.state FROM graph_queue_receipts r "
            "JOIN graph_continuations j ON j.id=r.continuation_id "
            "WHERE j.state IN ('done','failed','superseded')"
        ).fetchall()
        for key, state in rows:
            self.settle(key, failed=state == "failed")
