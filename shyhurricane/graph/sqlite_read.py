"""Read-only artifact connections with cancellable execution and bounded lock waits."""

import logging
import sqlite3
import time
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class ReadCursor(sqlite3.Cursor):
    @contextmanager
    def bounded(self):
        budget = self.connection.budget
        started = time.monotonic()
        if budget.remaining() <= 0.25:
            raise TimeoutError("Graph discovery budget reached")
        try:
            yield
        except sqlite3.OperationalError as error:
            if budget.remaining() <= 0.25 or error.sqlite_errorcode in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
                raise TimeoutError("Graph discovery read deadline reached") from error
            raise
        finally:
            logger.debug("Graph SQLite request=%s seconds=%.3f remaining_seconds=%.3f",
                         budget.request_id, time.monotonic() - started, budget.remaining())

    def execute(self, sql, parameters=()):
        with self.bounded():
            # PRAGMA must run through the base connection to avoid recursively creating this cursor.
            milliseconds = max(0, min(100, int((self.connection.budget.remaining() - 0.25) * 1000)))
            sqlite3.Connection.execute(self.connection, f"PRAGMA busy_timeout={milliseconds}")
            self.connection.budget.reads += 1
            return super().execute(sql, parameters)

    def fetchone(self):
        with self.bounded():
            return super().fetchone()

    def fetchall(self):
        with self.bounded():
            return super().fetchall()


class ReadConnection(sqlite3.Connection):
    def close(self):
        with self.budget.lock:
            self.budget.interrupts.discard(self.interrupt)
            super().close()

    def execute(self, sql, parameters=()):
        return self.cursor(factory=ReadCursor).execute(sql, parameters)


def open_read_connection(path, budget):
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True,
                                 timeout=0.1, factory=ReadConnection)
    connection.budget = budget
    sqlite3.Connection.execute(connection, "PRAGMA query_only=ON")
    connection.set_progress_handler(lambda: int(budget.remaining() <= 0.25), 1000)
    with budget.lock:
        budget.interrupts.add(connection.interrupt)
    return connection
