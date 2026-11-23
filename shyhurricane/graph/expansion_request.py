"""Reserve an accepted expansion and its artifact before enqueueing a wakeup ticket."""

import sqlite3
import time
from contextlib import closing, nullcontext

from shyhurricane.data_paths import persistent_queue_path
from shyhurricane.graph.blob_store import validate
from shyhurricane.graph.expansion_jobs import accept_job


def reserve(db, item, budget=None):
    path = persistent_queue_path(db, "graph_state") / "artifacts.sqlite"
    while True:
        if budget is not None:
            budget.check()
        try:
            with closing(sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=0.05)) as connection, connection:
                validate(connection)
                connection.execute("BEGIN IMMEDIATE")
                accept_job(connection, item, None)
                with budget.checkpoint() if budget is not None else nullcontext():
                    if budget is not None:
                        budget.check()
                    connection.commit()
                return
        except sqlite3.OperationalError as error:
            code = getattr(error, "sqlite_errorcode", 0) & 255
            if code not in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED) or budget is None:
                raise
            time.sleep(min(0.01, max(0, budget.remaining())))
