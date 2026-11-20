"""Atomic discovery batches and cooperative archive resumption."""

import logging
import time

from shyhurricane.graph.batch_timing import account
from shyhurricane.graph.model import identity
from shyhurricane.graph.parser_diagnostics import remaining_seconds, report_batch
from shyhurricane.graph.policy import ANALYZER_VERSION

logger = logging.getLogger(__name__)
BATCH_SIZE = 500
SLICE_SECONDS = 30


class ArchivePending(Exception):
    """Durable progress is available for another parser invocation."""


class ArchiveCursor:
    def __init__(self, artifacts, event, url, filename, raw, contexts):
        self.artifacts = artifacts
        self.connection = artifacts.connection
        self.started = time.monotonic()
        self.key = identity("archive-v1", ANALYZER_VERSION, event["id"], url, filename, raw, contexts)
        row = self.connection.execute(
            "SELECT phase,offset,artifact FROM graph_archive_progress WHERE id=?", (self.key,)
        ).fetchone()
        self.phase, self.offset = row[:2] if row else (0, 0)
        self.ir = artifacts.read(row[2])["ir"] if row and row[0] != -1 else None
        if row is None:
            with self.connection:
                self.ir = artifacts.write(identity("unit-ir-v1", filename, raw), raw)
                ref = artifacts.write(self.key, {"ir": self.ir, "contexts": contexts})
                self.connection.execute(
                    "INSERT INTO graph_archive_progress VALUES (?,?,0,0)", (self.key, ref)
                )
        logger.info("Graph archive resume checkpoint=%s phase=%s offset=%s", self.key, self.phase, self.offset)

    @property
    def complete(self):
        return self.phase == -1

    def run(self, phase, rows, write, *, batch_size=BATCH_SIZE):
        if self.phase > phase:
            return
        offset = self.offset if self.phase == phase else 0
        while offset < len(rows):
            if time.monotonic() - self.started >= SLICE_SECONDS or remaining_seconds() < 5:
                logger.info("Graph archive yield checkpoint=%s phase=%s completed=%s total=%s",
                            self.key, phase, offset, len(rows))
                raise ArchivePending()
            selected = rows[offset:offset + batch_size]
            started = time.monotonic()
            # Suppress ManifestStore's intermediate commits: facts and cursor must be atomic.
            with account() as timing, self.artifacts.manifest.batch(atomic=True):
                acquired = time.monotonic()
                lock_sql = timing["sql_seconds"]
                lock_calls = timing["sql_calls"]
                timing["sql_families"].clear()
                write(selected)
                offset += len(selected)
                self.connection.execute(
                    "UPDATE graph_archive_progress SET phase=?,offset=? WHERE id=?", (phase, offset, self.key)
                )
                committing = time.monotonic()
            logger.info("Graph archive batch checkpoint=%s phase=%s completed=%s total=%s "
                        "seconds=%.3f commit_seconds=%.3f", self.key, phase, offset, len(rows),
                        time.monotonic() - started, time.monotonic() - committing)
            finished = time.monotonic()
            report_batch({
                "checkpoint": self.key, "phase": phase, "offset": offset, "rows": len(selected),
                "total_seconds": finished - started,
                "lock_seconds": acquired - started,
                "sql_seconds": timing["sql_seconds"] - lock_sql,
                "sql_calls": timing["sql_calls"] - lock_calls,
                "sql_families": timing["sql_families"],
                "preparation_seconds": max(0, committing - acquired - timing["sql_seconds"] + lock_sql),
                "commit_seconds": finished - committing,
            })
            self.phase, self.offset = phase, offset
        with self.connection:
            self.connection.execute(
                "UPDATE graph_archive_progress SET phase=?,offset=0 WHERE id=?", (phase + 1, self.key)
            )
        self.phase, self.offset = phase + 1, 0

    def finish(self):
        self.connection.execute(
            "UPDATE graph_archive_progress SET phase=-1,offset=0,artifact='' WHERE id=?", (self.key,)
        )
