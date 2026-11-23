"""Durable, revision-pinned correlation slices with bounded JSON checkpoints."""

import json
import time

from neo4j.exceptions import Neo4jError

from shyhurricane.graph.budget import QueryBudget
from shyhurricane.graph.model import identity
from shyhurricane.investigation.jobs import POLICY_VERSION

SLICE_SECONDS = 30
READ_SECONDS = 5
PIN_SECONDS = 3600
MAX_JOB_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024


class CheckpointYield(Exception):
    """A slice ended without completing the finding."""


class CheckpointCapacityError(Exception):
    """A finding cannot fit within the durable checkpoint budget."""


class RestartCheckpoint(TimeoutError):
    """Retained graph state is unavailable; restart rather than mixing generations."""


class Checkpoint:
    def __init__(self, store, graph, job, revision):
        self.store = store
        self.graph = graph
        self.job = job
        self.revision = revision
        self.progressed = False
        self.budget = QueryBudget(seconds=SLICE_SECONDS)
        self.pin = identity("investigation", job["id"], job["generation"], revision, POLICY_VERSION)
        self.stage = "anchors"
        connection = store.connection
        expected = (job["generation"], job["revision"], POLICY_VERSION, revision)
        obsolete_pin = None
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            if not store.current_job(job):
                raise CheckpointYield("Finding generation changed")
            old = connection.execute(
                "SELECT generation,revision,policy,graph_revision,pin,expires FROM checkpoints WHERE finding_id=?",
                (job["id"],),
            ).fetchone()
            if old and (tuple(old[:4]) != expected or old[5] <= time.time()):
                obsolete_pin = old[4]
                connection.execute("DELETE FROM checkpoint_pages WHERE finding_id=?", (job["id"],))
                connection.execute("DELETE FROM checkpoints WHERE finding_id=?", (job["id"],))
            connection.execute(
                "INSERT OR IGNORE INTO checkpoints "
                "(finding_id,generation,revision,policy,graph_revision,pin,updated) VALUES (?,?,?,?,?,?,?)",
                (job["id"], *expected, self.pin, time.time()),
            )
        if obsolete_pin is not None:
            self.release(obsolete_pin)
        self.renew()

    def enter(self, stage):
        self.stage = stage
        with self.store.connection:
            self.store.connection.execute("BEGIN IMMEDIATE")
            if not self.store.current_job(self.job):
                raise CheckpointYield("Finding generation changed")
            self.store.connection.execute(
                "UPDATE checkpoints SET stage=?,updated=? WHERE finding_id=?",
                (stage, time.time(), self.job["id"]),
            )

    def renew(self):
        expires = time.time() + PIN_SECONDS
        rows = self.graph.read(
            "MERGE (p:GraphReadPin {id:$id}) SET p.revision=$revision,p.expires=$expires RETURN p.id AS id",
            id=self.pin, revision=self.revision, expires=expires,
            timeout=READ_SECONDS, access_mode="WRITE",
        )
        if not any(row["id"] == self.pin for row in rows):
            raise TimeoutError("Correlation revision pin could not be confirmed")
        with self.store.connection:
            self.store.connection.execute(
                "UPDATE checkpoints SET updated=?,expires=? WHERE finding_id=? AND pin=?",
                (time.time(), expires, self.job["id"], self.pin),
            )

    def release(self, pin=None):
        self.graph.read(
            "MATCH (p:GraphReadPin {id:$id}) DELETE p", id=pin or self.pin,
            timeout=READ_SECONDS, access_mode="WRITE",
        )

    def load(self, key):
        row = self.store.connection.execute(
            "SELECT payload FROM checkpoint_pages WHERE finding_id=? AND key=?", (self.job["id"], key),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def reset(self):
        with self.store.connection:
            self.store.connection.execute("BEGIN IMMEDIATE")
            if self.store.current_job(self.job):
                self.store.connection.execute("DELETE FROM checkpoint_pages WHERE finding_id=?", (self.job["id"],))
                self.store.connection.execute("DELETE FROM checkpoints WHERE finding_id=?", (self.job["id"],))

    def prune(self, operation):
        """Completed operation results replace their larger reconstruction pages."""
        with self.store.connection:
            self.store.connection.execute("BEGIN IMMEDIATE")
            if self.store.current_job(self.job):
                self.store.connection.execute(
                    "DELETE FROM checkpoint_pages WHERE finding_id=? AND "
                    "(key LIKE ? OR key LIKE ? OR key=?)",
                    (self.job["id"], f"read:{operation}:%", f"limit:{operation}:%", f"search:{operation}"),
                )

    def save(self, key, value):
        payload = json.dumps(value, separators=(",", ":"), ensure_ascii=True)
        connection = self.store.connection
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            if not self.store.current_job(self.job):
                raise CheckpointYield("Finding generation changed")
            existing = connection.execute(
                "SELECT payload FROM checkpoint_pages WHERE finding_id=? AND key=?", (self.job["id"], key),
            ).fetchone()
            if existing and existing[0] == payload:
                return
            if key.startswith(("result:", "search:")):
                operation = key.split(":", 1)[1]
                connection.execute(
                    "DELETE FROM checkpoint_pages WHERE finding_id=? AND "
                    "(key LIKE ? OR key LIKE ? OR (? AND key=?))",
                    (self.job["id"], f"read:{operation}:%", f"limit:{operation}:%",
                     key.startswith("result:"), f"search:{operation}"),
                )
            used, total = connection.execute(
                "SELECT coalesce((SELECT bytes FROM checkpoint_usage WHERE finding_id=?),0),"
                "bytes FROM checkpoint_total WHERE id=1", (self.job["id"],),
            ).fetchone()
            previous = connection.execute(
                "SELECT size FROM checkpoint_pages WHERE finding_id=? AND key=?",
                (self.job["id"], key),
            ).fetchone()
            delta = len(payload) - (previous[0] if previous else 0)
            if used + delta > MAX_JOB_BYTES or total + delta > MAX_TOTAL_BYTES:
                raise CheckpointCapacityError("Correlation checkpoint storage budget reached")
            connection.execute(
                "INSERT INTO checkpoint_pages VALUES (?,?,?,?) ON CONFLICT(finding_id,key) DO UPDATE SET payload=excluded.payload,size=excluded.size",
                (self.job["id"], key, payload, len(payload)),
            )
            connection.execute(
                "UPDATE checkpoints SET stage=?,updated=?,progress=? WHERE finding_id=?",
                (self.stage, time.time(), time.time(), self.job["id"]),
            )
        self.progressed = True

    def defer(self):
        # Move yielded work behind other ready findings without counting progress as failure.
        if self.progressed:
            with self.store.connection:
                self.store.connection.execute(
                    "UPDATE jobs SET due=?,attempts=0,error=NULL WHERE kind=? AND key=? AND generation=?",
                    (time.time() + 1, "correlate", self.job["id"], self.job["generation"]),
                )
        else:
            self.store.failed(self.job, TimeoutError(), transient=True)


def recover_checkpoints(store, graph, revision):
    """Retain one valid admitted finding; discard only unfinished reconstruction state."""
    connection = store.connection
    with connection:
        connection.execute("BEGIN IMMEDIATE")
        rows = connection.execute(
            "SELECT c.finding_id,c.pin FROM checkpoints c JOIN jobs j "
            "ON j.kind='correlate' AND j.key=c.finding_id "
            "JOIN findings f ON f.id=c.finding_id "
            "WHERE j.state='pending' AND j.generation=c.generation AND f.revision=c.revision "
            "AND c.policy=? AND c.graph_revision=? AND c.expires>? "
            "ORDER BY c.progress DESC,c.finding_id LIMIT 1",
            (POLICY_VERSION, revision, time.time()),
        ).fetchall()
        keep = rows[0][0] if rows else ""
        pins = connection.execute("SELECT pin FROM checkpoints WHERE finding_id<>?", (keep,)).fetchall()
        obsolete = connection.execute("SELECT finding_id FROM checkpoints WHERE finding_id<>?", (keep,)).fetchall()
        connection.executemany("DELETE FROM checkpoint_pages WHERE finding_id=?", obsolete)
        connection.execute("DELETE FROM checkpoints WHERE finding_id<>?", (keep,))
    for (pin,) in pins:
        try:
            graph.read("MATCH (p:GraphReadPin {id:$id}) DELETE p", id=pin,
                       timeout=READ_SECONDS, access_mode="WRITE")
        except Exception:
            pass  # Expiry releases pins when the database is temporarily unavailable.


class CheckpointQuery:
    """Replay pure stage computation, reusing durable reads and completed operations.

    Keyset reads reconstruct unfinished selection without rereading successful database pages.
    Path searches additionally save their explicit frontier and previously collected witnesses.
    """

    def __init__(self, query, checkpoint):
        self.query = query
        self.checkpoint = checkpoint
        self.original_read = query.read
        query.read = self.read
        query.budget = checkpoint.budget
        query.path_checkpoint = self.path_checkpoint
        self.operation_key = ""

    def read(self, statement, **parameters):
        timeout = parameters.pop("timeout", READ_SECONDS)
        fallback = f"limit:{self.operation_key}:" + identity(statement, json.dumps(
            {key: value for key, value in parameters.items() if key != "limit"}, sort_keys=True,
        ))
        if parameters.get("limit", 1) > 1:
            reduced = self.checkpoint.load(fallback)
            if reduced is not None:
                parameters["limit"] = min(parameters["limit"], reduced)
        key = f"read:{self.operation_key}:" + identity(statement, json.dumps(parameters, sort_keys=True))
        cached = self.checkpoint.load(key)
        if cached is not None:
            self.query.budget.check()
            return cached
        try:
            rows = self.original_read(statement, timeout=min(timeout, READ_SECONDS), **parameters)
        except Neo4jError as error:
            if parameters.get("limit", 1) > 1 and (
                "TransactionTimedOut" in (error.code or "")
                or (error.code or "").endswith("MemoryPoolOutOfMemoryError")
            ):
                self.checkpoint.save(fallback, max(1, parameters["limit"] // 2))
            raise
        self.checkpoint.save(key, rows)
        return rows

    def path_checkpoint(self, search, result):
        if "time_limit" in result.get("truncation_reasons", []):
            # These describe the unfinished slice, not the eventual completed search.
            search["analysis_gaps"] = [gap for gap in search.get("analysis_gaps", []) if not (
                "budget" in gap or "Frontier loading incomplete" in gap
                or gap.startswith("Selected seeds have no discovered path")
                or gap.startswith("No source-to-sink path was discovered")
            )]
            previous = self.checkpoint.load("search:" + self.operation_key) or {"results": []}
            self.checkpoint.save("search:" + self.operation_key, {
                "search": search, "results": previous["results"] + result["results"],
            })
            raise CheckpointYield("Path frontier checkpointed")

    def operation(self, name, *args, **kwargs):
        self.operation_key = identity(name, args, kwargs)
        self.checkpoint.enter(name)
        key = "result:" + self.operation_key
        cached = self.checkpoint.load(key)
        if cached is not None:
            self.checkpoint.prune(self.operation_key)
            return cached
        self.query.budget.check()
        search = self.checkpoint.load("search:" + self.operation_key) if name == "paths" else None
        if search:
            kwargs["_resume"] = search["search"]
        result = getattr(self.query, name)(*args, **kwargs)
        if "time_limit" in result.get("truncation_reasons", []):
            raise CheckpointYield("Correlation stage incomplete")
        if "generation_unavailable" in result.get("truncation_reasons", []):
            raise RestartCheckpoint("Pinned graph generation unavailable")
        if search:
            result["results"] = search["results"] + result["results"]
        self.checkpoint.save(key, result)
        self.checkpoint.prune(self.operation_key)
        return result

    def endpoints(self, *args, **kwargs):
        return self.operation("endpoints", *args, **kwargs)

    def elements(self, *args, **kwargs):
        return self.operation("elements", *args, **kwargs)

    def location_elements(self, *args, **kwargs):
        return self.operation("location_elements", *args, **kwargs)

    def paths(self, *args, **kwargs):
        return self.operation("paths", *args, **kwargs)
