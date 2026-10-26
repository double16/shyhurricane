"""Durable, finite graph epochs over frozen capture and policy snapshots."""

import json
import logging
import re
import time
from uuid import uuid4

from shyhurricane.graph.continuations import RETRY_DELAYS, SLICE_CONTEXTS, SLICE_SECONDS, Continuations
from shyhurricane.graph.epoch_catalog import SnapshotArtifacts, affected_captures
from shyhurricane.graph.expansion import Expansions
from shyhurricane.graph.extract import extract
from shyhurricane.graph.link_publication import LinkPublisher
from shyhurricane.graph.links import LinkPlanner
from shyhurricane.graph.model import (
    capture_unit_path,
    compact_event,
    identity,
    projection_snapshot,
    restore_projection,
    web_url,
)
from shyhurricane.graph.policy import ANALYZER_VERSION, library_analysis
from shyhurricane.graph.publication import GraphPublisher, PublicationConflict
from shyhurricane.graph.retry_policy import transient_neo4j_error
from shyhurricane.source_maps import javascript_url_from_map, source_map_url

logger = logging.getLogger(__name__)
EPOCH_VERSION = 3


class Epochs:
    """Queue receipts remain outstanding until their finite epoch finishes or fails.

    Snapshots isolate every artifact lookup, including source maps and consuming documents.
    Only the dependency closure is affected; content-addressed projection caches and
    publication digests eliminate unchanged analysis and writes across epochs.
    """

    def __init__(self, artifacts, store, *, open_world=False, isolate=False):
        self.artifacts = artifacts
        self.connection = artifacts.connection
        self.store = store
        self.open_world = open_world
        self.isolate = isolate
        self.snapshot = None
        self.snapshot_id = None
        self.expansions = Expansions(artifacts, store)
        self.expansion_turn = True
        legacy = self.connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('reanalysis','graph_continuations')"
        ).fetchall()
        for (table,) in legacy:
            if self.connection.execute(
                f"SELECT 1 FROM {table} WHERE state IN ('pending','running','failed') LIMIT 1"
            ).fetchone():
                raise ValueError("Unfinished legacy graph work: start with fresh graph state before using epochs")
        self.connection.executescript(
            "CREATE TABLE IF NOT EXISTS graph_epochs ("
            "id INTEGER PRIMARY KEY,version INTEGER NOT NULL,phase TEXT NOT NULL,snapshot TEXT NOT NULL,"
            "created_at REAL NOT NULL,next_attempt REAL NOT NULL DEFAULT 0,retries INTEGER NOT NULL DEFAULT 0,"
            "error TEXT NOT NULL DEFAULT '',noops INTEGER NOT NULL DEFAULT 0,"
            "structural_activations INTEGER NOT NULL DEFAULT 0,link_activations INTEGER NOT NULL DEFAULT 0,"
            "conflicts INTEGER NOT NULL DEFAULT 0,resume_phase TEXT,"
            "deduplicated_inputs INTEGER NOT NULL DEFAULT 0,open_world INTEGER NOT NULL DEFAULT 0,"
            "analyzer_version INTEGER NOT NULL DEFAULT 0,context_dirty INTEGER NOT NULL DEFAULT 0,"
            "affected INTEGER DEFAULT 0);"
            "CREATE TABLE IF NOT EXISTS graph_epoch_inputs ("
            "token TEXT PRIMARY KEY,capture_id TEXT NOT NULL,mode TEXT NOT NULL,"
            "epoch_id INTEGER,state TEXT NOT NULL,request_token TEXT);"
            "CREATE INDEX IF NOT EXISTS graph_epoch_input_request ON graph_epoch_inputs(request_token);"
            "CREATE TABLE IF NOT EXISTS graph_epoch_receipts (queue_id INTEGER PRIMARY KEY,token TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS graph_epoch_jobs ("
            "epoch_id INTEGER NOT NULL,capture_id TEXT NOT NULL,stage TEXT NOT NULL,checkpoint TEXT NOT NULL,"
            "PRIMARY KEY(epoch_id,capture_id));"
            "CREATE INDEX IF NOT EXISTS graph_epoch_jobs_stage ON graph_epoch_jobs(epoch_id,stage,capture_id);"
            "CREATE TABLE IF NOT EXISTS graph_epoch_failures (epoch_id INTEGER,capture_id TEXT,stage TEXT,error TEXT,"
            "PRIMARY KEY(epoch_id,capture_id));"
        )
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS graph_epoch_activity ("
            "id INTEGER PRIMARY KEY CHECK(id=1),epoch_id INTEGER,capture_id TEXT,stage TEXT,"
            "started_at REAL,last_progress_at REAL,interrupted INTEGER NOT NULL DEFAULT 0)"
        )
        with self.connection:
            self.connection.execute(
                "UPDATE graph_epoch_activity SET interrupted=1 WHERE capture_id IS NOT NULL"
            )
        self.last_progress_log = 0
        row = self.connection.execute(
            "SELECT version,analyzer_version FROM graph_epochs WHERE version<>? OR analyzer_version<>? LIMIT 1",
            (EPOCH_VERSION, ANALYZER_VERSION),
        ).fetchone()
        if row and row != (EPOCH_VERSION, ANALYZER_VERSION):
            raise ValueError("Unsupported graph epoch checkpoint version; rebuild graph state")

    def close(self):
        if self.snapshot is not None:
            self.snapshot.close()
            self.snapshot = None
        self.snapshot_id = None

    def accept(self, item, queue_id):
        if item.get("analysis_unit_id"):
            return self.expansions.accept(item, queue_id)
        if "reanalysis_ticket" in item or item.get("reconcile"):
            raise ValueError("Legacy graph delivery: rebuild graph state")
        event = self.artifacts.register(item)
        policy = self.connection.execute(
            "SELECT mode FROM analysis_policies WHERE capture_id=?", (event["id"],)
        ).fetchone()
        mode = library_analysis(policy[0] if policy else event.get("library_analysis"))
        token = identity("epoch-input", event["id"], ANALYZER_VERSION, mode, item.get("rebuild_token"))
        failed = self.connection.execute(
            "SELECT token FROM graph_epoch_inputs WHERE capture_id=? AND state='failed' "
            "AND request_token IS ? ORDER BY rowid LIMIT 1",
            (event["id"], item.get("rebuild_token")),
        ).fetchone()
        if failed:
            token = failed[0]
        with self.connection:
            inserted = self.connection.execute(
                "INSERT OR IGNORE INTO graph_epoch_inputs VALUES (?,?,?,NULL,'waiting',?)",
                (token, event["id"], mode, item.get("rebuild_token")),
            ).rowcount
            self.connection.execute("INSERT OR IGNORE INTO graph_epoch_receipts VALUES (?,?)", (queue_id, token))
            row = self.connection.execute(
                "SELECT epoch_id,state FROM graph_epoch_inputs WHERE token=?", (token,)
            ).fetchone()
            if not inserted and row[0] is not None:
                self.connection.execute(
                    "UPDATE graph_epochs SET deduplicated_inputs=deduplicated_inputs+1 WHERE id=?", (row[0],)
                )
            if row[1] == "failed":
                self.connection.execute(
                    "UPDATE graph_epoch_inputs SET state='waiting',epoch_id=NULL WHERE token=?", (token,)
                )
        return token

    def settle(self, queue):
        self.expansions.settle(queue)
        rows = self.connection.execute(
            "SELECT r.queue_id,i.state FROM graph_epoch_receipts r "
            "JOIN graph_epoch_inputs i ON i.token=r.token WHERE i.state IN ('done','failed')"
        ).fetchall()
        for queue_id, state in rows:
            (queue.ack_failed if state == "failed" else queue.ack)(id=queue_id)
            with self.connection:
                self.connection.execute("DELETE FROM graph_epoch_receipts WHERE queue_id=?", (queue_id,))

    def available(self):
        if self.expansions.available():
            return True
        return (
            self.connection.execute(
                "SELECT 1 FROM graph_epochs WHERE phase NOT IN ('done','failed') AND next_attempt<=? "
                "UNION ALL SELECT 1 FROM graph_epoch_inputs WHERE state='waiting' LIMIT 1",
                (time.time(),),
            ).fetchone()
            is not None
        )

    def start(self):
        if self.connection.execute("SELECT 1 FROM graph_epochs WHERE phase<>'done' LIMIT 1").fetchone():
            return
        if not self.connection.execute("SELECT 1 FROM graph_epoch_inputs WHERE state='waiting' LIMIT 1").fetchone():
            return
        waiting = self.connection.execute(
            "SELECT token,capture_id,mode FROM graph_epoch_inputs WHERE state='waiting' ORDER BY rowid"
        ).fetchall()
        modes = {}
        selected = []
        for token, capture, mode in waiting:
            if capture not in modes or modes[capture] == mode:
                modes[capture] = mode
                selected.append(token)
        watermark = self.connection.execute("SELECT coalesce(max(rowid),0) FROM captures").fetchone()[0]
        members = affected_captures(self.connection, modes, watermark)
        with self.connection:
            # Retain compact epoch summaries, not a growing matrix of completed jobs.
            self.connection.execute(
                "DELETE FROM graph_epoch_jobs WHERE epoch_id IN (SELECT id FROM graph_epochs WHERE phase='done')"
            )
            epoch = self.connection.execute(
                "INSERT INTO graph_epochs(version,phase,snapshot,created_at,open_world,analyzer_version,affected) "
                "VALUES (?,'references','',?,?,?,?)",
                (EPOCH_VERSION, time.time(), self.open_world, ANALYZER_VERSION, len(members)),
            ).lastrowid
            policies = []
            for capture in members:
                row = self.connection.execute(
                    "SELECT mode FROM analysis_policies WHERE capture_id=?", (capture,)
                ).fetchone()
                mode = modes.get(capture, row[0] if row else library_analysis())
                policies.append((capture, mode, bool(row)))
                self.connection.execute("INSERT INTO graph_epoch_jobs VALUES (?,?,'references','')", (epoch, capture))
            path = self.artifacts.write(
                f"epoch-{epoch}",
                {
                    "epoch": epoch,
                    "watermark": watermark,
                    "policies": policies,
                    "policy_watermark": self.connection.execute(
                        "SELECT coalesce(max(rowid),0) FROM graph_policy_revisions"
                    ).fetchone()[0],
                },
            )
            self.connection.execute(
                "UPDATE graph_epochs SET snapshot=? WHERE id=?", (self.artifacts.reference(path), epoch)
            )
            self.connection.executemany(
                "UPDATE graph_epoch_inputs SET epoch_id=?,state='active' WHERE token=?",
                ((epoch, token) for token in selected),
            )
        logger.info("Graph epoch %s started inputs=%s affected=%s", epoch, len(selected), len(members))

    def open_snapshot(self, epoch, path):
        if self.snapshot_id != epoch:
            self.close()
            snapshot = SnapshotArtifacts(self.artifacts.root, self.artifacts.resolve(path))
            self.snapshot, self.snapshot_id = snapshot, epoch
        return self.snapshot

    def save_job(self, epoch, capture_id, stage, state):
        old = self.connection.execute(
            "SELECT checkpoint FROM graph_epoch_jobs WHERE epoch_id=? AND capture_id=?", (epoch, capture_id)
        ).fetchone()[0]
        path = self.artifacts.write(f"epoch-job-{uuid4().hex}", state)
        with self.connection:
            self.connection.execute(
                "UPDATE graph_epoch_jobs SET stage=?,checkpoint=? WHERE epoch_id=? AND capture_id=?",
                (stage, self.artifacts.reference(path), epoch, capture_id),
            )
        if old:
            try:
                self.artifacts.resolve(old).unlink(missing_ok=True)
            except OSError:
                logger.warning("Graph epoch checkpoint cleanup deferred: %s", old, exc_info=True)

    def step(self):
        self.expansion_turn = not self.expansion_turn
        if (
            self.expansion_turn
            and not self.connection.execute(
                "SELECT 1 FROM graph_epochs WHERE phase NOT IN ('done','failed') LIMIT 1"
            ).fetchone()
            and self.expansions.step()
        ):
            return
        self.start()
        row = self.connection.execute(
            "SELECT id,phase,snapshot,retries FROM graph_epochs "
            "WHERE phase NOT IN ('done','failed') AND next_attempt<=? ORDER BY id LIMIT 1",
            (time.time(),),
        ).fetchone()
        if not row:
            return
        epoch, phase, path, retries = row
        job = None
        try:
            artifacts = self.open_snapshot(epoch, path)
            stages = {
                "references": ("references",),
                "contexts": ("contexts",),
                "structural": ("extract", "structural"),
                "links": ("planning", "links"),
            }[phase]
            placeholders = ",".join("?" for _ in stages)
            job = self.connection.execute(
                f"SELECT capture_id,stage,checkpoint FROM graph_epoch_jobs WHERE epoch_id=? "
                f"AND stage IN ({placeholders}) ORDER BY capture_id LIMIT 1",
                (epoch, *stages),
            ).fetchone()
            if job:
                with self.connection:
                    self.connection.execute(
                        "INSERT INTO graph_epoch_activity VALUES (1,?,?,?,?,NULL,0) "
                        "ON CONFLICT(id) DO UPDATE SET epoch_id=excluded.epoch_id,"
                        "capture_id=excluded.capture_id,stage=excluded.stage,started_at=excluded.started_at,"
                        "interrupted=0",
                        (epoch, job[0], job[1], time.time()),
                    )
                self.run_job(epoch, artifacts, *job)
                with self.connection:
                    self.connection.execute(
                        "UPDATE graph_epoch_activity SET capture_id=NULL,stage=NULL,started_at=NULL,"
                        "last_progress_at=?,interrupted=0 WHERE id=1", (time.time(),)
                    )
                if time.monotonic() - self.last_progress_log >= 30:
                    logger.info("Graph epoch progress %s", epoch_status(self.connection))
                    self.last_progress_log = time.monotonic()
            else:
                if (
                    phase == "contexts"
                    and self.connection.execute(
                        "SELECT context_dirty FROM graph_epochs WHERE id=?", (epoch,)
                    ).fetchone()[0]
                ):
                    self.repeat_context_discovery(epoch)
                    return
                if phase == "references" and self.expand_membership(epoch, artifacts):
                    return
                following = {
                    "references": "contexts",
                    "contexts": "structural",
                    "structural": "links",
                    "links": "done",
                }[phase]
                with self.connection:
                    self.connection.execute("UPDATE graph_epochs SET phase=? WHERE id=?", (following, epoch))
                    if following == "done":
                        self.connection.execute(
                            "UPDATE graph_epoch_inputs SET state='done' WHERE epoch_id=? AND state='active'", (epoch,)
                        )

                logger.info("Graph epoch %s phase=%s summary=%s", epoch, following, epoch_status(self.connection))
                if following == "done":
                    self.close()
                    self.artifacts.resolve(path).unlink(missing_ok=True)
        except Exception as error:
            with self.connection:
                self.connection.execute(
                    "UPDATE graph_epoch_activity SET capture_id=NULL,stage=NULL,started_at=NULL WHERE id=1"
                )
            transient = transient_neo4j_error(error) and not isinstance(error, PublicationConflict)
            with self.connection:
                if transient:
                    self.connection.execute(
                        "UPDATE graph_epochs SET next_attempt=?,retries=retries+1,error=? WHERE id=?",
                        (time.time() + RETRY_DELAYS[min(retries, len(RETRY_DELAYS) - 1)], str(error)[:500], epoch),
                    )
                elif job:
                    self.quarantine(epoch, job, error)
                else:
                    self.connection.execute(
                        "UPDATE graph_epochs SET phase='failed',resume_phase=?,error=?,"
                        "conflicts=conflicts+? WHERE id=?",
                        (
                            phase,
                            f"{type(error).__name__}: {error}"[:1000],
                            int(isinstance(error, PublicationConflict)),
                            epoch,
                        ),
                    )
                    self.connection.execute("UPDATE graph_epoch_inputs SET state='failed' WHERE epoch_id=?", (epoch,))
                    if job:
                        self.artifacts.status(job[0], "failed", str(error))
            logger.warning("Graph epoch %s retained phase=%s transient=%s", epoch, phase, transient, exc_info=True)

    def expand_membership(self, epoch, artifacts):
        row = self.connection.execute("SELECT snapshot FROM graph_epochs WHERE id=?", (epoch,)).fetchone()
        state = json.loads(self.artifacts.resolve(row[0]).read_text())
        existing = {
            capture
            for (capture,) in self.connection.execute(
                "SELECT capture_id FROM graph_epoch_jobs WHERE epoch_id=?", (epoch,)
            )
        }
        roots = [
            capture
            for (capture,) in self.connection.execute(
                "SELECT DISTINCT capture_id FROM graph_epoch_inputs WHERE epoch_id=?", (epoch,)
            )
        ]
        members = set(affected_captures(self.connection, roots, state["watermark"])) - existing
        if not members:
            return False
        with self.connection:
            for capture in sorted(members):
                policy = self.connection.execute(
                    "SELECT mode FROM graph_policy_revisions WHERE capture_id=? AND rowid<=? "
                    "ORDER BY rowid DESC LIMIT 1",
                    (capture, state["policy_watermark"]),
                ).fetchone()
                mode = policy[0] if policy else library_analysis()
                state["policies"].append((capture, mode, bool(policy)))
                artifacts.connection.execute("INSERT INTO analysis_policies VALUES (?,?,NULL,NULL)", (capture, mode))
                if policy:
                    artifacts.connection.execute("INSERT INTO epoch_explicit_policies VALUES (?)", (capture,))
                self.connection.execute("INSERT INTO graph_epoch_jobs VALUES (?,?,'references','')", (epoch, capture))
            self.connection.execute("UPDATE graph_epochs SET affected=affected+? WHERE id=?", (len(members), epoch))
            path = self.artifacts.write(f"epoch-{epoch}", state)
            self.connection.execute(
                "UPDATE graph_epochs SET snapshot=? WHERE id=?", (self.artifacts.reference(path), epoch)
            )
        artifacts.connection.commit()
        return True

    def quarantine(self, epoch, job, error):
        capture, stage, _ = job
        self.connection.execute(
            "UPDATE graph_epoch_jobs SET stage='failed' WHERE epoch_id=? AND capture_id=?", (epoch, capture)
        )
        self.connection.execute(
            "INSERT OR REPLACE INTO graph_epoch_failures VALUES (?,?,?,?)", (epoch, capture, stage, str(error)[:1000])
        )
        self.connection.execute(
            "UPDATE graph_epoch_inputs SET state='failed' WHERE epoch_id=? AND capture_id=?", (epoch, capture)
        )
        self.connection.execute(
            "UPDATE graph_epochs SET error=?,conflicts=conflicts+? WHERE id=?",
            (str(error)[:1000], int(isinstance(error, PublicationConflict)), epoch),
        )
        self.artifacts.manifest.unit(
            capture,
            "capture:" + self.connection.execute("SELECT url FROM captures WHERE id=?", (capture,)).fetchone()[0],
            discovery="failed",
            flow="failed",
            error=str(error),
        )
        # Reverse dependency closure only: an unrelated root can still finish this epoch.
        pending, blocked = [capture], {capture}
        while pending:
            failed = pending.pop()
            url = self.connection.execute("SELECT url FROM captures WHERE id=?", (failed,)).fetchone()[0]
            for (dependent,) in self.connection.execute(
                "SELECT d.capture_id FROM graph_manifest_dependencies d JOIN graph_epoch_jobs j "
                "ON j.capture_id=d.capture_id WHERE j.epoch_id=? AND d.url=?",
                (epoch, url),
            ).fetchall():
                if dependent in blocked:
                    continue
                blocked.add(dependent)
                pending.append(dependent)
                self.connection.execute(
                    "UPDATE graph_epoch_jobs SET stage='blocked' WHERE epoch_id=? AND capture_id=?",
                    (epoch, dependent),
                )
                self.connection.execute(
                    "UPDATE graph_epoch_inputs SET state='failed' WHERE epoch_id=? AND capture_id=?",
                    (epoch, dependent),
                )
                target = self.connection.execute("SELECT url FROM captures WHERE id=?", (dependent,)).fetchone()[0]
                self.artifacts.manifest.unit(
                    dependent,
                    "capture:" + target,
                    discovery="blocked",
                    flow="blocked",
                    error=f"Dependency {capture} failed",
                )
                self.artifacts.status(dependent, "failed", f"Dependency {capture} failed")
        self.artifacts.status(capture, "failed", str(error))

    def run_job(self, epoch, artifacts, capture_id, stage, checkpoint):
        if stage == "references":
            path = artifacts.connection.execute("SELECT path FROM captures WHERE id=?", (capture_id,)).fetchone()[0]
            event = json.loads(artifacts.resolve(path).read_text())
            mode = artifacts.connection.execute(
                "SELECT mode FROM analysis_policies WHERE capture_id=?", (capture_id,)
            ).fetchone()[0]
            event = {**event, "library_analysis": mode}
            headers = {key.lower(): value for key, value in event["data"].get("response_headers", {}).items()}
            match = re.search(r"[#@]\s*sourceMappingURL\s*=\s*(\S+)", event["data"].get("response_body") or "")
            hint = headers.get("sourcemap") or headers.get("x-sourcemap") or (match[1].rstrip("*/") if match else "")
            urls = {source_map_url(event["data"]["url"]), web_url(hint, event["data"]["url"]) if hint else None}
            maps = [artifacts.latest(url, as_of=event["observed_at"]) for url in sorted(url for url in urls if url)]
            maps = [item["id"] if item else None for item in maps]
            open_world = (
                bool(self.connection.execute("SELECT open_world FROM graph_epochs WHERE id=?", (epoch,)).fetchone()[0])
                and not artifacts.connection.execute(
                    "SELECT 1 FROM epoch_explicit_policies WHERE capture_id=?", (capture_id,)
                ).fetchone()
            )
            key = identity("epoch-reference-v2", capture_id, mode, ANALYZER_VERSION, maps, open_world)

            def discover_references():
                artifacts.map_reads.clear()
                projection = self.parse(event, artifacts, document_contexts=[], open_world=open_world)
                references = artifacts.connection.execute(
                    "SELECT url FROM refs WHERE capture_id=? ORDER BY url", (capture_id,)
                ).fetchall()
                source_maps = [
                    artifacts.connection.execute(
                        "SELECT id,content FROM graph_pinned_source_maps WHERE epoch_id=? AND id=?",
                        (artifacts.reference_epoch, map_id),
                    ).fetchone()
                    for (map_id,) in artifacts.connection.execute(
                        "SELECT map_id FROM graph_source_map_reads WHERE epoch_id=? AND capture_id=? ORDER BY map_id",
                        (artifacts.reference_epoch, capture_id),
                    )
                ]
                return {
                    "projection": projection_snapshot(projection),
                    "references": references,
                    "source_maps": source_maps,
                }

            discovered = artifacts.cached(key, discover_references)
            projection = restore_projection(discovered["projection"])
            with artifacts.connection:
                artifacts.connection.executemany(
                    "INSERT OR IGNORE INTO graph_pinned_source_maps VALUES (?,?,?)",
                    ((artifacts.reference_epoch, key, content) for key, content in discovered["source_maps"]),
                )
            # Cached extraction must replay reference discovery into this snapshot too.
            artifacts.references(capture_id, [url for (url,) in discovered["references"]])
            self.save_job(
                epoch,
                capture_id,
                "contexts" if Continuations.eligible(event) else "structural",
                {
                    "event": compact_event(event),
                    "projection": projection_snapshot(projection),
                    "pending": [javascript_url_from_map(event["data"]["url"]) or event["data"]["url"]],
                    "seen": [javascript_url_from_map(event["data"]["url"]) or event["data"]["url"]],
                    "after": "",
                    "contexts": {},
                },
            )
        else:
            state = json.loads(self.artifacts.resolve(checkpoint).read_text())
            if stage == "contexts":
                # Reuse the bounded, resumable discovery cursor without creating legacy work.
                discovery = object.__new__(Continuations)
                discovery.artifacts, discovery.connection = artifacts, artifacts.connection
                discovery.discover(state)
                if not state["pending"]:
                    projection = restore_projection(state["projection"])
                    references = sorted(
                        {
                            url
                            for context in state["contexts"].values()
                            for value in projection.browser_references
                            if (url := web_url(value, context["base"]))
                        }
                    )
                    before = artifacts.connection.total_changes
                    artifacts.references(capture_id, references)
                    if artifacts.connection.total_changes > before:
                        with self.connection:
                            self.connection.execute("UPDATE graph_epochs SET context_dirty=1 WHERE id=?", (epoch,))
                self.save_job(epoch, capture_id, "extract" if not state["pending"] else "contexts", state)
            elif stage == "extract":
                contexts = sorted(state["contexts"].values(), key=lambda item: item["id"])
                key = identity("epoch-context-v1", state["projection"], contexts)
                state["projection"] = artifacts.cached(
                    key,
                    lambda: projection_snapshot(
                        self.parse(
                            {
                                **json.loads(
                                    artifacts.resolve(
                                        artifacts.connection.execute(
                                            "SELECT path FROM captures WHERE id=?", (capture_id,)
                                        ).fetchone()[0]
                                    ).read_text()
                                ),
                                "library_analysis": state["event"]["library_analysis"],
                            },
                            artifacts,
                            document_contexts=contexts,
                        )
                    ),
                )
                self.save_job(epoch, capture_id, "structural", state)
            elif stage == "structural":
                projection = restore_projection(state["projection"])
                projection.structural_nodes = sorted(projection.nodes)
                state["projection"] = projection_snapshot(projection)
                projection.planned_links = {}
                activated = GraphPublisher(self.store).publish(projection)
                with self.connection:
                    self.connection.execute(
                        "UPDATE graph_manifest_units SET materialization='complete' "
                        "WHERE capture_id=? AND source_path=?",
                        (capture_id, capture_unit_path(projection.event)),
                    )
                self.count(epoch, "structural_activations" if activated else "noops")
                self.save_job(epoch, capture_id, "planning", state)
            elif stage == "planning":
                projection = restore_projection(state["projection"])
                planner = LinkPlanner(self.store, projection)
                if "planner" in state:
                    planner.restore(state["planner"])
                completed = planner.plan_slice(seconds=SLICE_SECONDS, contexts=SLICE_CONTEXTS)
                state.update(projection=projection_snapshot(projection), planner=planner.checkpoint())
                self.save_job(epoch, capture_id, "links" if completed else "planning", state)
            elif stage == "links":
                projection = restore_projection(state["projection"])
                projection.planned_links = state["planner"]["links"]
                activated = LinkPublisher(self.store).publish(projection)
                self.count(epoch, "link_activations" if activated else "noops")
                with self.connection:
                    self.connection.execute(
                        "UPDATE analysis_policies SET completed_version=?,completed_mode=? WHERE capture_id=?",
                        (ANALYZER_VERSION, projection.library_analysis, capture_id),
                    )
                self.artifacts.status(capture_id, "complete")
                self.save_job(epoch, capture_id, "done", {"version": EPOCH_VERSION})

    def count(self, epoch, name):
        with self.connection:
            self.connection.execute(f"UPDATE graph_epochs SET {name}={name}+1 WHERE id=?", (epoch,))

    def parse(self, event, artifacts, **options):
        artifacts.map_owner = event["id"]
        if self.isolate:
            from shyhurricane.graph.parser_worker import parse

            return parse(event, artifacts, **options)
        return extract(event, artifacts, **options)

    def repeat_context_discovery(self, epoch):
        """Reach a reference fixed point before any final analysis or publication.

        Only discovery cursors repeat. Every added URL derives from a finite captured
        document base and a finite AST reference; no publication can add obligations.
        """
        rows = self.connection.execute(
            "SELECT capture_id,checkpoint FROM graph_epoch_jobs WHERE epoch_id=? AND stage='extract'", (epoch,)
        ).fetchall()
        for capture_id, checkpoint in rows:
            state = json.loads(self.artifacts.resolve(checkpoint).read_text())
            url = javascript_url_from_map(state["event"]["data"]["url"]) or state["event"]["data"]["url"]
            state.update(pending=[url], seen=[url], after="", contexts={})
            self.save_job(epoch, capture_id, "contexts", state)
        with self.connection:
            self.connection.execute("UPDATE graph_epochs SET context_dirty=0 WHERE id=?", (epoch,))


def epoch_status(connection):
    """Additive monitoring fields; never initialize or advance epoch work."""
    if not connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='graph_epochs'").fetchone():
        return None
    cursor = connection.execute("SELECT * FROM graph_epochs ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    if row is None:
        return None
    result = dict(zip((column[0] for column in cursor.description), row))
    result.pop("snapshot")
    counts = dict(
        connection.execute(
            "SELECT stage,count(*) FROM graph_epoch_jobs WHERE epoch_id=? GROUP BY stage", (result["id"],)
        )
    )
    result.update(affected=result["affected"], completed=counts.get("done", 0), stages=counts)
    result["failed"] = counts.get("failed", 0)
    result["blocked"] = counts.get("blocked", 0)
    result["outstanding"] = result["affected"] - result["completed"] - result["failed"] - result["blocked"]
    result["discovery_total"] = result["affected"]
    result["discovery_completed"] = max(
        0, result["affected"] - counts.get("references", 0) - result["failed"] - result["blocked"]
    )
    result["current_job"] = None
    result["last_progress_at"] = None
    if connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='graph_epoch_activity'"
    ).fetchone():
        activity = connection.execute(
            "SELECT capture_id,stage,started_at,last_progress_at,interrupted "
            "FROM graph_epoch_activity WHERE id=1 AND epoch_id=?", (result["id"],)
        ).fetchone()
        if activity:
            result["last_progress_at"] = activity[3]
            if activity[0]:
                result["current_job"] = dict(
                    capture_id=activity[0], stage=activity[1], started_at=activity[2], interrupted=bool(activity[4])
                )
    result["accepted_inputs"] = connection.execute(
        "SELECT count(*) FROM graph_epoch_inputs WHERE epoch_id=?", (result["id"],)
    ).fetchone()[0]
    result["waiting_inputs"] = connection.execute(
        "SELECT count(*) FROM graph_epoch_inputs WHERE state='waiting'"
    ).fetchone()[0]
    return result
