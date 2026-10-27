"""Durable offline expansion of archived IR shards; independent of ordinary capture work."""

import time

from shyhurricane.graph.blob_store import owner_triggers
from shyhurricane.graph.extract import apply_javascript
from shyhurricane.graph.links import LinkPlanner
from shyhurricane.graph.model import Projection, identity, projection_snapshot, restore_projection
from shyhurricane.graph.retry_policy import transient_neo4j_error
from shyhurricane.graph.unit_publication import UnitPublisher


class Expansions:
    def __init__(self, artifacts, store):
        self.artifacts, self.store = artifacts, store
        self.connection = artifacts.connection
        self.connection.executescript(
            "CREATE TABLE IF NOT EXISTS graph_expansions (id TEXT PRIMARY KEY,capture_id TEXT,unit_id TEXT,"
            "state TEXT,error TEXT DEFAULT '',next_attempt REAL DEFAULT 0,checkpoint TEXT DEFAULT '');"
            "CREATE TABLE IF NOT EXISTS graph_expansion_receipts (queue_id INTEGER PRIMARY KEY,job_id TEXT);"
        )

        owner_triggers(self.connection, "graph_expansions", "checkpoint", "id")

    def accept(self, item, queue_id):
        key = identity("expand", item["id"], item["analysis_unit_id"])
        with self.connection:
            self.connection.execute(
                "INSERT OR IGNORE INTO graph_expansions(id,capture_id,unit_id,state) VALUES (?,?,?,'pending')",
                (key, item["id"], item["analysis_unit_id"]),
            )
            self.connection.execute(
                "UPDATE graph_expansions SET state='pending',next_attempt=0,checkpoint='' "
                "WHERE id=? AND state='failed'",
                (key,),
            )
            self.connection.execute("INSERT OR IGNORE INTO graph_expansion_receipts VALUES (?,?)", (queue_id, key))
        return key

    def available(self):
        return (
            self.connection.execute(
                "SELECT 1 FROM graph_expansions WHERE state='pending' AND next_attempt<=? LIMIT 1", (time.time(),)
            ).fetchone()
            is not None
        )

    def step(self):
        row = self.connection.execute(
            "SELECT id,capture_id,unit_id,checkpoint FROM graph_expansions WHERE state='pending' AND next_attempt<=? "
            "ORDER BY rowid LIMIT 1",
            (time.time(),),
        ).fetchone()
        if row is None:
            return False
        key, capture, unit, checkpoint = row
        try:
            record = self.connection.execute(
                "SELECT artifact,source_path FROM graph_manifest_units WHERE id=? AND capture_id=?", (unit, capture)
            ).fetchone()
            if record is None or not record[0]:
                raise ValueError("Analysis unit has no retained IR; inspect discovery coverage")
            state = self.artifacts.read(checkpoint) if checkpoint else None
            raw = state["projection"] if state else self.artifacts.read(record[0])
            markup_projection = None
            if "markup_capture" in raw:
                from shyhurricane.graph.parser_worker import parse

                reference = self.connection.execute("SELECT path FROM captures WHERE id=?", (capture,)).fetchone()[0]
                event = self.artifacts.read(reference)
                markup_projection = parse(
                    event,
                    self.artifacts,
                    markup_offset=raw["markup_offset"],
                    markup_limit=raw["markup_limit"],
                    record_discovery=False,
                    open_world=False,
                )
            if "ir_artifact" in raw:
                raw = {
                    **self.artifacts.read(raw["ir_artifact"]),
                    "contexts": raw["contexts"],
                    "requires_context_shards": False,
                }
            if raw.get("requires_context_shards"):
                raise ValueError("Select an archived context-shard to bound consuming-document work")
            if "contexts" not in raw and "event" not in raw:
                raw["contexts"] = [
                    self.artifacts.read(row[0])
                    for row in self.connection.execute(
                        "SELECT data FROM graph_unit_contexts WHERE unit_id=? ORDER BY context_id LIMIT 101", (unit,)
                    )
                ]
            if len(raw.get("contexts", [])) > 100:
                raise ValueError("Select an archived context-shard to bound consuming-document work")
            if "source" in raw:
                from shyhurricane.graph.discovery_manifest import archive_ir
                from shyhurricane.graph.extract import run_javascript

                source = raw
                raw = run_javascript(source["source"], source["filename"], "summary")
                reference = self.connection.execute("SELECT path FROM captures WHERE id=?", (capture,)).fetchone()[0]
                event = self.artifacts.read(reference)
                analyzed = archive_ir(
                    self.artifacts, event, event["data"]["url"], source["filename"], raw, contexts=source["contexts"]
                )
                with self.connection:
                    self.connection.execute(
                        "UPDATE graph_manifest_units SET "
                        "discovery=(SELECT discovery FROM graph_manifest_units WHERE id=?),"
                        "flow=(SELECT flow FROM graph_manifest_units WHERE id=?) WHERE id=?",
                        (analyzed, analyzed, unit),
                    )
                raw.update(filename=source["filename"], contexts=source["contexts"])
            if len(raw.get("nodes", [])) > 4000 or len(raw.get("edges", [])) > 4000:
                raise ValueError("Select an archived flow-shard or node-shard for bounded detail expansion")
            if markup_projection is not None:
                projection = markup_projection
            elif "event" in raw:
                projection = restore_projection(raw)
            else:
                reference = self.connection.execute("SELECT path FROM captures WHERE id=?", (capture,)).fetchone()[0]
                event = self.artifacts.read(reference)
                projection = Projection({**event, "library_analysis": "full"})
                projection.library_analysis = "full"
                root = projection.resource(projection.url)
                references = []

                def reference(value, kind, rule, **kwargs):
                    from shyhurricane.graph.model import web_url

                    url = web_url(value, kwargs.get("base") or projection.url)
                    if url:
                        references.append(url)
                        target = projection.resource(url, kwargs.get("method", "GET"))
                        projection.fact(
                            kwargs.get("source", root), target, kind, rule, location=kwargs.get("location", "")
                        )
                        return target
                    return None

                apply_javascript(
                    projection, root, raw.get("filename", record[1]), raw, reference, raw.get("contexts", [])
                )
            if len(projection.contexts) > 100:
                raise ValueError("Select an archived context-shard to bound consuming-document work")
            planner = LinkPlanner(self.store, projection)
            if state:
                planner.restore(state["planner"])
            completed = planner.plan_slice()
            snapshot = {"projection": projection_snapshot(projection), "planner": planner.checkpoint()}
            path = self.artifacts.write(identity("expansion-checkpoint", key), snapshot)
            with self.connection:
                self.connection.execute("UPDATE graph_expansions SET checkpoint=? WHERE id=?", (path, key))
            if not completed:
                return True
            projection.planned_links = planner.links
            UnitPublisher(self.store, unit).publish(projection)
            with self.connection:
                self.connection.execute(
                    "UPDATE graph_expansions SET state='done',error='',checkpoint='' WHERE id=?", (key,)
                )
                self.connection.execute(
                    "UPDATE graph_manifest_units SET materialization='complete',error='' WHERE id=?", (unit,)
                )
            self.artifacts.delete(path)
        except Exception as error:
            transient = transient_neo4j_error(error)
            with self.connection:
                self.connection.execute(
                    "UPDATE graph_expansions SET state=?,error=?,next_attempt=? WHERE id=?",
                    ("pending" if transient else "failed", str(error)[:1000], time.time() + 30, key),
                )
                self.connection.execute(
                    "UPDATE graph_manifest_units SET materialization=?,error=? WHERE id=?",
                    ("pending" if transient else "failed", str(error)[:1000], unit),
                )
        return True

    def settle(self, queue):
        for queue_id, state in self.connection.execute(
            "SELECT r.queue_id,j.state FROM graph_expansion_receipts r JOIN graph_expansions j ON j.id=r.job_id "
            "WHERE j.state IN ('done','failed')"
        ).fetchall():
            (queue.ack if state == "done" else queue.ack_failed)(id=queue_id)
            with self.connection:
                self.connection.execute("DELETE FROM graph_expansion_receipts WHERE queue_id=?", (queue_id,))
