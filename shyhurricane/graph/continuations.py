"""Durable, fair slices of shared-script discovery and inferred-link planning."""

import json
import logging
import time
from uuid import uuid4

from bs4 import BeautifulSoup, SoupStrainer

from shyhurricane.graph.extract import extract
from shyhurricane.graph.links import LinkPlanner
from shyhurricane.graph.model import identity, projection_snapshot, restore_projection, web_url
from shyhurricane.graph.publication import PublicationConflict
from shyhurricane.graph.retry_policy import transient_neo4j_error
from shyhurricane.index.javascript_analysis import javascript_url_from_map

logger = logging.getLogger(__name__)
CHECKPOINT_VERSION = 1
SLICE_SECONDS = 30
SLICE_CONTEXTS = 100
RETRY_DELAYS = (5, 30, 120)


class Continuations:
    def __init__(self, artifacts):
        self.artifacts = artifacts
        self.connection = artifacts.connection
        self.connection.executescript(
            "CREATE TABLE IF NOT EXISTS graph_continuations ("
            "id TEXT PRIMARY KEY,capture_id TEXT NOT NULL,ticket TEXT,state TEXT NOT NULL,stage TEXT NOT NULL,"
            "checkpoint TEXT NOT NULL,next_attempt REAL NOT NULL DEFAULT 0,retries INTEGER NOT NULL DEFAULT 0,"
            "updated_at REAL NOT NULL,error TEXT NOT NULL DEFAULT '',"
            "contexts_done INTEGER NOT NULL DEFAULT 0,contexts_total INTEGER NOT NULL DEFAULT 0);"
            "CREATE INDEX IF NOT EXISTS graph_continuations_ready "
            "ON graph_continuations(state,next_attempt,updated_at);"
            "CREATE INDEX IF NOT EXISTS graph_continuations_capture ON graph_continuations(capture_id,state);"
            "CREATE INDEX IF NOT EXISTS graph_continuations_updated ON graph_continuations(updated_at);"
        )

    @staticmethod
    def eligible(event):
        data = event["data"]
        mime = next((value for key, value in data.get("response_headers", {}).items()
                     if key.lower() == "content-type"), "").lower()
        return bool(data.get("response_body")) and (
            "javascript" in mime or data["url"].split("?", 1)[0].endswith((".js", ".mjs", ".map"))
        )

    def recover(self):
        with self.connection:
            self.connection.execute("UPDATE graph_continuations SET state='pending' WHERE state='running'")

    def enqueue(self, event, item, open_world):
        key = identity("continuation", CHECKPOINT_VERSION, event, item.get("reanalysis_ticket"))
        row = self.connection.execute("SELECT id FROM graph_continuations WHERE id=?", (key,)).fetchone()
        if row:
            return key
        url = javascript_url_from_map(event["data"]["url"]) or event["data"]["url"]
        state = {
            "version": CHECKPOINT_VERSION, "event": event, "item": item, "open_world": open_world,
            "stage": "discovery", "pending": [url], "seen": [url], "after": "", "contexts": {},
        }
        path = self.artifacts.write(f"continuation-{uuid4().hex}", state)
        with self.connection:
            self.connection.execute(
                "INSERT INTO graph_continuations(id,capture_id,ticket,state,stage,checkpoint,updated_at) "
                "VALUES (?,?,?,'pending','discovery',?,?)",
                (key, event["id"], item.get("reanalysis_ticket"), self.artifacts.reference(path), time.time()),
            )
        return key

    def ready(self):
        row = self.connection.execute(
            "SELECT j.id FROM graph_continuations j WHERE j.state='pending' AND j.next_attempt<=? "
            "AND NOT EXISTS (SELECT 1 FROM graph_continuations older WHERE older.capture_id=j.capture_id "
            "AND older.rowid<j.rowid AND older.state IN ('pending','running')) "
            "ORDER BY j.updated_at,j.id LIMIT 1", (time.time(),),
        ).fetchone()
        return row[0] if row else None

    def load(self, key):
        row = self.connection.execute("SELECT checkpoint FROM graph_continuations WHERE id=?", (key,)).fetchone()
        state = json.loads(self.artifacts.resolve(row[0]).read_text())
        if state.get("version") != CHECKPOINT_VERSION:
            raise ValueError("Unsupported graph continuation checkpoint version")
        return state

    def save(self, key, state, *, status="pending", error="", delay=0, retries=0):
        old = self.connection.execute("SELECT checkpoint FROM graph_continuations WHERE id=?", (key,)).fetchone()[0]
        if "base_projection" in state:
            state["base_projection"] = self.artifacts.reference(state["base_projection"])
        path = self.artifacts.write(f"continuation-{uuid4().hex}", state)
        cursor = state.get("planner", {}).get("cursor", {})
        with self.connection:
            self.connection.execute(
                "UPDATE graph_continuations SET state=?,stage=?,checkpoint=?,next_attempt=?,retries=?,"
                "updated_at=?,error=?,contexts_done=?,contexts_total=? WHERE id=?",
                (status, state["stage"], self.artifacts.reference(path), time.time() + delay,
                 retries, time.time(), error[:1000],
                 cursor.get("context", state.get("contexts_completed", 0)),
                 len(state["contexts"]) if "contexts" in state else state.get("contexts_total", 0), key),
            )
        # A crash before this deletion leaves an unreferenced JSON file, never a lost checkpoint.
        try:
            self.artifacts.resolve(old).unlink(missing_ok=True)
        except OSError:
            logger.warning("Graph checkpoint cleanup deferred: %s", old, exc_info=True)

    def discover(self, state):
        """Page dependent IDs before loading bodies; the cursor advances only after each body."""
        deadline = time.monotonic() + SLICE_SECONDS
        count, reads = 0, 0
        while state["pending"] and count < SLICE_CONTEXTS and reads < 200 and time.monotonic() < deadline:
            current = state["pending"][0]
            reads += 1
            rows = self.connection.execute(
                "SELECT c.id,c.path FROM refs r JOIN captures c ON c.id=r.capture_id "
                "WHERE r.url=? AND r.capture_id>? ORDER BY r.capture_id LIMIT ?",
                (current, state["after"], SLICE_CONTEXTS - count),
            ).fetchall()
            if not rows:
                state["pending"].pop(0)
                state["after"] = ""
                continue
            for capture_id, path in rows:
                if count >= SLICE_CONTEXTS or time.monotonic() >= deadline:
                    return
                event = json.loads(self.artifacts.resolve(path).read_text())
                data = event["data"]
                headers = {key.lower(): value for key, value in data.get("response_headers", {}).items()}
                mime = headers.get("content-type", "").lower()
                if "html" in mime:
                    base = BeautifulSoup(
                        data.get("response_body") or "", "html.parser", parse_only=SoupStrainer("base")
                    ).find("base", href=True)
                    state["contexts"][capture_id] = {
                        "id": capture_id, "url": data["url"],
                        "base": (web_url(base["href"], data["url"]) if base else None) or data["url"],
                    }
                elif "javascript" in mime or data["url"].split("?", 1)[0].endswith((".js", ".mjs")):
                    if data["url"] not in state["seen"]:
                        state["seen"].append(data["url"])
                        state["pending"].append(data["url"])
                state["after"] = capture_id
                count += 1
        if not state["pending"]:
            state["stage"] = "extract"

    def step(self, key, store, *, extractor=extract):
        """Run one slice; return a completed state for worker reconciliation, otherwise None."""
        try:
            state = self.load(key)
        except (OSError, ValueError) as error:
            with self.connection:
                self.connection.execute(
                    "UPDATE graph_continuations SET state='failed',error=? WHERE id=?", (str(error)[:1000], key)
                )
            capture = self.connection.execute(
                "SELECT capture_id FROM graph_continuations WHERE id=?", (key,)
            ).fetchone()[0]
            self.artifacts.status(capture, "failed", str(error))
            logger.error("Unreadable graph continuation %s retained for investigation", key, exc_info=True)
            return None
        with self.connection:
            self.connection.execute("UPDATE graph_continuations SET state='running' WHERE id=?", (key,))
        planner = None
        try:
            if state["stage"] == "discovery":
                self.discover(state)
            elif state["stage"] == "extract":
                projection = extractor(
                    state["event"], self.artifacts, open_world=state["open_world"],
                    document_contexts=list(state["contexts"].values()),
                )
                base = self.artifacts.write(f"projection-{key}", projection_snapshot(projection))
                state.update(
                    projection=projection_snapshot(projection),
                    base_projection=self.artifacts.reference(base), stage="planning",
                )
            elif state["stage"] == "planning":
                projection = restore_projection(state["projection"])
                planner = LinkPlanner(store, projection)
                if "planner" in state:
                    planner.restore(state["planner"])
                complete = planner.plan_slice(seconds=SLICE_SECONDS, contexts=SLICE_CONTEXTS)
                state.update(projection=projection_snapshot(projection), planner=planner.checkpoint())
                if complete:
                    state["stage"] = "publish"
            elif state["stage"] == "publish":
                projection = restore_projection(state["projection"])
                projection.planned_links = state["planner"]["links"]
                store.publish(projection)
                state["stage"] = "reconcile"
            elif state["stage"] == "reconcile":
                return state
            else:
                raise ValueError("Unknown graph continuation stage")
            self.save(key, state)
            logger.debug("Graph continuation %s capture=%s stage=%s contexts=%s/%s", key,
                        state["event"]["id"], state["stage"],
                        state.get("planner", {}).get("cursor", {}).get("context", 0), len(state["contexts"]))
        except Exception as error:
            if planner is not None:
                state.update(projection=projection_snapshot(planner.graph), planner=planner.checkpoint())
            if isinstance(error, PublicationConflict):
                state["projection"] = json.loads(self.artifacts.resolve(state["base_projection"]).read_text())
                state.pop("planner", None)
                state["stage"] = "planning"
                self.save(key, state, error=str(error), delay=5)
            elif transient_neo4j_error(error):
                self.retry(key, state, error)
            else:
                self.save(key, state, status="failed", error=f"{type(error).__name__}: {error}")
                self.artifacts.status(state["event"]["id"], "failed", str(error))
            logger.warning("Graph continuation %s retained stage=%s after failure", key, state["stage"], exc_info=True)
        return None

    def retry(self, key, state, error):
        """Keep transient failures pending with capped backoff until recovery."""
        retries = self.connection.execute(
            "SELECT retries FROM graph_continuations WHERE id=?", (key,)
        ).fetchone()[0]
        delay = RETRY_DELAYS[min(retries, len(RETRY_DELAYS) - 1)]
        self.save(key, state, error=f"{type(error).__name__}: {error}",
                  delay=delay, retries=retries + 1)
        self.artifacts.status(state["event"]["id"], "pending", str(error))

    def finish(self, key, state):
        base = state.get("base_projection")
        completed = {
            "version": CHECKPOINT_VERSION, "stage": "complete", "event": {"id": state["event"]["id"]},
            "contexts_completed": state.get("planner", {}).get("cursor", {}).get("context", 0),
            "contexts_total": len(state["contexts"]),
        }
        self.save(key, completed, status="done")
        if base:
            try:
                self.artifacts.resolve(base).unlink(missing_ok=True)
            except OSError:
                logger.warning("Graph projection cleanup deferred: %s", base, exc_info=True)
        with self.connection:
            self.connection.execute(
                "UPDATE graph_continuations SET state='superseded' WHERE capture_id=? AND state='failed' AND id<>?",
                (state["event"]["id"], key),
            )

    def reconcile(self, key, state, scheduler):
        """Page reconciliation too: shared scripts may have thousands of dependents."""
        from shyhurricane.graph.scheduling import MAX_RECONCILE_CAPTURES

        event = state["event"]
        chain = set(event.get("reconcile_chain", [])) | {event["id"]}
        remaining = event.get("reconcile_remaining", max(0, MAX_RECONCILE_CAPTURES - len(chain)))
        if remaining <= 0:
            return True
        route = state.get("reconciliation")
        if route is None:
            urls = [] if event.get("reconcile") else [event["data"]["url"]]
            bundle = javascript_url_from_map(event["data"]["url"])
            if urls and bundle:
                urls.append(bundle)
            route = {"urls": urls, "after": "", "target_url": "", "phase": "dependents"}
            state["reconciliation"] = route
        deadline = time.monotonic() + SLICE_SECONDS
        processed = 0
        while processed < SLICE_CONTEXTS and time.monotonic() < deadline:
            if route["phase"] == "dependents":
                if not route["urls"]:
                    route.update(phase="targets", after="")
                    continue
                rows = self.connection.execute(
                    "SELECT capture_id,url FROM refs WHERE url=? AND capture_id>? "
                    "ORDER BY capture_id LIMIT ?", (route["urls"][0], route["after"], SLICE_CONTEXTS - processed),
                ).fetchall()
            else:
                headers = {name.lower(): value for name, value in event["data"].get("response_headers", {}).items()}
                mime = headers.get("content-type", "")
                if "html" not in mime and "javascript" not in mime:
                    return True
                rows = self.connection.execute(
                    "SELECT c.id,r.url FROM refs r JOIN captures c ON c.url=r.url WHERE r.capture_id=? "
                    "AND (r.url>? OR (r.url=? AND c.id>?)) ORDER BY r.url,c.id LIMIT ?",
                    (event["id"], route["target_url"], route["target_url"], route["after"],
                     SLICE_CONTEXTS - processed),
                ).fetchall()
            if not rows:
                if route["phase"] == "targets":
                    scheduler.flush()
                    return True
                route["urls"].pop(0)
                route["after"] = ""
                continue
            for capture_id, url in rows:
                if time.monotonic() >= deadline:
                    return False
                if capture_id not in chain:
                    scheduler.request(capture_id, chain, remaining - 1, obligation_id=identity(key, capture_id))
                route["after"] = capture_id
                if route["phase"] == "targets":
                    route["target_url"] = url
                processed += 1
        scheduler.flush()
        return False
