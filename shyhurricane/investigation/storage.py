"""Assessment-local durable obligations and atomically replaced correlation witnesses."""

import json
import sqlite3
import time
from contextlib import closing
from urllib.parse import urlsplit

from shyhurricane.data_paths import state_path
from shyhurricane.graph.model import identity
from shyhurricane.graph.query import scope_predicate

POLICY_VERSION = 1
MAX_TARGETS = 1000


def store_path(db):
    return state_path("investigation_state") / "correlations.sqlite"


class CorrelationStore:
    def __init__(self, db):
        self.path = store_path(db)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, timeout=10)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.executescript(
            "CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY,target TEXT NOT NULL,"
            "host_key TEXT NOT NULL,metadata TEXT NOT NULL,conflicts TEXT NOT NULL,revision TEXT NOT NULL,"
            "source_revision INTEGER NOT NULL DEFAULT 1,"
            "state TEXT NOT NULL DEFAULT 'pending',graph_revision INTEGER NOT NULL DEFAULT -1,"
            "policy INTEGER NOT NULL DEFAULT 0,result TEXT,updated REAL NOT NULL DEFAULT 0,"
            "retry_at REAL NOT NULL DEFAULT 0,attempts INTEGER NOT NULL DEFAULT 0,error TEXT);"
            "CREATE INDEX IF NOT EXISTS finding_scope ON findings(host_key,id);"
            "CREATE INDEX IF NOT EXISTS finding_work ON findings(state,retry_at,updated);"
            "CREATE TABLE IF NOT EXISTS targets (id TEXT PRIMARY KEY,payload TEXT NOT NULL,priority INTEGER NOT NULL, "
            "anchor_rank INTEGER NOT NULL);"
            "CREATE INDEX IF NOT EXISTS target_priority ON targets(priority DESC,anchor_rank DESC,id);"
            "CREATE TABLE IF NOT EXISTS dependencies (target_id TEXT NOT NULL,finding_id TEXT NOT NULL,"
            "revision TEXT NOT NULL,PRIMARY KEY(target_id,finding_id));"
            "CREATE INDEX IF NOT EXISTS dependency_finding ON dependencies(finding_id,target_id);"
            "CREATE TABLE IF NOT EXISTS associations (key TEXT NOT NULL,finding_id TEXT NOT NULL,"
            "PRIMARY KEY(key,finding_id));"
            "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY,value TEXT NOT NULL);"
        )

    def close(self):
        self.connection.close()

    def setting(self, key, default=None):
        row = self.connection.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set_setting(self, key, value):
        with self.connection:
            self.connection.execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (key, json.dumps(value)))

    def submit(self, finding_id, target, metadata, conflicts=(), source_revision=1):
        revision = identity(metadata, conflicts)
        parsed = urlsplit(target if "://" in target else f"https://{target}")
        host_key = ".".join(reversed((parsed.hostname or "").lower().split(".")))
        with self.connection:
            self.connection.execute(
                "INSERT INTO findings(id,target,host_key,metadata,conflicts,revision,source_revision) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET metadata=excluded.metadata,conflicts=excluded.conflicts,"
                "revision=excluded.revision,source_revision=excluded.source_revision,state='pending',retry_at=0,attempts=0,error=NULL "
                "WHERE findings.revision!=excluded.revision AND excluded.source_revision>=findings.source_revision",
                (
                    str(finding_id),
                    target,
                    host_key,
                    json.dumps(metadata),
                    json.dumps(list(conflicts)),
                    revision,
                    source_revision,
                ),
            )

    def work(self, graph_revision):
        row = self.connection.execute(
            "SELECT id,target,metadata,conflicts,revision FROM findings "
            "WHERE state!='failed' AND retry_at<=? AND "
            "(state='pending' OR graph_revision!=? OR policy!=?) ORDER BY updated,id LIMIT 1",
            (time.time(), graph_revision, POLICY_VERSION),
        ).fetchone()
        if not row:
            return None
        return dict(
            zip(
                ("id", "target", "metadata", "conflicts", "revision"),
                (row[0], row[1], json.loads(row[2]), json.loads(row[3]), row[4]),
            )
        )

    def failed(self, job, error, *, transient):
        with self.connection:
            self.connection.execute(
                "UPDATE findings SET state=?,error=?,attempts=attempts+1,retry_at=?,updated=? "
                "WHERE id=? AND revision=?",
                (
                    "pending" if transient else "failed",
                    type(error).__name__,
                    time.time() + min(120, 5 * 2 ** min(self.attempts(job["id"]), 5)),
                    time.time(),
                    job["id"],
                    job["revision"],
                ),
            )

    def attempts(self, finding_id):
        return self.connection.execute("SELECT attempts FROM findings WHERE id=?", (finding_id,)).fetchone()[0]

    def neighbors(self, keys, *, limit=100):
        ids = set()
        distinct_keys = sorted(set(keys))
        for key in distinct_keys[:100]:
            ids.update(
                row[0]
                for row in self.connection.execute(
                    "SELECT finding_id FROM associations WHERE key=? ORDER BY finding_id LIMIT ?", (key, limit + 1)
                )
            )
            if len(ids) > limit:
                break
        records = []
        for finding_id in sorted(ids)[:limit]:
            row = self.connection.execute(
                "SELECT result FROM findings WHERE id=? AND result IS NOT NULL", (finding_id,)
            ).fetchone()
            if row:
                records.append(json.loads(row[0]))
        return records, len(ids) > limit or len(distinct_keys) > 100

    def publish(self, job, result, derived, graph_revision):
        """Do not activate a result computed before a concurrent finding enrichment."""
        with self.connection:
            current = self.connection.execute("SELECT revision FROM findings WHERE id=?", (job["id"],)).fetchone()
            if not current or current[0] != job["revision"]:
                return False
            obsolete = [
                row[0]
                for row in self.connection.execute(
                    "SELECT target_id FROM dependencies WHERE finding_id=?", (job["id"],)
                )
            ]
            for target_id in obsolete:
                self.connection.execute("DELETE FROM targets WHERE id=?", (target_id,))
                self.connection.execute("DELETE FROM dependencies WHERE target_id=?", (target_id,))
            self.connection.execute("DELETE FROM associations WHERE finding_id=?", (job["id"],))
            for key in result.get("association_keys", []):
                self.connection.execute("INSERT OR IGNORE INTO associations VALUES (?,?)", (key, job["id"]))
            for candidate in [result, *derived]:
                if candidate.get("excluded"):
                    continue
                self.connection.execute(
                    "INSERT OR REPLACE INTO targets VALUES (?,?,?,?)",
                    (candidate["id"], json.dumps(candidate), candidate["priority"], candidate["anchor_rank"]),
                )
                self.connection.execute("DELETE FROM dependencies WHERE target_id=?", (candidate["id"],))
                for finding_id, revision in candidate["finding_revisions"].items():
                    self.connection.execute(
                        "INSERT INTO dependencies VALUES (?,?,?)", (candidate["id"], finding_id, revision)
                    )
            self.connection.execute(
                "UPDATE findings SET state='complete',graph_revision=?,policy=?,result=?,updated=?,"
                "attempts=0,retry_at=0,error=NULL WHERE id=?",
                (graph_revision, POLICY_VERSION, json.dumps(result), time.time(), job["id"]),
            )
            self.connection.execute(
                "INSERT OR REPLACE INTO settings VALUES ('last_success',?)", (json.dumps(time.time()),)
            )
        return True

    def read(self, scope, vulnerability_type=None, include_hypotheses=True):
        contains = scope_predicate(scope)
        parsed = urlsplit(scope if "://" in scope else f"https://{scope}")
        host_key = ".".join(reversed(parsed.hostname.lower().split(".")))
        # Indexed host range, followed by exact URL/port verification. No finding bodies are loaded.
        rows = self.connection.execute(
            "SELECT id,target,state,graph_revision,revision,updated,error FROM findings WHERE "
            "host_key=? OR (host_key>=? AND host_key<?) ORDER BY id LIMIT 10001",
            (host_key, f"{host_key}.", f"{host_key}.\uffff"),
        ).fetchall()
        truncated = len(rows) > 10000
        selected = {}
        for row in rows[:10000]:
            target = row[1]
            if "://" in scope and "://" not in target:
                continue
            if contains(target if "://" in target else f"https://{target}/"):
                selected[row[0]] = row
        results = []
        revision = self.setting("graph_revision", 0)
        target_rows = []
        if selected:
            placeholders = ",".join("?" for _ in selected)
            target_rows = self.connection.execute(
                "SELECT DISTINCT t.id,t.payload,t.priority,t.anchor_rank FROM targets t "
                "JOIN dependencies d ON d.target_id=t.id "
                f"WHERE d.finding_id IN ({placeholders}) "
                "ORDER BY t.priority DESC,t.anchor_rank DESC,t.id LIMIT 10001",
                tuple(selected),
            ).fetchall()
            truncated |= len(target_rows) > 10000
        for target_id, payload, _, _ in target_rows[:10000]:
            item = json.loads(payload)
            # Never leak another scope through a multi-finding chain or hotspot.
            if not set(item["finding_ids"]) <= selected.keys():
                continue
            if vulnerability_type and vulnerability_type not in item["vulnerability_types"]:
                continue
            if item.get("hypothesis") and not include_hypotheses:
                continue
            dependencies = list(
                self.connection.execute(
                    "SELECT d.revision,f.revision,f.state,f.graph_revision FROM dependencies d "
                    "JOIN findings f ON f.id=d.finding_id WHERE d.target_id=?",
                    (target_id,),
                )
            )
            stale = item["graph_revision"] != revision or any(
                a != b or state != "complete" or graph != revision for a, b, state, graph in dependencies
            )
            item = {key: value for key, value in item.items() if key not in {"association_keys", "metadata"}}
            retained_contexts = [url for url in item["context_urls"] if contains(url)]
            witnesses = [
                w
                for w in item["witnesses"]
                if all(
                    contains(node.get("url", ""))
                    or (node.get("kind") != "resource" and any(contains(url) for url in node.get("context_urls", [])))
                    for node in w.get("nodes", [])
                )
            ]
            if retained_contexts != item["context_urls"] or witnesses != item["witnesses"]:
                item["scope_limited"] = True
                item["analysis_gaps"] = [*item["analysis_gaps"], "Related contexts outside requested scope omitted"]
                item["context_urls"] = retained_contexts
                item["witnesses"] = witnesses
            item["evidence_ids"] = sorted(
                {step["evidence_id"] for w in witnesses for step in w.get("steps", []) if step.get("evidence_id")}
            )
            item["follow_up"] = [
                {**call, "arguments": {**call["arguments"], "scope": scope}}
                for call in item["follow_up"]
                if "scope" in call["arguments"]
            ] + [
                {"tool": "fetch_application_graph_evidence", "arguments": {"evidence_id": key}}
                for key in item["evidence_ids"][:3]
            ]
            item["stale"] = stale
            states = {dependency[2] for dependency in dependencies}
            item["materialization_status"] = (
                "failed"
                if "failed" in states
                else "pending" if "pending" in states else "stale" if stale else "complete"
            )
            results.append(item)
            if len(results) > MAX_TARGETS:
                truncated = True
                break
        results.sort(key=lambda item: (-item["priority"], -item["anchor_rank"], item["id"]))
        statuses = {
            name: sum(row[2] == name for row in selected.values()) for name in ("pending", "failed", "complete")
        }
        statuses["stale"] = sum(row[3] != revision for row in selected.values())
        return {
            "results": results[:MAX_TARGETS],
            "status": statuses,
            "graph_revision": revision,
            "policy_version": POLICY_VERSION,
            "retrieval_truncated": truncated,
            "truncation_reasons": ["result_limit"] if truncated else [],
            "analysis_gaps": (
                ["Materialization has not discovered all scoped findings yet"]
                if self.setting("reconcile_complete", False) is False
                else []
            ),
        }

    def status(self):
        counts = dict(self.connection.execute("SELECT state,count(*) FROM findings GROUP BY state"))
        revision = self.setting("graph_revision", 0)
        stale = self.connection.execute(
            "SELECT count(*) FROM findings WHERE graph_revision!=?", (revision,)
        ).fetchone()[0]
        return {
            "pending": counts.get("pending", 0),
            "failed": counts.get("failed", 0),
            "completed": counts.get("complete", 0),
            "stale": stale,
            "graph_revision": revision,
            "policy_version": POLICY_VERSION,
            "last_successful_refresh": self.setting("last_success"),
            "last_reconciliation": self.setting("last_reconciliation"),
            "error": self.setting("worker_error"),
        }


def correlation_status(db):
    if not store_path(db).exists():
        return {"pending": 0, "failed": 0, "completed": 0, "policy_version": POLICY_VERSION}
    with closing(CorrelationStore(db)) as store:
        return store.status()


def retry_correlations(db):
    if not store_path(db).exists():
        return 0
    with closing(CorrelationStore(db)) as store, store.connection:
        return store.connection.execute(
            "UPDATE findings SET state='pending',retry_at=0,attempts=0,error=NULL WHERE state='failed'"
        ).rowcount


def submit_document(db, doc):
    with closing(CorrelationStore(db)) as store:
        target = doc.meta.get("url") or doc.meta.get("netloc") or doc.meta["host"]
        store.submit(
            doc.id,
            target,
            doc.meta.get("finding_metadata", {}),
            doc.meta.get("finding_metadata_conflicts", []),
            doc.meta.get("finding_metadata_revision", 1),
        )
