"""Assessment-local correlation records with short, generation-guarded publications."""

import json
import sqlite3
import time
from contextlib import closing

from shyhurricane.data_paths import state_path
from shyhurricane.graph.model import identity
from shyhurricane.graph.query import scope_predicate
from shyhurricane.investigation.jobs import POLICY_VERSION, JobStore
from shyhurricane.investigation.targets import target_coordinates

MAX_TARGETS = 1000
SCHEMA_VERSION = 3


def store_path(db):
    return state_path("investigation_state") / "correlations.sqlite"


class CorrelationStore(JobStore):
    def __init__(self, db):
        self.path = store_path(db)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, timeout=10)
        try:
            self._initialize()
        except BaseException:
            self.connection.close()
            raise

    def _initialize(self):
        # Serialize initializers from the finding handoff, monitor, and worker processes.
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            version = self.connection.execute("PRAGMA user_version").fetchone()[0]
            populated = self.connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' LIMIT 1").fetchone()
            if populated and version != SCHEMA_VERSION:
                raise ValueError("Unsupported correlation database; rebuild assessment storage")
            statements = (
                "CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY,target TEXT NOT NULL,"
                "host_key TEXT NOT NULL,metadata TEXT NOT NULL,conflicts TEXT NOT NULL,revision TEXT NOT NULL,"
                "source_revision INTEGER NOT NULL DEFAULT 1,state TEXT NOT NULL DEFAULT 'pending',"
                "graph_revision INTEGER NOT NULL DEFAULT -1,policy INTEGER NOT NULL DEFAULT 0,"
                "result TEXT,result_generation INTEGER NOT NULL DEFAULT 0,"
                "derivation_limited INTEGER NOT NULL DEFAULT 0,"
                "updated REAL NOT NULL DEFAULT 0,error TEXT)",
                "CREATE INDEX IF NOT EXISTS finding_scope ON findings(host_key,id)",
                "CREATE TABLE IF NOT EXISTS jobs(kind TEXT,key TEXT,generation INTEGER NOT NULL,"
                "state TEXT NOT NULL,due REAL NOT NULL,requested_revision INTEGER NOT NULL DEFAULT 0,"
                "requested_policy INTEGER NOT NULL DEFAULT 0,"
                "attempts INTEGER NOT NULL DEFAULT 0,error TEXT,PRIMARY KEY(kind,key))",
                "CREATE INDEX IF NOT EXISTS ready_jobs ON jobs(due,kind,key) WHERE state='pending'",
                "CREATE TABLE IF NOT EXISTS targets(id TEXT PRIMARY KEY,payload TEXT NOT NULL,"
                "priority INTEGER NOT NULL,anchor_rank INTEGER NOT NULL,kind TEXT NOT NULL,"
                "hypothesis INTEGER NOT NULL,job_key TEXT NOT NULL)",
                "CREATE INDEX IF NOT EXISTS target_priority ON targets(priority DESC,anchor_rank DESC,id)",
                "CREATE TABLE IF NOT EXISTS categories(target_id TEXT,category TEXT,PRIMARY KEY(target_id,category))",
                "CREATE INDEX IF NOT EXISTS target_category ON categories(category,target_id)",
                "CREATE TABLE IF NOT EXISTS dependencies(target_id TEXT,finding_id TEXT,revision TEXT NOT NULL,"
                "result_generation INTEGER NOT NULL,PRIMARY KEY(target_id,finding_id))",
                "CREATE INDEX IF NOT EXISTS dependency_finding ON dependencies(finding_id,target_id)",
                "CREATE TABLE IF NOT EXISTS associations(key TEXT,finding_id TEXT,PRIMARY KEY(key,finding_id))",
                "CREATE INDEX IF NOT EXISTS association_finding ON associations(finding_id,key)",
                "CREATE TABLE IF NOT EXISTS memberships(key TEXT,finding_id TEXT,PRIMARY KEY(key,finding_id))",
                "CREATE INDEX IF NOT EXISTS membership_finding ON memberships(finding_id,key)",
                "CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
            )
            for statement in statements:
                self.connection.execute(statement)
            self.connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        self.connection.execute("PRAGMA journal_mode=WAL")

    def close(self):
        self.connection.close()

    def setting(self, key, default=None):
        row = self.connection.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def _setting(self, key, value):
        self.connection.execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (key, json.dumps(value)))

    def set_setting(self, key, value):
        with self.connection:
            self._setting(key, value)

    def submit(self, finding_id, target, metadata, conflicts=(), source_revision=1):
        revision = identity(metadata, conflicts)
        host_key = target_coordinates(target).host_key
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            changed = self.connection.execute(
                "INSERT INTO findings(id,target,host_key,metadata,conflicts,revision,source_revision) "
                "VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET metadata=excluded.metadata,conflicts=excluded.conflicts,"
                "revision=excluded.revision,source_revision=excluded.source_revision,state='pending',error=NULL "
                "WHERE findings.revision!=excluded.revision "
                "AND excluded.source_revision>=findings.source_revision",
                (
                    str(finding_id),
                    target,
                    host_key,
                    json.dumps(metadata),
                    json.dumps(list(conflicts)),
                    revision,
                    source_revision,
                ),
            ).rowcount
            if changed:
                self.enqueue("correlate", str(finding_id), revision=self.setting("graph_revision", 0))
                # Existing aggregates become dirty immediately, before graph analysis finishes.
                for (key,) in self.connection.execute(
                    "SELECT key FROM memberships WHERE finding_id=?", (str(finding_id),)
                ):
                    self.enqueue("hotspot", key)

    def load_result(self, finding_id):
        row = self.connection.execute(
            "SELECT result,revision,result_generation,state,graph_revision,policy FROM findings WHERE id=?",
            (finding_id,),
        ).fetchone()
        if not row or not row[0]:
            return None
        result = json.loads(row[0])
        if (
            row[3] != "complete"
            or row[4] != result["graph_revision"]
            or row[5] != POLICY_VERSION
            or result["finding_revisions"].get(finding_id) != row[1]
        ):
            return None
        return {**result, "result_generations": {finding_id: row[2]}}

    def neighbors(self, keys, *, limit=100):
        ids = set()
        distinct = sorted(set(keys))
        for key in distinct[:100]:
            ids.update(
                row[0]
                for row in self.connection.execute(
                    "SELECT finding_id FROM associations WHERE key=? ORDER BY finding_id LIMIT ?", (key, limit + 1)
                )
            )
            if len(ids) > limit:
                break
        records = [value for key in sorted(ids)[:limit] if (value := self.load_result(key)) is not None]
        return records, len(ids) > limit or len(distinct) > 100

    def _delete_target(self, target_id):
        for table in ("targets", "dependencies", "categories"):
            column = "id" if table == "targets" else "target_id"
            self.connection.execute(f"DELETE FROM {table} WHERE {column}=?", (target_id,))

    def _write_target(self, candidate, payload):
        self._delete_target(candidate["id"])
        if candidate.get("excluded"):
            return
        key = candidate.get("shared_key") if candidate["kind"] == "hotspot" else candidate["finding_ids"][0]
        self.connection.execute(
            "INSERT INTO targets VALUES (?,?,?,?,?,?,?)",
            (
                candidate["id"],
                payload,
                candidate["priority"],
                candidate["anchor_rank"],
                candidate["kind"],
                bool(candidate.get("hypothesis")),
                key,
            ),
        )
        self.connection.executemany(
            "INSERT INTO categories VALUES (?,?)",
            ((candidate["id"], value) for value in set(candidate["vulnerability_types"])),
        )
        for finding_id, revision in candidate["finding_revisions"].items():
            generation = self.connection.execute(
                "SELECT result_generation FROM findings WHERE id=?", (finding_id,)
            ).fetchone()[0]
            self.connection.execute(
                "INSERT INTO dependencies VALUES (?,?,?,?)", (candidate["id"], finding_id, revision, generation)
            )

    def publish(self, job, result, graph_revision):
        """Activate an individual result; derived work runs independently without graph reads."""
        result = dict(result)
        next_generation = self.connection.execute(
            "SELECT result_generation+1 FROM findings WHERE id=?", (job["id"],)
        ).fetchone()
        if next_generation is None:
            return False
        result["result_generations"] = {job["id"]: next_generation[0]}
        payload = json.dumps(result)
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            current = self.connection.execute("SELECT revision FROM findings WHERE id=?", (job["id"],)).fetchone()
            if not current or current[0] != job["revision"] or not self.current_job(job):
                return False
            old_keys = {
                row[0]
                for row in self.connection.execute("SELECT key FROM memberships WHERE finding_id=?", (job["id"],))
            }
            self.connection.execute(
                "UPDATE findings SET state='complete',graph_revision=?,policy=?,result=?,result_generation=?,"
                "updated=?,error=NULL,derivation_limited=0 WHERE id=?",
                (graph_revision, POLICY_VERSION, payload, next_generation[0], time.time(), job["id"]),
            )
            self.connection.execute("DELETE FROM associations WHERE finding_id=?", (job["id"],))
            self.connection.execute("DELETE FROM memberships WHERE finding_id=?", (job["id"],))
            keys = (
                set() if result.get("excluded") else set(result.get("hotspot_keys", result.get("association_keys", [])))
            )
            keys = {key for key in keys if key.startswith(("url:", "node:"))}
            pairing = [] if result.get("excluded") else result.get("pairing_keys", result.get("association_keys", []))
            self.connection.executemany("INSERT INTO associations VALUES (?,?)", ((key, job["id"]) for key in pairing))
            self.connection.executemany("INSERT INTO memberships VALUES (?,?)", ((key, job["id"]) for key in keys))
            self._write_target(result, payload)
            self.enqueue("derive", job["id"])
            for key in old_keys | keys:
                self.enqueue("hotspot", key)
            self.acknowledge(job)
            self._setting("last_success", time.time())
        return True

    def dependencies_current(self, candidate):
        for finding_id, revision in candidate["finding_revisions"].items():
            row = self.connection.execute(
                "SELECT revision,result_generation,state,graph_revision,policy FROM findings WHERE id=?", (finding_id,)
            ).fetchone()
            if (
                not row
                or row[0] != revision
                or row[2] != "complete"
                or row[3] != candidate["graph_revision"]
                or row[4] != POLICY_VERSION
                or row[1] != candidate.get("result_generations", {}).get(finding_id)
            ):
                return False
        return True

    def publish_derived(self, job, candidates, *, dependency=None, waiting=False, limited=False):
        prepared = [(candidate, json.dumps(candidate)) for candidate in candidates]
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            if not self.current_job(job):
                return False
            if dependency is not None and not self.dependencies_current(dependency):
                return False
            if any(not self.dependencies_current(candidate) for candidate in candidates):
                return False
            if waiting:
                # Keep the old aggregate until its selected members have compatible results.
                self.connection.execute(
                    "UPDATE jobs SET due=? WHERE kind=? AND key=? AND generation=?",
                    (time.time() + 5, job["kind"], job["id"], job["generation"]),
                )
                return False
            if job["kind"] == "hotspot":
                self._delete_target(identity("hotspot", job["id"]))
            elif not limited:
                # A missing fresh neighbor is not evidence that an older supported chain vanished.
                # Retain it as stale while any contributor is pending, failed, or on another revision.
                obsolete = self.connection.execute(
                    "SELECT t.id FROM targets t JOIN dependencies d ON d.target_id=t.id "
                    "WHERE t.kind='chain' AND d.finding_id=? AND NOT EXISTS ("
                    "SELECT 1 FROM dependencies other JOIN findings f ON f.id=other.finding_id "
                    "WHERE other.target_id=t.id AND (f.state!='complete' OR f.graph_revision!=? OR f.policy!=?))",
                    (job["id"], dependency["graph_revision"], POLICY_VERSION),
                ).fetchall()
                for (target_id,) in obsolete:
                    self._delete_target(target_id)
            for candidate, payload in prepared:
                self._write_target(candidate, payload)
            if job["kind"] == "derive":
                self.connection.execute("UPDATE findings SET derivation_limited=? WHERE id=?", (limited, job["id"]))
            self.acknowledge(job)
        return True

    def hotspot_members(self, key, revision):
        rows = self.connection.execute(
            "SELECT m.finding_id,f.state,f.graph_revision FROM memberships m JOIN findings f ON f.id=m.finding_id "
            "WHERE m.key=? ORDER BY m.finding_id LIMIT 101",
            (key,),
        ).fetchall()
        members = []
        waiting = False
        for finding_id, state, graph in rows[:100]:
            value = self.load_result(finding_id)
            if state != "complete" or graph != revision or value is None:
                waiting = True
            elif not value.get("excluded"):
                members.append(value)
        return members, len(rows) > 100, waiting

    def read(self, scope, vulnerability_type=None, include_hypotheses=True):
        with self.connection:
            self.connection.execute("BEGIN")
            return self._read(scope, vulnerability_type, include_hypotheses)

    def _read(self, scope, vulnerability_type, include_hypotheses):
        contains = scope_predicate(scope)
        host_key = target_coordinates(scope).host_key
        rows = self.connection.execute(
            "SELECT id,target,state,graph_revision,revision FROM findings WHERE "
            "host_key=? OR (host_key>=? AND host_key<?) ORDER BY id LIMIT 10001",
            (host_key, f"{host_key}.", f"{host_key}.\uffff"),
        ).fetchall()
        truncated = len(rows) > 10000
        selected = {}
        for row in rows[:10000]:
            if "://" in scope and "://" not in row[1]:
                continue
            if contains(target_coordinates(row[1]).comparison_url):
                selected[row[0]] = row
        self.connection.execute("CREATE TEMP TABLE IF NOT EXISTS selected_findings(id TEXT PRIMARY KEY)")
        self.connection.execute("DELETE FROM selected_findings")
        self.connection.executemany("INSERT INTO selected_findings VALUES (?)", ((key,) for key in selected))
        # Filter using scalar headers and dependency indexes, never witness JSON.
        cursor = self.connection.execute(
            "SELECT t.id,t.kind,coalesce(j.state,'complete') FROM targets t "
            "LEFT JOIN jobs j ON j.kind=CASE WHEN t.kind='hotspot' THEN 'hotspot' ELSE 'derive' END "
            "AND j.key=t.job_key "
            "WHERE EXISTS (SELECT 1 FROM dependencies d JOIN selected_findings s ON s.id=d.finding_id "
            "WHERE d.target_id=t.id) AND NOT EXISTS (SELECT 1 FROM dependencies d "
            "WHERE d.target_id=t.id AND NOT EXISTS (SELECT 1 FROM selected_findings s WHERE s.id=d.finding_id)) "
            "AND (? OR t.hypothesis=0) AND (? IS NULL OR EXISTS (SELECT 1 FROM categories c "
            "WHERE c.target_id=t.id AND c.category=?)) "
            "ORDER BY t.priority DESC,t.anchor_rank DESC,t.id LIMIT ?",
            (include_hypotheses, vulnerability_type, vulnerability_type, MAX_TARGETS + 1),
        )
        results = []
        revision = self.setting("graph_revision", 0)
        while headers := cursor.fetchmany(100):
            available = MAX_TARGETS - len(results)
            if len(headers) > available:
                truncated = True
                headers = headers[:available]
            if not headers:
                break
            ids = [row[0] for row in headers]
            placeholders = ",".join("?" for _ in ids)
            payloads = dict(
                self.connection.execute(f"SELECT id,payload FROM targets WHERE id IN ({placeholders})", ids)
            )
            dependency_map = {key: [] for key in ids}
            for row in self.connection.execute(
                "SELECT d.target_id,d.revision,f.revision,f.state,f.graph_revision,d.result_generation,"
                "f.result_generation,coalesce(j.state,'complete'),f.derivation_limited FROM dependencies d "
                "JOIN findings f ON f.id=d.finding_id LEFT JOIN jobs j ON j.kind='derive' AND j.key=f.id "
                f"WHERE d.target_id IN ({placeholders})",
                ids,
            ):
                dependency_map[row[0]].append(row[1:])
            for target_id, kind, job_state in headers:
                item = json.loads(payloads[target_id])
                dependencies = dependency_map[target_id]
                stale = item["graph_revision"] != revision or any(
                    a != b or state != "complete" or graph != revision or old_generation != generation
                    for a, b, state, graph, old_generation, generation, _, _ in dependencies
                )
                if kind != "target":
                    stale |= job_state != "complete" or any(row[6] != "complete" for row in dependencies)
                item = {
                    key: value
                    for key, value in item.items()
                    if key not in {"association_keys", "pairing_keys", "hotspot_keys", "metadata", "result_generations"}
                }
                if any(row[7] for row in dependencies):
                    gap = "Related finding selection limited to 100 neighbors or keys"
                    item["contexts_limited"] = True
                    if gap not in item["analysis_gaps"]:
                        item["analysis_gaps"] = [*item["analysis_gaps"], gap]
                retained_contexts = [url for url in item["context_urls"] if contains(url)]
                witnesses = [
                    w
                    for w in item["witnesses"]
                    if all(
                        contains(node.get("url", ""))
                        or (
                            node.get("kind") != "resource"
                            and any(contains(url) for url in node.get("context_urls", []))
                        )
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
                if kind != "target":
                    states.add(job_state)
                    states.update(dependency[6] for dependency in dependencies)
                item["materialization_status"] = (
                    "failed"
                    if "failed" in states
                    else "pending"
                    if "pending" in states
                    else "stale"
                    if stale
                    else "complete"
                )
                results.append(item)
        statuses = {
            name: sum(row[2] == name for row in selected.values()) for name in ("pending", "failed", "complete")
        }
        statuses["stale"] = sum(row[3] != revision for row in selected.values())
        return {
            "results": results,
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
            "work": self.work_status(),
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
    with closing(CorrelationStore(db)) as store:
        return store.retry()


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
