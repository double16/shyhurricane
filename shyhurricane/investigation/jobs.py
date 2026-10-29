"""Durable generation-guarded work and bounded refresh sweeps."""

import json
import time

POLICY_VERSION = 3
BATCH_SIZE = 100
KINDS = ("correlate", "derive", "hotspot")


class JobStore:
    def enqueue(self, kind, key, *, revision=0, force=True):
        """Called inside the transaction that changes the corresponding obligation."""
        self.connection.execute(
            "INSERT INTO jobs(kind,key,generation,state,due,requested_revision,requested_policy) "
            "VALUES (?,?,1,'pending',?,?,?) ON CONFLICT(kind,key) DO UPDATE SET "
            "generation=jobs.generation+1,state='pending',"
            "due=CASE WHEN ? OR jobs.state='complete' THEN excluded.due ELSE jobs.due END,"
            "attempts=CASE WHEN ? THEN 0 ELSE jobs.attempts END,"
            "error=CASE WHEN ? THEN NULL ELSE jobs.error END,"
            "requested_revision=max(jobs.requested_revision,excluded.requested_revision),"
            "requested_policy=excluded.requested_policy "
            "WHERE ? OR (jobs.state!='failed' AND (jobs.requested_revision<excluded.requested_revision "
            "OR jobs.requested_policy!=excluded.requested_policy))",
            (kind, key, time.time(), revision, POLICY_VERSION, force, force, force, force),
        )

    def sweep(self, revision):
        """Finish each cursor pass, then coalesce another pass for newer publications."""
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            sweep = self.setting("sweep")
            if sweep is None:
                if self.setting("swept", [-1, 0]) == [revision, POLICY_VERSION]:
                    return
                sweep = {"revision": revision, "policy": POLICY_VERSION, "after": ""}
            rows = self.connection.execute(
                "SELECT id,state,graph_revision,policy FROM findings WHERE id>? ORDER BY id LIMIT ?",
                (sweep["after"], BATCH_SIZE),
            ).fetchall()
            for key, state, graph, policy in rows:
                if state != "failed" and (graph < sweep["revision"] or policy != sweep["policy"]):
                    self.enqueue("correlate", key, revision=sweep["revision"], force=False)
            if len(rows) == BATCH_SIZE:
                sweep["after"] = rows[-1][0]
                self._setting("sweep", sweep)
            else:
                self._setting("swept", [sweep["revision"], sweep["policy"]])
                self._setting("sweep", None)

    def _select_job(self, kinds):
        placeholders = ",".join("?" for _ in kinds)
        row = self.connection.execute(
            "SELECT kind,key,generation,attempts FROM jobs INDEXED BY ready_jobs "
            f"WHERE state='pending' AND due<=? AND kind IN ({placeholders}) "
            "ORDER BY due,kind,key LIMIT 1",
            (time.time(), *kinds),
        ).fetchone()
        if row is None:
            return None
        job = dict(zip(("kind", "id", "generation", "attempts"), row))
        if job["kind"] != "hotspot":
            finding = self.connection.execute(
                "SELECT target,metadata,conflicts,revision FROM findings WHERE id=?", (job["id"],)
            ).fetchone()
            job.update(zip(("target", "metadata", "conflicts", "revision"), finding))
            for key in ("metadata", "conflicts"):
                job[key] = json.loads(job[key])
        return job

    def work(self, graph_revision):
        self.sweep(graph_revision)
        return self._select_job(("correlate",))

    def next_job(self, graph_revision):
        self.sweep(graph_revision)
        return self._select_job(KINDS)

    def current_job(self, job):
        return (
            self.connection.execute(
                "SELECT 1 FROM jobs WHERE kind=? AND key=? AND generation=? AND state='pending'",
                (job["kind"], job["id"], job["generation"]),
            ).fetchone()
            is not None
        )

    def acknowledge(self, job):
        self.connection.execute(
            "UPDATE jobs SET state='complete',attempts=0,error=NULL WHERE kind=? AND key=? AND generation=?",
            (job["kind"], job["id"], job["generation"]),
        )

    def failed(self, job, error, *, transient):
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            if not self.current_job(job):
                return
            state = "pending" if transient else "failed"
            due = time.time() + min(120, 5 * 2 ** min(job["attempts"], 5))
            self.connection.execute(
                "UPDATE jobs SET state=?,error=?,attempts=attempts+1,due=? WHERE kind=? AND key=? AND generation=?",
                (state, type(error).__name__, due, job["kind"], job["id"], job["generation"]),
            )
            if job["kind"] == "correlate":
                self.connection.execute(
                    "UPDATE findings SET state=?,error=?,updated=? WHERE id=? AND revision=?",
                    (state, type(error).__name__, time.time(), job["id"], job["revision"]),
                )

    def attempts(self, finding_id):
        return self.connection.execute(
            "SELECT attempts FROM jobs WHERE kind='correlate' AND key=?", (finding_id,)
        ).fetchone()[0]

    def retry(self):
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            rows = self.connection.execute("SELECT kind,key FROM jobs WHERE state='failed'").fetchall()
            for kind, key in rows:
                self.enqueue(kind, key)
                if kind == "correlate":
                    self.connection.execute("UPDATE findings SET state='pending',error=NULL WHERE id=?", (key,))
        return len(rows)

    def work_status(self):
        result = {kind: {"pending": 0, "failed": 0} for kind in KINDS}
        for kind, state, count in self.connection.execute(
            "SELECT kind,state,count(*) FROM jobs WHERE state!='complete' GROUP BY kind,state"
        ):
            result[kind][state] = count
        return result
