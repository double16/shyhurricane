"""Resumably queue retained captures for a selected library-analysis policy."""

import argparse
import json
import os
import sqlite3
from contextlib import closing

from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.policy import ANALYZER_VERSION, library_analysis
from shyhurricane.graph.query import scope_predicate
from shyhurricane.graph.scheduling import MAX_RECONCILE_CAPTURES, ReanalysisScheduler
from shyhurricane.persistent_queue import get_persistent_queue, persistent_queue_path


def rebuild(db, *, mode="summary", target=None, dry_run=False):
    mode = library_analysis(mode)
    contains = scope_predicate(target) if target else lambda url: True
    path = persistent_queue_path(db, "graph_state") / "artifacts.sqlite"
    result = {"selected": 0, "queued": 0, "skipped": 0, "dry_run": dry_run, "mode": mode}
    if not path.exists():
        return result
    # Dry runs do not initialize schemas, queues, artifacts, or target connections.
    with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)) as connection:
        captures = [row for row in connection.execute("SELECT id,url FROM captures ORDER BY id") if contains(row[1])]
    result["selected"] = len(captures)
    if dry_run:
        return result
    artifacts = ArtifactStore(db)
    try:
        queue = get_persistent_queue(db, "graph_queue", auto_resume=False)
        try:
            scheduler = ReanalysisScheduler(artifacts, queue)
            with artifacts.lock("graph-rebuild"):
                for capture_id, _ in captures:
                    row = artifacts.connection.execute(
                        "SELECT p.mode,p.completed_version,p.completed_mode,r.state FROM analysis_policies p "
                        "LEFT JOIN reanalysis r ON r.capture_id=p.capture_id WHERE p.capture_id=?",
                        (capture_id,),
                    ).fetchone()
                    if (
                        row
                        and row[0] == mode
                        and (row[1:3] == (ANALYZER_VERSION, mode) or row[3] in {"pending", "running"})
                    ):
                        result["skipped"] += 1
                        continue
                    with artifacts.connection:
                        artifacts.connection.execute(
                            "INSERT INTO analysis_policies(capture_id,mode) VALUES (?,?) "
                            "ON CONFLICT(capture_id) DO UPDATE SET mode=excluded.mode",
                            (capture_id, mode),
                        )
                    scheduler.request(capture_id, set(), MAX_RECONCILE_CAPTURES - 2)
                    result["queued"] += 1
                scheduler.flush()
        finally:
            queue.close()
    finally:
        artifacts.close()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default=os.environ.get("QDRANT", "shyhurricane.db"))
    parser.add_argument("--target", help="Host, netloc, or HTTP(S) URL prefix")
    parser.add_argument("--mode", choices=("summary", "full"), default="summary")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    print(json.dumps(rebuild(args.database, mode=args.mode, target=args.target, dry_run=args.dry_run)))


if __name__ == "__main__":
    main()
