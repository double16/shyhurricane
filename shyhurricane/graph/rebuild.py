"""Resumably queue retained captures for a selected library-analysis policy."""

import argparse
import json
import os
import sqlite3
from contextlib import closing
from uuid import uuid4

from shyhurricane.data_paths import add_data_dir_argument, qdrant_location, resolve_data_dir
from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.epochs import Epochs
from shyhurricane.graph.policy import ANALYZER_VERSION, library_analysis
from shyhurricane.graph.query import scope_predicate
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
            Epochs(artifacts, None).close()
            artifacts.connection.execute(
                "CREATE TABLE IF NOT EXISTS graph_rebuild_outbox (capture_id TEXT PRIMARY KEY,"
                "mode TEXT,version INTEGER,token TEXT,delivered INTEGER NOT NULL DEFAULT 0)"
            )
            with artifacts.lock("graph-rebuild"):
                for capture_id, _ in captures:
                    row = artifacts.connection.execute(
                        "SELECT p.mode,p.completed_version,p.completed_mode,r.mode,r.version,i.state "
                        "FROM analysis_policies p LEFT JOIN graph_rebuild_outbox r ON r.capture_id=p.capture_id "
                        "LEFT JOIN graph_epoch_inputs i ON i.request_token=r.token WHERE p.capture_id=?",
                        (capture_id,),
                    ).fetchone()
                    if (
                        row
                        and row[0] == mode
                        and row[5] != "failed"
                        and (row[1:3] == (ANALYZER_VERSION, mode) or row[3:5] == (mode, ANALYZER_VERSION))
                    ):
                        result["skipped"] += 1
                        continue
                    with artifacts.connection:
                        artifacts.connection.execute(
                            "INSERT INTO analysis_policies(capture_id,mode) VALUES (?,?) "
                            "ON CONFLICT(capture_id) DO UPDATE SET mode=excluded.mode",
                            (capture_id, mode),
                        )
                        if row and row[5] == "failed" and row[3:5] == (mode, ANALYZER_VERSION):
                            artifacts.connection.execute(
                                "UPDATE graph_rebuild_outbox SET delivered=0 WHERE capture_id=?", (capture_id,)
                            )
                        else:
                            artifacts.connection.execute(
                                "INSERT OR REPLACE INTO graph_rebuild_outbox VALUES (?,?,?,?,0)",
                                (capture_id, mode, ANALYZER_VERSION, uuid4().hex),
                            )
                    result["queued"] += 1
                flush_rebuild_requests(artifacts, queue)
        finally:
            queue.close()
    finally:
        artifacts.close()
    return result


def flush_rebuild_requests(artifacts, queue):
    """Deliver committed policy requests; a crash can duplicate but cannot lose a token."""
    if not artifacts.connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='graph_rebuild_outbox'"
    ).fetchone():
        return
    for capture_id, token in artifacts.connection.execute(
        "SELECT capture_id,token FROM graph_rebuild_outbox WHERE delivered=0"
    ).fetchall():
        reference = artifacts.connection.execute(
            "SELECT path FROM captures WHERE id=?", (capture_id,)
        ).fetchone()[0]
        event = artifacts.read(reference)
        queue.put({**event, "rebuild_token": token})
        with artifacts.connection:
            artifacts.connection.execute(
                "UPDATE graph_rebuild_outbox SET delivered=1 WHERE capture_id=? AND token=?",
                (capture_id, token),
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    add_data_dir_argument(parser)
    parser.add_argument("--target", help="Host, netloc, or HTTP(S) URL prefix")
    parser.add_argument("--mode", choices=("summary", "full"), default="summary")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        root = resolve_data_dir(args.data_dir)
        os.environ["DATA_DIR"] = str(root)
        db = qdrant_location(root)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(rebuild(db, mode=args.mode, target=args.target, dry_run=args.dry_run)))


if __name__ == "__main__":
    main()
