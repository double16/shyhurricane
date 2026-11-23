"""Read retained queue failures: uv run python -m shyhurricane.queue_failures DATA_DIR."""

import argparse
import json
import sqlite3
from contextlib import closing
from pathlib import Path

from shyhurricane.persistent_queue import PERSISTENT_QUEUES


def inspect_failures(root, queue=None, limit=20, resolved=False):
    """Read bounded metadata without opening queues or decoding their payloads."""
    results = []
    for name, directory in PERSISTENT_QUEUES.items():
        database = Path(root) / "queues" / directory / "data.db"
        if (queue and name != queue) or not database.exists():
            continue
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=5)) as connection:
            connection.set_progress_handler(lambda: 1, 2_000_000)
            present = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name='queue_failure'"
            ).fetchone()
            fields = "f.failed_at,f.attempts,f.error_type,f.detail,f.pid,f.stage" if present else (
                "NULL,0,'Unknown','Details unavailable',NULL,NULL"
            )
            join = "LEFT JOIN queue_failure f ON f.queue_id=q._id" if present else ""
            condition = "(q.status=9 OR f.queue_id IS NOT NULL)" if resolved and present else "q.status=9"
            rows = connection.execute(
                f"SELECT q._id,q.status,{fields} FROM ack_queue_default q {join} "
                f"WHERE {condition} ORDER BY q._id LIMIT ?", (limit - len(results),)
            ).fetchall()
            for row in rows:
                results.append(dict(zip(
                    ("queue", "id", "status", "failed_at", "attempts", "error_type", "detail", "pid", "stage"),
                    (name, *row), strict=True,
                )))
        if len(results) >= limit:
            break
    return results


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("data_dir", type=Path)
    parser.add_argument("--queue", choices=PERSISTENT_QUEUES)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--resolved", action="store_true")
    parser.add_argument("--detail", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.limit <= 1000:
        parser.error("limit must be between 1 and 1000")
    rows = inspect_failures(args.data_dir.resolve(), args.queue, args.limit, args.resolved)
    for row in rows:
        if not args.detail:
            row["detail"] = row["detail"].splitlines()[-1][:500]
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
