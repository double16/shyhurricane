"""Queue previously stored representations without contacting target applications."""

import argparse
import json
import os

from haystack import Document
from qdrant_client import QdrantClient

from shyhurricane.data_paths import add_data_dir_argument, configure_data_dir, qdrant_location, resolve_data_dir
from shyhurricane.db import qdrant_host_port
from shyhurricane.graph.artifacts import ArtifactStore
from shyhurricane.graph.model import capture_event
from shyhurricane.persistent_queue import get_persistent_queue


class StoredCollection:
    """Stream payloads without vectors or loading a complete collection into memory."""

    def __init__(self, db: str, kind: str):
        self.db = db
        self.kind = kind

    def filter_documents(self):
        host, port = qdrant_host_port(self.db)
        client = QdrantClient(host=host, port=port)
        try:
            if not client.collection_exists(self.kind):
                return
            offset = None
            while True:
                records, offset = client.scroll(
                    collection_name=self.kind, offset=offset, limit=100, with_payload=True, with_vectors=False
                )
                for record in records:
                    payload = record.payload or {}
                    yield Document(
                        id=payload.get("id", str(record.id)),
                        content=payload.get("content"),
                        meta=payload.get("meta", {}),
                    )
                if offset is None:
                    break
        finally:
            client.close()


def backfill(db: str, *, stores=None) -> int:
    artifacts = ArtifactStore(db)
    queue = get_persistent_queue(db, "graph_queue", auto_resume=False)
    checkpoint = artifacts.root / "backfill.json"
    artifacts.connection.execute("CREATE TABLE IF NOT EXISTS backfill (key TEXT PRIMARY KEY)")
    total = 0
    try:
        stores = stores or {kind: StoredCollection(db, kind) for kind in ("content", "network", "forms")}
        for kind, store in stores.items():
            for doc in store.filter_documents():
                key = f"{kind}:{doc.id}"
                if artifacts.connection.execute("SELECT 1 FROM backfill WHERE key=?", (key,)).fetchone():
                    continue
                meta = doc.meta
                headers = json.loads(meta.get("response_headers", "{}"))
                if not headers.get("Content-Type"):
                    headers["Content-Type"] = meta.get("content_type", "")
                data = {
                    "url": meta["url"],
                    "method": meta.get("http_method", "GET"),
                    "timestamp": meta.get("timestamp", ""),
                    "request_headers": json.loads(meta.get("request_headers", "{}")),
                    "response_headers": headers,
                    "response_code": meta.get("status_code", 200),
                    "response_body": doc.content if kind == "content" else "",
                    "request_body": None,
                    "forms": json.loads(doc.content) if kind == "forms" else None,
                }
                event = capture_event(data, backfill=True)
                event = artifacts.register(event)
                queue.put(event)
                with artifacts.connection:
                    artifacts.connection.execute("INSERT OR IGNORE INTO backfill VALUES (?)", (key,))
                # Publication is atomic; a crash before this checkpoint safely requeues the same identity.
                temporary = checkpoint.with_suffix(".tmp")
                temporary.write_text(json.dumps({"last_queued": key}))
                os.replace(temporary, checkpoint)
                total += 1
        return total
    finally:
        queue.close()
        artifacts.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    add_data_dir_argument(parser)
    args = parser.parse_args()
    try:
        root = resolve_data_dir(args.data_dir)
        configure_data_dir(root)
        db = qdrant_location(root)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(f"Queued {backfill(db)} stored representations; unavailable original fields remain unknown.")


if __name__ == "__main__":
    main()
