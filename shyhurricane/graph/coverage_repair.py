"""Conservative, bounded reconciliation of legacy root analysis-unit aliases."""

import logging
import sqlite3
import time
from contextlib import closing

from shyhurricane.data_paths import persistent_queue_path
from shyhurricane.graph.blob_store import BlobStore
from shyhurricane.graph.model import identity, web_url
from shyhurricane.graph.policy import ANALYZER_VERSION

logger = logging.getLogger(__name__)


class CoverageRepair:
    """Resume finite pending-unit scans without opening or migrating an artifact service."""

    def __init__(self, db):
        self.root = persistent_queue_path(db, "graph_state")
        self.after = ""

    def archive_exists(self, reference):
        """A corrupt or inaccessible reference must not starve later candidates."""
        try:
            with closing(sqlite3.connect((self.root / "artifacts.sqlite").as_uri() + "?mode=ro",
                                        uri=True, timeout=0.05)) as connection:
                return BlobStore(connection).exists(reference)
        except (OSError, ValueError, sqlite3.Error):
            return False

    def tick(self, stop_event):
        started = time.monotonic()
        deadline = started + 1
        database = self.root / "artifacts.sqlite"
        if not database.exists():
            return
        repaired = 0
        with closing(sqlite3.connect(database.as_uri() + "?mode=rw", uri=True, timeout=0.05)) as connection:
            connection.set_progress_handler(lambda: int(stop_event.is_set() or time.monotonic() >= deadline), 1000)
            rows = connection.execute(
                "SELECT id,capture_id,source_path,discovery,flow FROM graph_manifest_units "
                "WHERE (discovery='pending' OR flow='pending') AND id>? ORDER BY id LIMIT 100",
                (self.after,),
            ).fetchall()
            for key, capture, source, discovery, flow in rows:
                if stop_event.is_set() or time.monotonic() >= deadline:
                    break
                if source.startswith("capture:") and discovery == flow == "pending":
                    normalized = web_url(source[len("capture:"):])
                    expected = identity("analysis-unit-v2", ANALYZER_VERSION, capture, source)
                    if normalized and expected == key:
                        successor = identity("analysis-unit-v2", ANALYZER_VERSION, capture, "capture:" + normalized)
                        with connection:
                            row = connection.execute(
                                "SELECT discovery,flow,artifact,error FROM graph_manifest_units "
                                "WHERE id=? AND capture_id=? AND discovery='complete' "
                                "AND flow IN ('complete','partial') AND artifact IS NOT NULL",
                                (successor, capture),
                            ).fetchone()
                            if row and self.archive_exists(row[2]):
                                if stop_event.is_set() or time.monotonic() >= deadline:
                                    break
                                repaired += connection.execute(
                                    "UPDATE graph_manifest_units SET discovery=?,flow=?,artifact=?,error=?,updated_at=? "
                                    "WHERE id=? AND discovery=? AND flow=?",
                                    (*row, time.time(), key, discovery, flow),
                                ).rowcount
                self.after = key
            if len(rows) < 100 and (not rows or self.after == rows[-1][0]):
                self.after = ""
        logger.info("Graph coverage reconciliation selected=%s repaired=%s seconds=%.3f",
                    len(rows), repaired, time.monotonic() - started)
