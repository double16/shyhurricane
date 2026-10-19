"""Managed Neo4j lifecycle and graph publication."""

import hashlib
import logging
import math
import os
import re
import threading
from pathlib import Path
from urllib.parse import urlsplit

from neo4j import GraphDatabase, Query, unit_of_work

from shyhurricane.db import _find_available_port, _get_published_port, _inspect_container, _is_running, _run
from shyhurricane.graph.config import graph_timeouts
from shyhurricane.graph.statistics import summarize_captures

logger = logging.getLogger(__name__)
IMAGE = "neo4j:2026.09.0-community"


def memory_environment() -> list[str]:
    """Validate deployment memory sizes before launching a managed container."""
    heap = os.environ.get("NEO4J_HEAP_SIZE", "1g")
    pagecache = os.environ.get("NEO4J_PAGECACHE_SIZE", "1g")
    transaction = os.environ.get("NEO4J_TRANSACTION_MEMORY_LIMIT", "")

    def size(value):
        match = re.fullmatch(r"([1-9][0-9]*)([kmg])", value, re.IGNORECASE)
        if match is None:
            raise ValueError("Neo4j memory settings require a positive size with k, m, or g suffix")
        return int(match[1]) * {"k": 1024, "m": 1024**2, "g": 1024**3}[match[2].lower()]

    heap_bytes = size(heap)
    size(pagecache)
    if transaction and size(transaction) > heap_bytes:
        raise ValueError("NEO4J_TRANSACTION_MEMORY_LIMIT must not exceed NEO4J_HEAP_SIZE")
    environment = [
        f"NEO4J_server_memory_heap_initial__size={heap}",
        f"NEO4J_server_memory_heap_max__size={heap}",
        f"NEO4J_server_memory_pagecache_size={pagecache}",
    ]
    if transaction:
        environment.append(f"NEO4J_dbms_memory_transaction_total_max={transaction}")
    return environment


def graph_location() -> str:
    from shyhurricane.server_config import get_server_config

    return get_server_config().graph_database


def resolve_uri(location: str) -> str:
    if "://" in location:
        parsed = urlsplit(location)
        if parsed.scheme not in {"bolt", "bolt+s", "bolt+ssc", "neo4j", "neo4j+s", "neo4j+ssc"}:
            raise ValueError("NEO4J must be a storage directory or a Bolt/Neo4j URI")
        if not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("NEO4J requires a hostname; supply credentials separately")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("NEO4J URI must identify the server, without a database path or query")
        parsed.port
        return location
    storage = Path(location).expanduser().resolve()
    storage.mkdir(parents=True, exist_ok=True)
    name = "neo4j-shyhurricane-" + hashlib.sha256(str(storage).encode()).hexdigest()[:12]
    info = _inspect_container(name)
    environment = memory_environment()
    if info is None:
        port = _find_available_port("127.0.0.1")
        password = os.environ.get("NEO4J_PASSWORD")
        auth = f"neo4j/{password}" if password else "none"
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                name,
                "-p",
                f"127.0.0.1:{port}:7687",
                "-v",
                f"{storage}:/data:rw",
                "-v",
                f"{storage}/logs:/logs:rw",
                "-e",
                f"NEO4J_AUTH={auth}",
                *[part for value in environment for part in ("-e", value)],
                IMAGE,
            ]
        )
        info = _inspect_container(name)
    elif not _is_running(info):
        _run(["docker", "start", name])
        info = _inspect_container(name)
    if not info:
        raise RuntimeError("Cannot inspect managed Neo4j container")
    mounts = info.get("Mounts", [])
    if not any(item.get("Destination") == "/data" and item.get("Source") == str(storage) for item in mounts):
        raise RuntimeError("Managed Neo4j storage mount does not match configured directory")
    current_environment = info.get("Config", {}).get("Env", [])
    current_memory = dict(value.split("=", 1) for value in current_environment if "=" in value)
    desired_memory = dict(value.split("=", 1) for value in environment)
    desired_memory.setdefault("NEO4J_dbms_memory_transaction_total_max", "")
    if any(current_memory.get(key, "").lower() != value.lower() for key, value in desired_memory.items()):
        logger.warning(
            "Managed Neo4j container %s has different memory settings; stop the server and recreate "
            "that container with the existing storage mounts to apply NEO4J memory overrides",
            name,
        )
    host, port = _get_published_port(info, "7687/tcp")
    return f"bolt://{host}:{port}"


class GraphStore:
    """One driver per process; never share driver objects across fork boundaries."""

    def __init__(self, location: str | None = None):
        self.timeouts = graph_timeouts()
        self.location = location or graph_location()
        if "://" in self.location:
            resolve_uri(self.location)
        self.driver = None
        self.uri = None
        self.lock = threading.Lock()
        self.schema_ready = False

    def connect(self):
        with self.lock:
            if self.driver is None:
                self.uri = resolve_uri(self.location)
                password = os.environ.get("NEO4J_PASSWORD")
                auth = (os.environ.get("NEO4J_USERNAME", "neo4j"), password) if password else None
                self.driver = GraphDatabase.driver(
                    self.uri, auth=auth, connection_timeout=3, max_transaction_retry_time=5
                )
        return self.driver

    def close(self):
        with self.lock:
            if self.driver is not None:
                self.driver.close()
                self.driver = None
                self.schema_ready = False

    def read(self, statement: str, *, timeout: float | None = None, **parameters) -> list[dict]:
        """Read with managed retries normally, or one deadline-bounded transaction."""
        if timeout is not None and (not math.isfinite(timeout) or timeout <= 0):
            raise ValueError("Graph read timeout must be finite and positive")
        with self.connect().session(database="neo4j", default_access_mode="READ") as session:
            if timeout is not None:
                # Explicit transactions do not perform driver-managed retries, which could
                # otherwise outlive the caller's remaining hydration budget.
                with session.begin_transaction(timeout=min(self.timeouts.read, timeout)) as transaction:
                    return [dict(row) for row in transaction.run(statement, **parameters)]

            @unit_of_work(timeout=self.timeouts.read)
            def read(tx):
                return [dict(row) for row in tx.run(statement, **parameters)]

            return session.execute_read(read)

    def ready(self) -> bool:
        self.connect().verify_connectivity()
        if not self.schema_ready:
            with self.driver.session(database="neo4j") as session:
                self.initialize_schema(session)
        with self.driver.session(database="neo4j", default_access_mode="READ") as session:
            session.run(Query("RETURN 1", timeout=self.timeouts.health)).consume()
            self.schema_ready = True
        return True

    def initialize_schema(self, session):
        def run(statement):
            return session.run(Query(statement, timeout=self.timeouts.schema))

        for label in (
            "GraphEntity",
            "GraphEvidence",
            "GraphCapture",
            "GraphArtifact",
            "GraphState",
            "GraphPublication",
        ):
            run(
                f"CREATE CONSTRAINT {label.lower()}_id IF NOT EXISTS FOR (n:{label}) REQUIRE n.id IS UNIQUE"
            ).consume()
        run("CREATE INDEX graph_entity_url IF NOT EXISTS FOR (n:GraphEntity) ON (n.url)").consume()
        for field in (
            "module_key",
            "import_key",
            "capture_id",
            "selector",
            "_publication_id",
            "context_owner_id",
            "_logical_id",
        ):
            run(f"CREATE INDEX graph_entity_{field} IF NOT EXISTS FOR (n:GraphEntity) ON (n.{field})").consume()
        run("CREATE INDEX graph_capture_host IF NOT EXISTS FOR (n:GraphCapture) ON (n.host)").consume()
        run(
            "CREATE INDEX graph_evidence_capture IF NOT EXISTS FOR (n:GraphEvidence) ON (n.capture_id)"
        ).consume()
        run(
            "CREATE INDEX graph_evidence_publication IF NOT EXISTS FOR (n:GraphEvidence) ON (n._publication_id)"
        ).consume()
        run(
            "CREATE INDEX graph_rel_publication IF NOT EXISTS FOR ()-[r:RELATES]-() ON (r._publication_id)"
        ).consume()
        run("CREATE INDEX graph_rel_id IF NOT EXISTS FOR ()-[r:RELATES]-() ON (r.id)").consume()
        run("CREATE INDEX graph_rel_capture IF NOT EXISTS FOR ()-[r:RELATES]-() ON (r.capture_id)").consume()
        run(
            "CREATE INDEX graph_publication_capture IF NOT EXISTS FOR (n:GraphPublication) ON (n.capture_id)"
        ).consume()
        run(
            "CREATE INDEX graph_publication_retired IF NOT EXISTS FOR (n:GraphPublication) ON (n.state,n.retired_at)"
        ).consume()
        run(
            "CREATE INDEX graph_cleanup_pending IF NOT EXISTS "
            "FOR (n:GraphCleanupPending) ON (n.retired_at,n.id)"
        ).consume()
        run(
            "CREATE INDEX graph_capture_resource IF NOT EXISTS FOR (n:GraphCapture) ON (n.resource_key, n.observed_at)"
        ).consume()

        run("MERGE (n:GraphState {id:'publication_revision'}) ON CREATE SET n.value=0").consume()
        # Hydration uses explicit seek hints, so newly created indexes must be online.
        run(f"CALL db.awaitIndexes({math.ceil(self.timeouts.schema)})").consume()

    def publish(self, projection):
        from shyhurricane.graph.publication import GraphPublisher

        GraphPublisher(self).publish(projection)

    def cleanup(self, **kwargs):
        from shyhurricane.graph.publication import GraphPublisher

        return GraphPublisher(self).cleanup(**kwargs)

    def activity(self) -> dict:
        """Read the indexed counter advanced atomically by publication activation."""
        rows = self.read(
            "MATCH (s:GraphState {id:'publication_revision'}) RETURN s.value AS revision",
            timeout=2,
        )
        return {"publication_revision": rows[0]["revision"] if rows else None}

    def statistics(self) -> dict:
        rows = self.read(
            "MATCH (c:GraphCapture) WHERE c.complete=true "
            "RETURN coalesce(c.resource_key,c.id) AS resource_key,coalesce(c.observed_at,0) AS observed_at, "
            "c.entity_estimate AS entity_estimate,c.relationship_estimate AS relationship_estimate, "
            "c.summarized AS summarized,c.budget_limited AS budget_limited, "
            "size(coalesce(c.gaps,[])) > 0 AS gaps, "
            "c.published_at AS published_at",
            timeout=5,
        )
        return {**summarize_captures(rows), "uri": self.uri}
