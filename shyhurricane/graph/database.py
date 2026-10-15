"""Managed Neo4j lifecycle and graph publication."""

import hashlib
import logging
import os
import re
import threading
from pathlib import Path
from urllib.parse import urlsplit

from neo4j import GraphDatabase, Query, unit_of_work

from shyhurricane.db import _find_available_port, _get_published_port, _inspect_container, _is_running, _run
from shyhurricane.graph.statistics import summarize_captures

logger = logging.getLogger(__name__)
IMAGE = "neo4j:2026.09.0-community"


def memory_environment() -> list[str]:
    """Validate deployment memory sizes before launching a managed container."""
    heap = os.environ.get("NEO4J_HEAP_SIZE", "1g")
    pagecache = os.environ.get("NEO4J_PAGECACHE_SIZE", "256m")
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

    return get_server_config().graph_database or os.environ.get("NEO4J", "shyhurricane.graph.db")


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

    def read(self, statement: str, **parameters) -> list[dict]:
        with self.connect().session(database="neo4j") as session:

            @unit_of_work(timeout=10)
            def read(tx):
                return [dict(row) for row in tx.run(statement, **parameters)]

            return session.execute_read(read)

    def ready(self) -> bool:
        self.connect().verify_connectivity()
        with self.driver.session(database="neo4j") as session:
            if not self.schema_ready:
                self.initialize_schema(session)
            session.run(
                Query("MERGE (n:GraphState {id:'health'}) SET n.checked_at=timestamp() RETURN n.id", timeout=5)
            ).consume()
            self.schema_ready = True
        self.cleanup()
        return True

    def initialize_schema(self, session):
        for label in (
            "GraphEntity",
            "GraphEvidence",
            "GraphCapture",
            "GraphArtifact",
            "GraphState",
            "GraphPublication",
        ):
            session.run(
                f"CREATE CONSTRAINT {label.lower()}_id IF NOT EXISTS " f"FOR (n:{label}) REQUIRE n.id IS UNIQUE"
            ).consume()
        session.run("CREATE INDEX graph_entity_url IF NOT EXISTS FOR (n:GraphEntity) ON (n.url)").consume()
        for field in ("module_key", "import_key", "capture_id", "selector", "_publication_id", "context_owner_id"):
            session.run(f"CREATE INDEX graph_entity_{field} IF NOT EXISTS FOR (n:GraphEntity) ON (n.{field})").consume()
        session.run("CREATE INDEX graph_capture_host IF NOT EXISTS FOR (n:GraphCapture) ON (n.host)").consume()
        session.run(
            "CREATE INDEX graph_evidence_capture IF NOT EXISTS FOR (n:GraphEvidence) ON (n.capture_id)"
        ).consume()
        session.run(
            "CREATE INDEX graph_evidence_publication IF NOT EXISTS FOR (n:GraphEvidence) ON (n._publication_id)"
        ).consume()
        session.run(
            "CREATE INDEX graph_rel_publication IF NOT EXISTS FOR ()-[r:RELATES]-() ON (r._publication_id)"
        ).consume()
        session.run("CREATE INDEX graph_rel_id IF NOT EXISTS FOR ()-[r:RELATES]-() ON (r.id)").consume()
        session.run("CREATE INDEX graph_rel_capture IF NOT EXISTS FOR ()-[r:RELATES]-() ON (r.capture_id)").consume()
        session.run(
            "CREATE INDEX graph_publication_retired IF NOT EXISTS FOR (n:GraphPublication) ON (n.state,n.retired_at)"
        ).consume()
        session.run(
            "CREATE INDEX graph_capture_resource IF NOT EXISTS "
            "FOR (n:GraphCapture) ON (n.resource_key, n.observed_at)"
        ).consume()

    def publish(self, projection):
        from shyhurricane.graph.publication import GraphPublisher

        GraphPublisher(self).publish(projection)

    def cleanup(self):
        from shyhurricane.graph.publication import GraphPublisher

        GraphPublisher(self).cleanup()

    def statistics(self) -> dict:
        rows = self.read(
            "MATCH (c:GraphCapture) WHERE c.complete=true "
            "RETURN coalesce(c.resource_key,c.id) AS resource_key,coalesce(c.observed_at,0) AS observed_at, "
            "c.entity_estimate AS entity_estimate,c.relationship_estimate AS relationship_estimate, "
            "c.summarized AS summarized,c.budget_limited AS budget_limited,c.gaps AS gaps, "
            "c.published_at AS published_at"
        )
        return {**summarize_captures(rows), "uri": self.uri}
