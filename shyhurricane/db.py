import asyncio
import hashlib
import json
import logging
import os
import re
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncGenerator, List, Optional, Sequence, Tuple

from haystack_integrations.document_stores.qdrant import QdrantDocumentStore
from qdrant_client import AsyncQdrantClient
from qdrant_client.conversions import common_types as types
from qdrant_client.http import models as qm
from qdrant_client.http.exceptions import UnexpectedResponse

from shyhurricane.haystack_lifecycle import managed_resource
from shyhurricane.qdrant_indexes import IndexedQdrantDocumentStore
from shyhurricane.search_metadata import SEARCH_FIELDS
from shyhurricane.search_predicates import HTTP_TYPES

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class QdrantDockerInfo:
    name: str
    container_id: str
    http_host: str
    http_port: int
    grpc_host: str
    grpc_port: int

    @property
    def http_url(self) -> str:
        return f"http://{self.http_host}:{self.http_port}"


def _run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def _inspect_container(name: str) -> Optional[dict]:
    p = _run(["docker", "inspect", name], check=False)
    if p.returncode != 0:
        return None
    data = json.loads(p.stdout)
    return data[0] if data else None


def _is_running(inspect: dict) -> bool:
    return bool(inspect.get("State", {}).get("Running", False))


def _get_published_port(inspect: dict, container_port: str) -> Tuple[str, int]:
    """
    container_port like "6333/tcp"
    Returns (HostIp, HostPort_int)
    """
    ports = inspect.get("NetworkSettings", {}).get("Ports", {})
    bindings = ports.get(container_port)
    if not bindings:
        raise RuntimeError(f"Container has no published binding for {container_port}")

    # Prefer 127.0.0.1 binding if present; otherwise take the first.
    chosen = None
    for b in bindings:
        if b.get("HostIp") == "127.0.0.1":
            chosen = b
            break
    if chosen is None:
        chosen = bindings[0]

    host_ip = chosen.get("HostIp") or "127.0.0.1"
    host_port = chosen.get("HostPort")
    if not host_port:
        raise RuntimeError(f"Container binding for {container_port} missing HostPort")
    return host_ip, int(host_port)


def _find_available_port(host: str) -> int:
    listener = socket.create_server((host, 0))
    try:
        return listener.getsockname()[1]
    finally:
        listener.close()


def _start_qdrant_docker(
        *,
        name: str = "qdrant-shyhurricane-db",
        storage_dir: str = "./shyhurricane.db",
        image: str = "qdrant/qdrant:latest",
        host_bind: str = "127.0.0.1",
        http_container_port: int = 6333,
        grpc_container_port: int = 6334,
        pull: bool = False,
) -> QdrantDockerInfo:
    """
    - If a container with `name` already exists:
        - If running: reuse it.
        - If stopped: start it.
      (No recreation, no port changes.)
    - If it doesn't exist: create it with available host ports, bound to `host_bind`.
    - Returns the bound host ports discovered via docker inspect.
    """
    storage = Path(storage_dir).resolve()
    storage.mkdir(parents=True, exist_ok=True)

    if pull:
        _run(["docker", "pull", image], check=True)

    inspect = _inspect_container(name)
    if inspect is None:
        http_host_port = _find_available_port(host_bind)
        grpc_host_port = _find_available_port(host_bind)
        while grpc_host_port == http_host_port:
            grpc_host_port = _find_available_port(host_bind)
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                name,
                "-p",
                f"{host_bind}:{http_host_port}:{http_container_port}",
                "-p",
                f"{host_bind}:{grpc_host_port}:{grpc_container_port}",
                "-v",
                f"{str(storage)}:/qdrant/storage:rw",
                image,
            ],
            check=True,
        )
        inspect = _inspect_container(name)
        if inspect is None:
            raise RuntimeError("Failed to inspect container after creation")
    else:
        if not _is_running(inspect):
            _run(["docker", "start", name], check=True)
            inspect = _inspect_container(name)
            if inspect is None:
                raise RuntimeError("Failed to inspect container after start")

    container_id = inspect.get("Id")
    if not container_id:
        raise RuntimeError("docker inspect did not return container Id")

    if not any(mount.get("Destination") == "/qdrant/storage" and mount.get("Source") == str(storage)
               for mount in inspect.get("Mounts", [])):
        raise RuntimeError("Managed Qdrant storage mount does not match configured directory")

    http_ip, http_port = _get_published_port(inspect, f"{http_container_port}/tcp")
    grpc_ip, grpc_port = _get_published_port(inspect, f"{grpc_container_port}/tcp")

    return QdrantDockerInfo(
        name=name,
        container_id=container_id,
        http_host=http_ip,
        http_port=http_port,
        grpc_host=grpc_ip,
        grpc_port=grpc_port,
    )


_QDRANT_ENDPOINTS: dict[str, Tuple[str, int]] = {}


def qdrant_host_port(db: str) -> Tuple[str, int]:
    remote = re.fullmatch(r"([^/\\\s]+):(\d+)", db)
    location = db if remote else str(Path(db).expanduser().resolve())
    if location in _QDRANT_ENDPOINTS:
        return _QDRANT_ENDPOINTS[location]
    if remote:
        host, port = remote.groups()
        endpoint = (host, int(port))
    else:
        container_name = "qdrant-shyhurricane-" + hashlib.sha256(location.encode()).hexdigest()[:12]
        container_info = _start_qdrant_docker(name=container_name, storage_dir=location)
        logger.info("Qdrant database at %s", container_info.http_url)
        endpoint = (container_info.http_host, container_info.http_port)
    _QDRANT_ENDPOINTS[location] = endpoint
    return endpoint


async def create_qdrant_client(db: str) -> AsyncQdrantClient:
    timeout = int(os.environ.get("QDRANT_ASYNC_TIMEOUT_SECONDS", "30"))
    if timeout <= 0:
        raise ValueError("QDRANT_ASYNC_TIMEOUT_SECONDS must be a positive integer")
    host, port = qdrant_host_port(db)
    return AsyncQdrantClient(
        host=host,
        port=port,
        timeout=timeout,
    )


async def scroll_qdrant_collection(
        qdrant_client: AsyncQdrantClient,
        index: str,
        fields: Sequence[str] = None,
        scroll_filter: types.Filter | None = None,
        newest_limit: int | None = None,
        page_size: int = 1000,
) -> AsyncGenerator[types.Record, None]:
    """Read all matching points by ID, or one explicitly bounded newest-first sample."""
    next_offset = None
    stop_scrolling = False
    page = 0
    while not stop_scrolling:
        started = asyncio.get_running_loop().time()
        page += 1
        records, next_offset = await qdrant_client.scroll(
            collection_name=index,
            scroll_filter=scroll_filter,
            limit=newest_limit if newest_limit is not None else page_size,
            offset=next_offset,
            with_payload=fields or False,
            with_vectors=False,
            order_by=(qm.OrderBy(key="meta.timestamp_float", direction=qm.Direction.DESC)
                      if newest_limit is not None else None),
        )
        stop_scrolling = newest_limit is not None or next_offset is None or (
                hasattr(next_offset, "num")
                and hasattr(next_offset, "uuid")
                and next_offset.num == 0
                and next_offset.uuid == ""
        )  # PointId always has num and uuid
        logger.debug(
            "Qdrant scroll collection=%s page=%d records=%d has_more=%s seconds=%.3f",
            index, page, len(records), not stop_scrolling, asyncio.get_running_loop().time() - started,
        )

        for record in records:
            yield record


async def facet_qdrant_values(
        qdrant_client, key: str, filters: qm.Filter, *, timeout: int = 10, repair_index: bool = False,
):
    """Enumerate complete exact facets, preserving raw values for subsequent indexed filters."""
    started = asyncio.get_running_loop().time()
    requests = 0
    limit = 256
    repaired = False
    while True:
        try:
            async with asyncio.timeout(timeout):
                requests += 1
                response = await qdrant_client.facet(
                    collection_name="network", key=key, facet_filter=filters,
                    limit=limit, exact=True, timeout=timeout,
                )
        except UnexpectedResponse as error:
            missing_index = f"No appropriate index for faceting: `{key}`".encode()
            if not repair_index or repaired or error.status_code != 400 or missing_index not in error.content:
                raise
            # Haystack only creates configured payload indexes for new collections.
            # Upgrade an existing collection without recreating it or scanning its points.
            logger.info("Creating missing Qdrant facet index network.%s", key)
            async with asyncio.timeout(timeout):
                await qdrant_client.create_payload_index(
                    collection_name="network", field_name=key,
                    field_schema=qm.PayloadSchemaType.KEYWORD, wait=True, timeout=timeout,
                )
            repaired = True
            continue
        if len(response.hits) < limit:
            logger.debug(
                "Qdrant facet key=%s requests=%d values=%d elapsed=%.3fs",
                key, requests, len(response.hits), asyncio.get_running_loop().time() - started,
            )
            return response.hits
        limit *= 2


async def get_domain_and_host_counts(
        qdrant_client: AsyncQdrantClient, version: int
) -> tuple[dict[str, int], dict[str, int]]:
    filters = qm.Filter(
        must=[qm.FieldCondition(key="meta.version", match=qm.MatchValue(value=version))]
    )
    async def counts(key: str) -> dict[str, int]:
        hits = await facet_qdrant_values(qdrant_client, key, filters, timeout=5, repair_index=True)
        result: dict[str, int] = {}
        for hit in hits:
            if isinstance(hit.value, str) and hit.value:
                value = hit.value.lower()
                result[value] = result.get(value, 0) + hit.count
        return result

    # A deadline also bounds expansion for high-cardinality fields and callers outside the UI.
    tasks = [asyncio.create_task(counts(key)) for key in ("meta.domain", "meta.host")]
    try:
        async with asyncio.timeout(10):
            domains, hosts = await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    return domains, hosts


@managed_resource
def create_qdrant_document_store(db: str, **kwargs) -> QdrantDocumentStore:
    if "timeout" not in kwargs:
        timeout = int(os.environ.get("QDRANT_DOCUMENT_STORE_TIMEOUT_SECONDS", "120"))
        if timeout <= 0:
            raise ValueError("QDRANT_DOCUMENT_STORE_TIMEOUT_SECONDS must be a positive integer")
        kwargs["timeout"] = timeout
    payload_fields_to_index = [
        {"field_name": "meta.version", "field_schema": "integer"},
        {"field_name": "meta.timestamp", "field_schema": "datetime"},
        {"field_name": "meta.timestamp_float", "field_schema": "float"},
        {"field_name": "meta.url", "field_schema": "keyword"},
        {"field_name": "meta.netloc", "field_schema": "keyword"},
        {"field_name": "meta.host", "field_schema": "keyword"},
        {"field_name": "meta.port", "field_schema": "integer"},
        {"field_name": "meta.domain", "field_schema": "keyword"},
        {"field_name": "meta.content_type", "field_schema": "keyword"},
        {"field_name": "meta.status_code", "field_schema": "integer"},
        {"field_name": "meta.http_method", "field_schema": "keyword"},
        {"field_name": "meta.title", "field_schema": "text"},
        {"field_name": "meta.description", "field_schema": "text"},
        {"field_name": "meta.content_sha256", "field_schema": "keyword"},
        {"field_name": "meta.normalized", "field_schema": "bool"},
        {"field_name": "meta.targets", "field_schema": "keyword"},
        {"field_name": "meta.runtime_ts", "field_schema": "float"},
    ]
    if kwargs.get("index", "").split("_", 1)[0] in HTTP_TYPES:
        payload_fields_to_index.extend(
            {"field_name": f"meta.{field}", "field_schema": "keyword"} for field in (*SEARCH_FIELDS, "type")
        )
    host, port = qdrant_host_port(db)
    return IndexedQdrantDocumentStore(
        host=host,
        port=int(port),
        use_sparse_embeddings=True,
        payload_fields_to_index=payload_fields_to_index,
        **kwargs
    )


async def list_collections(db: str) -> List[str]:
    """Return collection names using a raw Chroma client."""
    client = await create_qdrant_client(db)
    return [c.name for c in (await client.get_collections()).collections]
