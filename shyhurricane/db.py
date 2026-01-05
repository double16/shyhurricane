import os
import re
import json
import subprocess
import time
import requests
from pathlib import Path
from typing import Sequence, AsyncGenerator, List, Optional, Tuple
from dataclasses import dataclass

from haystack_integrations.document_stores.qdrant import QdrantDocumentStore
from qdrant_client import AsyncQdrantClient
from qdrant_client.conversions import common_types as types
from qdrant_client.http import models as qm


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
    - If it doesn't exist: create it with auto-assigned host ports, bound to `host_bind`.
    - Returns the bound host ports discovered via docker inspect.
    """
    storage = Path(storage_dir).resolve()
    storage.mkdir(parents=True, exist_ok=True)

    if pull:
        _run(["docker", "pull", image], check=True)

    inspect = _inspect_container(name)
    if inspect is None:
        # Auto-assign host ports by leaving host port empty, but still bind to localhost
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                name,
                "-p",
                f"{host_bind}::{http_container_port}",
                "-p",
                f"{host_bind}::{grpc_container_port}",
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


def _wait_ready(url: str = "http://127.0.0.1:6333", timeout_s: int = 30) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            r = requests.get(f"{url}/readyz", timeout=1)
            if r.status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(0.2)
    raise TimeoutError(f"Qdrant not ready after {timeout_s}s")


_QDRANT_HOST: Optional[str] = None
_QDRANT_HOST_PORT: Optional[int] = None
_QDRANT_GRPC_PORT: Optional[int] = None


def qdrant_host_port(db: str) -> Tuple[str, int]:
    global _QDRANT_HOST, _QDRANT_HOST_PORT, _QDRANT_GRPC_PORT

    if _QDRANT_HOST and _QDRANT_HOST_PORT:
        return _QDRANT_HOST, _QDRANT_HOST_PORT

    if re.match(r'\S+:\d+$', db):
        host, _, port = db.rpartition(':')
        _QDRANT_HOST = host
        _QDRANT_HOST_PORT = int(port)
        return _QDRANT_HOST, _QDRANT_HOST_PORT

    container_name = "qdrant-" + re.sub(r'[^A-Za-z0-9]+', '-', os.path.basename(db)).lower()
    container_info = _start_qdrant_docker(name=container_name, storage_dir=os.path.abspath(db))
    _wait_ready(container_info.http_url)
    _QDRANT_HOST = container_info.http_host
    _QDRANT_HOST_PORT = container_info.http_port
    return _QDRANT_HOST, _QDRANT_HOST_PORT


async def create_qdrant_client(db: str) -> AsyncQdrantClient:
    host, port = qdrant_host_port(db)
    return AsyncQdrantClient(
        host=host,
        port=port,
    )


async def scroll_qdrant_collection(
        qdrant_client: AsyncQdrantClient,
        index: str,
        fields: Sequence[str] = None,
        scroll_filter: types.Filter | None = None,
) -> AsyncGenerator[types.Record, None]:
    next_offset = None
    stop_scrolling = False
    while not stop_scrolling:
        records, next_offset = await qdrant_client.scroll(
            collection_name=index,
            scroll_filter=scroll_filter,
            limit=1000,
            offset=next_offset,
            with_payload=fields or False,
            with_vectors=False,
            order_by=qm.OrderBy(key="meta.timestamp_float", direction=qm.Direction.DESC),
        )
        stop_scrolling = next_offset is None or (
                hasattr(next_offset, "num")
                and hasattr(next_offset, "uuid")
                and next_offset.num == 0
                and next_offset.uuid == ""
        )  # PointId always has num and uuid

        for record in records:
            yield record


def create_qdrant_document_store(db: str, **kwargs) -> QdrantDocumentStore:
    payload_fields_to_index = [
        {"field_name": "meta.version", "field_schema": "integer"},
        {"field_name": "meta.timestamp", "field_schema": "datetime"},
        {"field_name": "meta.timestamp_float", "field_schema": "float"},
        {"field_name": "meta.url", "field_schema": "keyword"},
        {"field_name": "meta.netloc", "field_schema": "keyword"},
        {"field_name": "meta.host", "field_schema": "keyword"},
        {"field_name": "meta.domain", "field_schema": "keyword"},
        {"field_name": "meta.content_type", "field_schema": "keyword"},
        {"field_name": "meta.status_code", "field_schema": "integer"},
        {"field_name": "meta.http_method", "field_schema": "keyword"},
        {"field_name": "meta.title", "field_schema": "text"},
        {"field_name": "meta.description", "field_schema": "text"},
        {"field_name": "meta.content_sha256", "field_schema": "keyword"},
    ]
    host, port = qdrant_host_port(db)
    return QdrantDocumentStore(
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
