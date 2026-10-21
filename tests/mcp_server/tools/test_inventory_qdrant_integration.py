"""Inventory contract checks against an explicitly isolated, empty Qdrant server."""

import os
from inspect import unwrap
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from qdrant_client import AsyncQdrantClient
from qdrant_client.http import models as qm

from shyhurricane.db import facet_qdrant_values
from shyhurricane.index.web_resources_pipeline import WEB_RESOURCE_VERSION
from shyhurricane.mcp_server.tools import find_indexed_metadata as metadata


@pytest.mark.asyncio
async def test_indexed_inventories_match_capture_scan(monkeypatch):
    url = os.environ.get("QDRANT_TEST_URL")
    if not url:
        pytest.skip("Set QDRANT_TEST_URL to an isolated empty Qdrant server")
    client = AsyncQdrantClient(url=url, timeout=10)
    try:
        assert not (await client.get_collections()).collections, "Integration server must be empty"
        await client.create_collection("network", vectors_config=qm.VectorParams(size=1, distance=qm.Distance.COSINE))
        for field, schema in [("version", "integer"), ("domain", "keyword"), ("host", "keyword"),
                              ("port", "integer"), ("netloc", "keyword"), ("url", "keyword")]:
            await client.create_payload_index("network", f"meta.{field}", field_schema=schema, wait=True)
        records = [
            {"version": WEB_RESOURCE_VERSION, "domain": "Example.COM", "host": f"Host-{i % 600}.example.com",
             "port": 443 if i % 2 else 8443, "netloc": f"Host-{i % 600}.example.com:{443 if i % 2 else 8443}",
             "url": f"https://Host-{i % 600}.example.com/path/{i % 1200}"}
            for i in range(1500)
        ]
        records.extend([
            {"version": WEB_RESOURCE_VERSION, "domain": "other.test", "host": "other.test",
             "port": 443, "url": "https://other.test/Admin"},
            {"version": WEB_RESOURCE_VERSION, "domain": "example.com", "host": "legacy.example.com",
             "port": 443, "url": "https://legacy.example.com/Admin"},
            {"version": WEB_RESOURCE_VERSION, "domain": "example.com", "host": "null.example.com",
             "port": 443, "netloc": None},
            {"version": -1, "domain": "stale.test", "host": "stale.example.com", "url": "https://stale.test/"},
        ])
        for offset in range(0, len(records), 500):
            await client.upsert("network", points=[
                qm.PointStruct(id=i, vector=[1.0], payload={"meta": record})
                for i, record in enumerate(records[offset:offset + 500], start=offset)
            ], wait=True)
        monkeypatch.setattr(metadata, "get_server_context", AsyncMock(return_value=SimpleNamespace(qdrant_client=client)))
        monkeypatch.setattr(metadata, "log_tool_history", AsyncMock())
        current = [record for record in records if record["version"] == WEB_RESOURCE_VERSION]
        result = await unwrap(metadata.find_domains)(None, "EXAMPLE")
        assert result.domains == ["example.com"]
        for query, port in [("example.com", None), ("example.com:443", 443), ("absent.test", None), ("", None)]:
            host_query = query.split(":")[0]
            selected = [record for record in current if record["host"].lower().endswith(host_query)
                        and (port is None or record.get("port") == port)]
            result = await unwrap(metadata.find_hosts)(None, query)
            assert result.hosts == sorted({record["host"].lower() for record in selected})
            result = await unwrap(metadata.find_netloc)(None, query)
            assert result.network_locations == sorted({
                record.get("netloc", record["host"]).lower() for record in selected
                if record.get("netloc", record["host"]) is not None
            })
            for path in [None, "Admin", "admin"]:
                result = await unwrap(metadata.find_urls)(None, query, path_query=path)
                assert result.urls == sorted({record["url"] for record in selected if "url" in record
                                              and (not path or path in record["url"])})
        hits = await facet_qdrant_values(client, "meta.url", metadata._inventory_filter())
        assert len(hits) == 1202
    finally:
        await client.close()
