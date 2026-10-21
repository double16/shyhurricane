from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import shyhurricane.mcp_server.tools.find_indexed_metadata as metadata


class Record:
    def __init__(self, meta):
        self.payload = {"meta": meta}


class ServerContext:
    qdrant_client = object()


async def noop(*args, **kwargs):
    return None


async def get_fake_server_context():
    return ServerContext()


async def fake_scroll(records):
    for record in records:
        yield record


@pytest.fixture
def indexed_metadata(monkeypatch):
    records = [
        Record({"domain": "Example.COM", "host": "www.example.com", "netloc": "www.example.com:443", "port": 443,
                "url": "https://www.example.com/login"}),
        Record({"domain": "example.com", "host": "api.example.com", "netloc": "api.example.com:8443", "port": 8443,
                "url": "https://api.example.com/admin"}),
        Record({"domain": "Other.test", "host": "other.test", "netloc": "other.test:80", "port": 80,
                "url": "http://other.test/"}),
        Record({"domain": "", "host": "", "url": "missing-host"}),
    ]

    monkeypatch.setattr(metadata, "get_server_context", get_fake_server_context)
    monkeypatch.setattr(metadata, "log_tool_history", noop)
    def matches(record, filters):
        for condition in filters.must:
            if isinstance(condition, metadata.qm.FieldCondition):
                name = condition.key.removeprefix("meta.")
                value = record.payload["meta"].get(name)
                if name == "version":
                    value = record.payload["meta"].get(name, metadata.WEB_RESOURCE_VERSION)
                match = condition.match
                if isinstance(match, metadata.qm.MatchAny):
                    if value not in match.any:
                        return False
                elif value != match.value:
                    return False
            elif isinstance(condition, metadata.qm.IsEmptyCondition):
                if record.payload["meta"].get("netloc") is not None:
                    return False
        return True

    async def facet(**kwargs):
        values = {
            record.payload["meta"][kwargs["key"].removeprefix("meta.")]
            for record in records if matches(record, kwargs["facet_filter"])
            and kwargs["key"].removeprefix("meta.") in record.payload["meta"]
        }
        return SimpleNamespace(hits=[SimpleNamespace(value=value, count=1) for value in sorted(values)][
            :kwargs["limit"]
        ])

    async def scroll(**kwargs):
        assert kwargs["with_payload"] == ["meta.host", "meta.netloc"]
        return ([record for record in records if matches(record, kwargs["scroll_filter"])], None)

    monkeypatch.setattr(ServerContext, "qdrant_client", SimpleNamespace(
        facet=AsyncMock(side_effect=facet), scroll=AsyncMock(side_effect=scroll),
    ))
    return records


def test_finder_instructions_switches_on_results():
    found = metadata._finder_instructions("domains", {"example.com"})
    assert found.startswith("These are indexed domains")
    assert "get_result_page" in found
    missing = metadata._finder_instructions("domains", set())
    assert missing.startswith("No indexed domains")
    assert "Check or broaden the filter within the existing scope first" in missing


@pytest.mark.asyncio
async def test_find_domains_filters_contains_query(indexed_metadata):
    result = await metadata.find_domains(None, "example")

    assert result.query == "example"
    assert result.domains == ["example.com"]
    assert result.instructions.startswith("These are indexed domains")


@pytest.mark.asyncio
async def test_domain_inventory_includes_domain_after_first_thousand_records(indexed_metadata, monkeypatch):
    indexed_metadata.extend(Record({"domain": "first.test"}) for _ in range(1000))
    indexed_metadata.extend(Record({"domain": f"domain-{index}.test"}) for index in range(1100))
    result = await metadata.find_domains(None, limit=1000)
    assert result.pagination.total_items == 1103
    assert ServerContext.qdrant_client.facet.await_count == 4
    ServerContext.qdrant_client.scroll.assert_not_awaited()



@pytest.mark.asyncio
async def test_find_hosts_filters_domain_and_port(indexed_metadata):
    result = await metadata.find_hosts(None, "example.com:443")

    assert result.domain_query == "example.com:443"
    assert result.hosts == ["www.example.com"]


@pytest.mark.asyncio
async def test_find_netloc_filters_domain_without_port(indexed_metadata):
    result = await metadata.find_netloc(None, "example.com")

    assert result.network_locations == ["api.example.com:8443", "www.example.com:443"]


@pytest.mark.asyncio
async def test_find_urls_filters_path_and_applies_limit(indexed_metadata):
    result = await metadata.find_urls(None, "example.com", path_query="admin", limit=1)

    assert result.host_query == "example.com"
    assert result.path_query == "admin"
    assert result.limit == 1
    assert result.urls == ["https://api.example.com/admin"]


@pytest.mark.asyncio
async def test_internal_network_inventory_is_not_paginated(indexed_metadata, result_store):
    result = await metadata.find_netloc_all(None, "example.com")
    assert result.network_locations == ["api.example.com:8443", "www.example.com:443"]
    assert result.pagination is None
    assert not list(result_store.snapshots.iterdir())


@pytest.mark.asyncio
async def test_inventory_waits_before_query_and_saves_indexing_status(indexed_metadata, monkeypatch, result_store):
    from shyhurricane import indexing_wait

    calls = []

    async def wait(ctx, server, matches, **kwargs):
        assert matches("https://api.example.com/admin")
        assert not matches("https://other.test/admin")
        calls.append("wait")
        indexed_metadata.append(Record({"host": "new.example.com", "url": "https://new.example.com/admin"}))
        return indexing_wait.IndexingStatus(status="timed_out", potentially_incomplete=True)

    monkeypatch.setattr(indexing_wait, "wait_for_indexing", wait)
    result = await metadata.find_urls(None, "example.com", path_query="admin", limit=1)
    assert calls == ["wait"]
    assert result.indexing.status == "timed_out"
    assert result.pagination.total_items == 2
    saved = result_store.read(result.pagination.next_page_token)["result"]
    assert saved["indexing"] == result.indexing.model_dump()
    assert saved["urls"] == ["https://new.example.com/admin"]


@pytest.mark.asyncio
async def test_inventory_filters_batches_and_missing_netloc(indexed_metadata):
    indexed_metadata.extend([
        Record({"host": "UPPER.EXAMPLE.COM", "url": "https://UPPER.EXAMPLE.COM/Admin", "port": 443}),
        Record({"host": "stale.example.com", "domain": "stale.test", "version": -1}),
    ])
    indexed_metadata.extend(
        Record({"host": f"host-{index}.example.com", "netloc": f"host-{index}.example.com:443",
                "url": f"https://host-{index}.example.com/", "port": 443})
        for index in range(260)
    )
    locations = await metadata.find_netloc_all(None, "example.com:443")
    assert len(locations.network_locations) == 262
    assert "upper.example.com" in locations.network_locations
    assert "stale.example.com" not in locations.network_locations
    result = await metadata.find_urls(None, "example.com:443", path_query="Admin")
    assert result.urls == ["https://UPPER.EXAMPLE.COM/Admin"]
    result = await metadata.find_urls(None, "example.com:443", path_query="admin")
    assert result.urls == []
    requests = ServerContext.qdrant_client.facet.call_args_list
    host_filters = [call.kwargs["facet_filter"] for call in requests if call.kwargs["key"] == "meta.url"]
    assert all(len(filters.must[-1].match.any) <= 256 for filters in host_filters)


@pytest.mark.asyncio
async def test_inventories_empty_and_failures(indexed_metadata):
    for function, field in [(metadata.find_hosts, "hosts"), (metadata.find_netloc, "network_locations"),
                            (metadata.find_urls, "urls")]:
        result = await function(None, "absent.test")
        assert getattr(result, field) == []
    result = await metadata.find_domains(None, "absent")
    assert result.domains == []
    ServerContext.qdrant_client.facet.side_effect = RuntimeError("database unavailable")
    for function, arguments in [(metadata.find_domains, ()), (metadata.find_hosts, ("example.com",)),
                                (metadata.find_netloc, ("example.com",)), (metadata.find_urls, ("example.com",))]:
        with pytest.raises(RuntimeError, match="database unavailable"):
            await function(None, *arguments)


@pytest.mark.asyncio
async def test_facet_strings_rejects_non_strings(indexed_metadata):
    client = SimpleNamespace(facet=AsyncMock(return_value=SimpleNamespace(hits=[
        SimpleNamespace(value=17), SimpleNamespace(value=""), SimpleNamespace(value="Example.COM"),
    ])))
    assert await metadata._facet_strings(client, "meta.host", metadata._inventory_filter()) == {"", "Example.COM"}


@pytest.mark.asyncio
async def test_inventory_facet_timeout_and_no_index_repair(indexed_metadata, monkeypatch):
    import asyncio

    from shyhurricane import db

    timeout = asyncio.timeout
    monkeypatch.setattr(db.asyncio, "timeout", lambda seconds: timeout(0.001))

    async def blocked(**kwargs):
        await asyncio.Event().wait()

    client = SimpleNamespace(facet=AsyncMock(side_effect=blocked))
    with pytest.raises(TimeoutError):
        await db.facet_qdrant_values(client, "meta.host", metadata._inventory_filter())
    from qdrant_client.http.exceptions import UnexpectedResponse

    def facet_error():
        return UnexpectedResponse(400, "Bad Request", b"No appropriate index for faceting: `meta.domain`", {})

    client.facet.side_effect = facet_error()
    with pytest.raises(type(facet_error())):
        await db.facet_qdrant_values(client, "meta.domain", metadata._inventory_filter())


@pytest.mark.asyncio
async def test_exact_facet_boundary_and_unfiltered_inventory(indexed_metadata):
    indexed_metadata.clear()
    indexed_metadata.extend(Record({"domain": f"domain-{index}.test", "host": f"host-{index}.test"})
                            for index in range(256))
    result = await metadata.find_domains(None, limit=1000)
    assert len(result.domains) == 256
    assert [call.kwargs["limit"] for call in ServerContext.qdrant_client.facet.call_args_list] == [256, 512]
    assert len((await metadata.find_hosts(None, "")).hosts) == 100
    result = await metadata.find_netloc_all(None, "")
    assert len(result.network_locations) == 256
    ServerContext.qdrant_client.scroll.assert_awaited_once()
