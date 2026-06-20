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
    monkeypatch.setattr(metadata, "scroll_qdrant_collection", lambda **kwargs: fake_scroll(records))
    return records


def test_finder_instructions_switches_on_results():
    assert metadata._finder_instructions("domains", {"example.com"}).startswith("These are the domains")
    assert metadata._finder_instructions("domains", set()).startswith("No domains")


@pytest.mark.asyncio
async def test_find_domains_filters_contains_query(indexed_metadata):
    result = await metadata.find_domains(None, "example")

    assert result.query == "example"
    assert result.domains == ["example.com"]
    assert result.instructions.startswith("These are the domains")


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
    assert result.limit == 10
    assert result.urls == ["https://api.example.com/admin"]
