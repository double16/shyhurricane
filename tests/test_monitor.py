import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from textual.widgets import Static

from shyhurricane.db import get_domain_and_host_counts
from shyhurricane.health import HealthMonitor
from shyhurricane.monitor import (
    MonitorApp,
    MonitorData,
    certificate_fingerprint,
    collect_monitor_data,
    format_configuration_panel,
    format_database_panel,
    format_domain_and_host_panel,
    format_graph_panel,
    format_monitor_database_panel,
    format_qdrant_freshness,
    format_tools_panel,
    get_recent_indexed_urls,
    queue_size,
    top_counts,
)
from shyhurricane.monitoring_qdrant import MonitorQdrantCache
from shyhurricane.server_config import ServerConfig


class Queue:
    def __init__(self, size):
        self.size = size

    def active_size(self):
        return self.size


class Store:
    def __init__(self, count):
        self.count = count

    async def count_documents_async(self):
        return self.count


class UnavailableStore:
    async def count_documents_async(self):
        raise ConnectionError("Qdrant is unavailable")


def test_certificate_fingerprint_handles_missing_and_invalid_files(tmp_path, monkeypatch):
    assert certificate_fingerprint(None) is None
    invalid_certificate = tmp_path / "invalid.pem"
    invalid_certificate.write_text("not a certificate")
    assert certificate_fingerprint(invalid_certificate) is None

    class Certificate:
        def fingerprint(self, algorithm):
            return bytes.fromhex("abcd")

    monkeypatch.setattr(
        "cryptography.x509.load_pem_x509_certificate",
        lambda contents: Certificate(),
    )
    assert certificate_fingerprint(invalid_certificate) == "ab:cd"


def test_monitor_app_stores_runtime_dependencies():
    context = object()
    server = SimpleNamespace(running_tools=[], recent_tools=[])
    app = MonitorApp(context, "127.0.0.1", 8000, server)

    assert app.server_context is context
    assert app.host == "127.0.0.1"
    assert app.port == 8000
    assert app.server is server


def test_queue_size_uses_available_fallbacks(monkeypatch):
    queue = SimpleNamespace(total=lambda: 3)
    assert queue_size(queue) == 3

    queue = SimpleNamespace(total=lambda: (_ for _ in ()).throw(NotImplementedError()), active_size=lambda: 4)
    assert queue_size(queue) == 4

    queue = SimpleNamespace(total=lambda: (_ for _ in ()).throw(OSError("unavailable")), qsize=lambda: 5)
    assert queue_size(queue) == 5

    queue = SimpleNamespace(total=lambda: (_ for _ in ()).throw(OSError("unavailable")))
    assert queue_size(queue) == 0

    monkeypatch.setattr("shyhurricane.monitor.active_queue_size", lambda value: 6)
    queue = SimpleNamespace(unack_count=1, _count=2)
    assert queue_size(queue) == 6


@pytest.mark.asyncio
async def test_get_recent_indexed_urls_filters_missing_metadata():
    records = [
        SimpleNamespace(payload={"meta": {"url": "https://example.test/one"}}),
        SimpleNamespace(payload={"meta": {}}),
        SimpleNamespace(payload={}),
    ]

    class Client:
        async def scroll(self, **kwargs):
            assert kwargs["collection_name"] == "network"
            assert kwargs["timeout"] == kwargs["limit"] == 5
            assert kwargs["order_by"].direction == "desc"
            assert kwargs["with_vectors"] is False
            return records, None

    assert await get_recent_indexed_urls(Client()) == ["https://example.test/one"]


@pytest.mark.asyncio
async def test_recent_urls_timeout_and_connection_errors_propagate(monkeypatch):
    timeout = asyncio.timeout
    monkeypatch.setattr(asyncio, "timeout", lambda seconds: timeout(0.01))

    async def blocked(**kwargs):
        await asyncio.Event().wait()

    client = SimpleNamespace(scroll=AsyncMock(side_effect=blocked))
    with pytest.raises(TimeoutError):
        await get_recent_indexed_urls(client)
    client.scroll.side_effect = ConnectionError("offline")
    with pytest.raises(ConnectionError, match="offline"):
        await get_recent_indexed_urls(client)


def test_qdrant_freshness_panels_distinguish_unavailable_empty_and_stale():
    assert format_qdrant_freshness({}) == ""
    assert format_qdrant_freshness({"status": "cached", "age_seconds": 299}) == ""
    assert format_qdrant_freshness({"status": "unavailable", "age_seconds": None}) == "\nUnavailable"
    assert format_qdrant_freshness({"status": "stale", "age_seconds": 301}) == "\nStale (301s old)"
    data = SimpleNamespace(
        document_counts={"finding": 0, "network": 12}, domain_count=1, host_count=1,
        top_domains=[("example.test", 12)], top_hosts=[("www.example.test", 12)],
        qdrant_freshness={
            "domains": {"status": "unavailable", "age_seconds": None},
            "documents:finding": {"status": "unavailable", "age_seconds": None},
            "documents:network": {"status": "stale", "age_seconds": 360},
        },
    )
    assert "Domains: 0" not in format_domain_and_host_panel(data)
    assert "Statistics unavailable" in format_domain_and_host_panel(data)
    panel = format_monitor_database_panel(data)
    assert "Findings: unavailable" in panel
    assert "network: 12\nStale (360s old)" in panel
    data.qdrant_freshness["domains"] = {"status": "stale", "age_seconds": 300}
    panel = format_domain_and_host_panel(data)
    assert "Stale (300s old)" in panel and "Domains: 1" in panel


@pytest.mark.asyncio
@pytest.mark.parametrize("has_primary_store", [False, True])
async def test_monitor_cache_integration_retains_all_qdrant_samples(monkeypatch, has_primary_store):
    now = [0.0]
    cache = MonitorQdrantCache(lambda: now[0])
    store = SimpleNamespace(count_documents_async=AsyncMock(return_value=12))
    context = SimpleNamespace(
        db="db", stores={"network": store}, task_queue=Queue(0), spider_result_queue=Queue(0),
        port_scan_result_queue=Queue(0), dir_busting_result_queue=Queue(0), proxy_host=None,
        proxy_port=None, proxy_ca_cert_path=None, qdrant_client=SimpleNamespace(
            collection_exists=AsyncMock(return_value=True), count=AsyncMock(return_value=SimpleNamespace(count=193)),
        ), health_monitor=None, low_power=False,
    )
    if has_primary_store:
        context.stores["finding"] = Store(0)
    monkeypatch.setattr("shyhurricane.monitor.persistent_queue_counts", AsyncMock(return_value=queue_counts()))
    monkeypatch.setattr("shyhurricane.monitor.graph_status", AsyncMock(return_value={}))
    monkeypatch.setattr("shyhurricane.monitor.get_generator_config", lambda: SimpleNamespace(describe=lambda: "model"))
    urls = AsyncMock(return_value=["https://example.test/"])
    domains = AsyncMock(return_value=({"example.test": 12}, {"www.example.test": 12}))
    monkeypatch.setattr("shyhurricane.monitor.get_recent_indexed_urls", urls)
    monkeypatch.setattr("shyhurricane.monitor.get_domain_and_host_counts", domains)
    first = await collect_monitor_data(context, "localhost", 8000, [], qdrant_cache=cache)
    now[0] = 30
    await collect_monitor_data(context, "localhost", 8000, [], qdrant_cache=cache)
    assert urls.await_count == 2
    assert domains.await_count == store.count_documents_async.await_count == 1
    assert first.document_counts["finding"] == 193
    assert context.qdrant_client.count.await_count == 1
    now[0] = 300
    for loader in (urls, domains, store.count_documents_async, context.qdrant_client.count):
        loader.side_effect = ConnectionError("offline")
    stale = await collect_monitor_data(context, "localhost", 8000, [], qdrant_cache=cache)
    assert stale.document_counts == first.document_counts
    assert stale.top_domains == first.top_domains
    assert stale.recent_urls == first.recent_urls
    assert all(sample["status"] == "stale" for sample in stale.qdrant_freshness.values())


def test_top_counts_limits_results_and_sorts_ties_by_name():
    assert top_counts({"beta.test": 3, "alpha.test": 3, "gamma.test": 2}, limit=2) == [
        ("alpha.test", 3),
        ("beta.test", 3),
    ]
    assert top_counts({}) == []


def test_format_database_panel_sorts_counts_descending_with_name_tiebreaker():
    assert format_database_panel({"content": 8, "network": 12, "metadata": 12}) == (
        "[b]Database statistics[/b]\nFindings: 0\nmetadata: 12\nnetwork: 12\ncontent: 8"
    )
    assert format_database_panel({}) == "[b]Database statistics[/b]\nFindings: 0"


@pytest.mark.parametrize("finding_count", [0, 2, 1000])
def test_format_database_panel_pins_primary_findings_above_top_five_collections(finding_count):
    counts = {"finding": finding_count, "finding_256": 200, **{f"collection_{i}": 100 + i for i in range(6)}}

    lines = format_database_panel(counts).splitlines()

    assert lines == [
        "[b]Database statistics[/b]",
        f"Findings: {finding_count}",
        "finding_256: 200",
        "collection_5: 105",
        "collection_4: 104",
        "collection_3: 103",
        "collection_2: 102",
    ]
    assert counts["finding"] == finding_count


def test_format_database_panel_with_only_findings():
    assert format_database_panel({"finding": 7}) == "[b]Database statistics[/b]\nFindings: 7"


def test_format_database_panel_does_not_use_chunks_when_primary_findings_missing():
    assert format_database_panel({"finding_256": 23}) == (
        "[b]Database statistics[/b]\nFindings: 0\nfinding_256: 23"
    )


def test_format_domain_and_host_panel_includes_top_counts_and_empty_states():
    data = MonitorData(
        bound_address="127.0.0.1:8000",
        proxy_address="not started",
        model="Ollama llama3.2:3b at localhost:11434",
        model_health=None,
        certificate_fingerprint=None,
        database="db",
        qdrant_host_bind="127.0.0.1",
        qdrant_http_port=49201,
        qdrant_health=None,
        low_power=False,
        document_counts={},
        domain_count=2,
        host_count=0,
        top_domains=[("example.test", 4), ("other.test", 2)],
        top_hosts=[],
        queue_sizes={},
        recent_urls=[],
        running_tools=[],
    )

    assert format_domain_and_host_panel(data) == (
        "[b]Domains and hosts[/b]\nDomains: 2\nHosts: 0\n[b]Top domains[/b]\n"
        "example.test: 4\nother.test: 2\n[b]Top hosts[/b]\nNo hosts indexed"
    )


def test_format_configuration_panel_orders_dependencies_and_shows_health_indicators():
    data = MonitorData(
        bound_address="127.0.0.1:8000",
        proxy_address="not started",
        model="model",
        model_health=True,
        certificate_fingerprint=None,
        database="qdrant",
        qdrant_host_bind="127.0.0.1",
        qdrant_http_port=49201,
        qdrant_health=False,
        graph={"healthy": None, "queue_depth": 0},
        low_power=False,
        document_counts={},
        domain_count=0,
        host_count=0,
        top_domains=[],
        top_hosts=[],
        queue_sizes={},
        recent_urls=[],
        running_tools=[],
    )

    panel = format_configuration_panel(data)
    assert panel.index("Model: model 🟢") < panel.index("Qdrant: 127.0.0.1:49201 🔴")
    assert "Qdrant: 127.0.0.1:49201 🔴" in panel
    assert data.database not in panel
    assert "healthy" not in panel
    assert "unhealthy" not in panel
    assert "Host bind:" not in panel
    assert "HTTP port:" not in panel


def test_format_configuration_panel_marks_missing_qdrant_endpoint_unavailable():
    data = MonitorData(
        bound_address="127.0.0.1:8000",
        proxy_address="not started",
        model="model",
        model_health=None,
        certificate_fingerprint=None,
        database="qdrant",
        qdrant_host_bind=None,
        qdrant_http_port=None,
        qdrant_health=None,
        low_power=False,
        document_counts={},
        domain_count=0,
        host_count=0,
        top_domains=[],
        top_hosts=[],
        queue_sizes={},
        recent_urls=[],
        running_tools=[],
    )

    panel = format_configuration_panel(data)

    assert "Qdrant: unavailable:unavailable (unavailable)" in panel
    assert data.database not in panel


def test_format_configuration_panel_shows_low_power_setting():
    enabled_data = MonitorData(
        bound_address="127.0.0.1:8000",
        proxy_address="not started",
        model="model",
        model_health=True,
        certificate_fingerprint=None,
        database="qdrant",
        qdrant_host_bind="127.0.0.1",
        qdrant_http_port=49201,
        qdrant_health=True,
        low_power=True,
        document_counts={},
        domain_count=0,
        host_count=0,
        top_domains=[],
        top_hosts=[],
        queue_sizes={},
        recent_urls=[],
        running_tools=[],
    )
    disabled_data = MonitorData(
        bound_address="127.0.0.1:8000",
        proxy_address="not started",
        model="model",
        model_health=True,
        certificate_fingerprint=None,
        database="qdrant",
        qdrant_host_bind="127.0.0.1",
        qdrant_http_port=49201,
        qdrant_health=True,
        low_power=False,
        document_counts={},
        domain_count=0,
        host_count=0,
        top_domains=[],
        top_hosts=[],
        queue_sizes={},
        recent_urls=[],
        running_tools=[],
    )

    enabled_panel = format_configuration_panel(enabled_data)
    disabled_panel = format_configuration_panel(disabled_data)

    assert "Low power: enabled" in enabled_panel
    assert "Low power: disabled" in disabled_panel


def test_health_monitor_exposes_unavailable_then_per_service_results():
    monitor = HealthMonitor(lambda: True, lambda: False)
    assert monitor.qdrant_healthy is None
    assert monitor.llm_healthy is None

    assert monitor.check() is False
    assert monitor.qdrant_healthy is True
    assert monitor.llm_healthy is False


def test_health_monitor_marks_connection_probe_errors_unhealthy():
    def unavailable_qdrant():
        raise ConnectionError("Qdrant is unavailable")

    monitor = HealthMonitor(unavailable_qdrant, lambda: True)

    assert monitor.check() is False
    assert monitor.qdrant_healthy is False
    assert monitor.llm_healthy is True
    assert monitor.ready.is_set() is False


def test_health_monitor_recovers_after_qdrant_probe_failure():
    results = iter([ConnectionError("Qdrant is unavailable"), True])

    def qdrant_probe():
        result = next(results)
        if isinstance(result, Exception):
            raise result
        return result

    monitor = HealthMonitor(qdrant_probe, lambda: True)

    assert monitor.check() is False
    assert monitor.qdrant_healthy is False
    assert monitor.check() is True
    assert monitor.qdrant_healthy is True
    assert monitor.ready.is_set() is True


@pytest.mark.asyncio
async def test_get_domain_and_host_counts_deduplicates_case_insensitively(monkeypatch):
    async def facet(**kwargs):
        assert kwargs["exact"] is True
        values = (["Example.test", "example.test", "other.test", ""]
                  if kwargs["key"] == "meta.domain"
                  else ["www.example.test", "WWW.EXAMPLE.TEST", "api.other.test", ""])
        return SimpleNamespace(hits=[SimpleNamespace(value=value, count=1) for value in values])

    domain_counts, host_counts = await get_domain_and_host_counts(SimpleNamespace(facet=facet), 1)

    assert domain_counts == {"example.test": 2, "other.test": 1}
    assert host_counts == {"www.example.test": 2, "api.other.test": 1}


@pytest.mark.asyncio
@pytest.mark.parametrize("graph_depth", [0, 7])
async def test_collect_monitor_data_includes_runtime_configuration_and_statistics(monkeypatch, tmp_path, graph_depth):
    certificate = tmp_path / "proxy-ca.pem"
    certificate.write_text(
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBhTCCASugAwIBAgIUakK0PF4EoVw0kMKZQmANq+ocwF0wCgYIKoZIzj0E\n"
        "AwIwEzERMA8GA1UEAwwIc2h5aHVycmkwHhcNMjYwNzMwMDAwMDAwWhcNMjcw\n"
        "NzMwMDAwMDAwWjATMREwDwYDVQQDDAhzaHlodXJyaTBZMBMGByqGSM49AgEG\n"
        "CCqGSM49AwEHA0IABKRTw8lYTeX9n4rKznysPImrc3N2SpDFsNTt1YO3n4Tf\n"
        "ZPJX4n7sfJ7PlOqOzg+tp7TaJPsiwv3bIFxlhxCjUzBRMB0GA1UdDgQWBBT0\n"
        "TGPHo2MO6Rr3yAVcLfRAYFgzDjAfBgNVHSMEGDAWgBT0TGPHo2MO6Rr3yAVc\n"
        "LfRAYFgzDjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQDd\n"
        "Y29uZHVjdG9yLW5vdC1hLXJlYWwtY2VydGlmaWNhdGUhIQIgVGVzdCBjZXJ0\n"
        "aWZpY2F0ZSBjb250ZW50IGlzIG5vdCB2YWxpZC4=\n"
        "-----END CERTIFICATE-----\n"
    )
    context = SimpleNamespace(
        db="/tmp/shyhurricane.db",
        ingest_queue=Queue(3),
        task_queue=Queue(2),
        spider_result_queue=Queue(1),
        port_scan_result_queue=Queue(0),
        dir_busting_result_queue=Queue(4),
        stores={"content": Store(12), "network": Store(8)},
        proxy_host="127.0.0.1",
        proxy_port=8010,
        proxy_ca_cert_path=certificate,
        qdrant_client=SimpleNamespace(
            collection_exists=AsyncMock(return_value=True), count=AsyncMock(return_value=SimpleNamespace(count=193)),
        ),
        qdrant_host="127.0.0.1",
        qdrant_port=49201,
        health_monitor=SimpleNamespace(llm_healthy=True, qdrant_healthy=False),
    )

    async def recent_urls(*args, **kwargs):
        return ["https://example.test/second", "https://example.test/first"]

    async def domain_and_host_counts(*args, **kwargs):
        return {"first.test": 1, "second.test": 2, "third.test": 1}, {
            "one.first.test": 1,
            "two.second.test": 1,
            "three.third.test": 1,
            "four.third.test": 1,
            "five.third.test": 1,
        }

    monkeypatch.setattr("shyhurricane.monitor.persistent_queue_counts", AsyncMock(return_value=queue_counts(3, 5, graph_depth)))
    graph_status = AsyncMock(return_value={"healthy": None, "queue_depth": graph_depth})
    monkeypatch.setattr("shyhurricane.monitor.graph_status", graph_status)
    monkeypatch.setattr(
        "shyhurricane.monitor.get_generator_config",
        lambda: SimpleNamespace(describe=lambda: "OpenAI gpt-5-nano"),
    )
    monkeypatch.setattr("shyhurricane.monitor.get_recent_indexed_urls", recent_urls)
    monkeypatch.setattr("shyhurricane.monitor.get_domain_and_host_counts", domain_and_host_counts)

    data = await collect_monitor_data(
        context, "127.0.0.1", 8000, ["port_scan"], [("find_urls", "complete")]
    )
    graph_status.assert_awaited_once_with(context, include_estimates=False)

    assert data == MonitorData(
        bound_address="127.0.0.1:8000",
        proxy_address="127.0.0.1:8010",
        model="OpenAI gpt-5-nano",
        model_health=True,
        certificate_fingerprint=None,
        database="/tmp/shyhurricane.db",
        qdrant_host_bind="127.0.0.1",
        qdrant_http_port=49201,
        qdrant_health=False,
        low_power=False,
        graph={"healthy": None, "queue_depth": graph_depth},
        queue_failures={name: 0 for name in ("index", "type-specific index", "scan findings", "graph")},
        document_counts={"content": 12, "network": 8, "finding": 193},
        domain_count=3,
        host_count=5,
        top_domains=[("second.test", 2), ("first.test", 1), ("third.test", 1)],
        top_hosts=[
            ("five.third.test", 1),
            ("four.third.test", 1),
            ("one.first.test", 1),
            ("three.third.test", 1),
            ("two.second.test", 1),
        ],
        queue_sizes={
            "index": 3,
            "type-specific index": 5,
            "scan findings": 0,
            "graph": graph_depth,
            "tasks": 2,
            "spider results": 1,
            "port scan results": 0,
            "directory busting results": 4,
        },
        recent_urls=["https://example.test/second", "https://example.test/first"],
        running_tools=["port_scan"],
        recent_tools=[("find_urls", "complete")],
    )
    disk = {"state": "paused", "error": "missing mount"}
    context.health_monitor.disk_guard = SimpleNamespace(snapshot=lambda: dict(disk))
    refreshed = await collect_monitor_data(context, "127.0.0.1", 8000, [])
    assert refreshed.disk == disk


@pytest.mark.asyncio
async def test_collect_monitor_data_tolerates_unavailable_qdrant_document_counts(monkeypatch):
    context = SimpleNamespace(
        db="qdrant:6333",
        ingest_queue=Queue(0),
        task_queue=Queue(0),
        spider_result_queue=Queue(0),
        port_scan_result_queue=Queue(0),
        dir_busting_result_queue=Queue(0),
        stores={"javascript": UnavailableStore(), "finding": UnavailableStore()},
        proxy_host=None,
        proxy_port=None,
        proxy_ca_cert_path=None,
        qdrant_client=object(),
        health_monitor=SimpleNamespace(llm_healthy=True, qdrant_healthy=False),
    )

    monkeypatch.setattr("shyhurricane.monitor.persistent_queue_counts", AsyncMock(return_value=queue_counts()))
    monkeypatch.setattr(
        "shyhurricane.monitor.get_generator_config",
        lambda: SimpleNamespace(describe=lambda: "model"),
    )

    async def recent_urls(*args, **kwargs):
        return []

    monkeypatch.setattr("shyhurricane.monitor.get_recent_indexed_urls", recent_urls)
    monkeypatch.setattr(
        "shyhurricane.monitor.get_domain_and_host_counts",
        lambda *args: ({}, {}),
    )

    data = await collect_monitor_data(context, "127.0.0.1", 8000, [], qdrant_cache=MonitorQdrantCache())

    assert data.document_counts == {"javascript": 0, "finding": 0}
    assert format_database_panel(data.document_counts).splitlines()[1] == "Findings: 0"
    assert "Findings: unavailable" in format_monitor_database_panel(data)
    assert data.qdrant_health is False


@pytest.mark.asyncio
async def test_collect_monitor_data_tolerates_unavailable_optional_data(monkeypatch):
    context = SimpleNamespace(
        db="qdrant:6333",
        ingest_queue=Queue(0),
        task_queue=Queue(0),
        spider_result_queue=Queue(0),
        port_scan_result_queue=Queue(0),
        dir_busting_result_queue=Queue(0),
        stores={},
        proxy_host=None,
        proxy_port=None,
        proxy_ca_cert_path=None,
        qdrant_client=object(),
        health_monitor=None,
    )

    monkeypatch.setattr("shyhurricane.monitor.persistent_queue_counts", AsyncMock(return_value=queue_counts()))
    monkeypatch.setattr(
        "shyhurricane.monitor.get_generator_config",
        lambda: SimpleNamespace(describe=lambda: "Ollama llama3.2:3b at localhost:11434"),
    )

    async def unavailable_urls(*args, **kwargs):
        raise RuntimeError("database unavailable")

    async def unavailable_domain_and_host_counts(*args, **kwargs):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr("shyhurricane.monitor.get_recent_indexed_urls", unavailable_urls)
    monkeypatch.setattr("shyhurricane.monitor.get_domain_and_host_counts", unavailable_domain_and_host_counts)

    data = await collect_monitor_data(context, "0.0.0.0", 8000, [])

    assert data.proxy_address == "not started"
    assert data.model == "Ollama llama3.2:3b at localhost:11434"
    assert data.model_health is None
    assert data.qdrant_health is None
    assert data.recent_urls == []
    assert data.domain_count == 0
    assert data.host_count == 0
    assert data.top_domains == []
    assert data.top_hosts == []
    assert data.running_tools == []
    assert data.low_power is False


@pytest.mark.asyncio
async def test_collect_monitor_data_reads_low_power_from_context_and_config(monkeypatch):
    context_with_low_power = SimpleNamespace(
        db="qdrant:6333",
        ingest_queue=Queue(0),
        task_queue=Queue(0),
        spider_result_queue=Queue(0),
        port_scan_result_queue=Queue(0),
        dir_busting_result_queue=Queue(0),
        stores={},
        proxy_host=None,
        proxy_port=None,
        proxy_ca_cert_path=None,
        qdrant_client=object(),
        health_monitor=None,
        low_power=True,
    )
    context_without_low_power = SimpleNamespace(
        db="qdrant:6333",
        ingest_queue=Queue(0),
        task_queue=Queue(0),
        spider_result_queue=Queue(0),
        port_scan_result_queue=Queue(0),
        dir_busting_result_queue=Queue(0),
        stores={},
        proxy_host=None,
        proxy_port=None,
        proxy_ca_cert_path=None,
        qdrant_client=object(),
        health_monitor=None,
    )

    monkeypatch.setattr("shyhurricane.monitor.persistent_queue_counts", AsyncMock(return_value=queue_counts()))
    monkeypatch.setattr(
        "shyhurricane.monitor.get_generator_config",
        lambda: SimpleNamespace(describe=lambda: "model"),
    )
    monkeypatch.setattr("shyhurricane.monitor.get_recent_indexed_urls", lambda *args, **kwargs: [])
    monkeypatch.setattr("shyhurricane.monitor.get_domain_and_host_counts", lambda *args, **kwargs: ({}, {}))

    data1 = await collect_monitor_data(context_with_low_power, "127.0.0.1", 8000, [])
    assert data1.low_power is True

    monkeypatch.setattr(
        "shyhurricane.monitor.get_server_config",
        lambda: SimpleNamespace(low_power=True),
    )
    data2 = await collect_monitor_data(context_without_low_power, "127.0.0.1", 8000, [])
    assert data2.low_power is True


@pytest.mark.asyncio
async def test_monitor_refreshes_immediately_then_every_thirty_seconds(monkeypatch):
    app = MonitorApp(SimpleNamespace(), "127.0.0.1", 8000, SimpleNamespace(running_tools=[], recent_tools=[]))
    refresh = AsyncMock()
    schedule = Mock()
    monkeypatch.setattr(app, "refresh_data", refresh)
    monkeypatch.setattr(app, "set_interval", schedule)

    await app.on_mount()

    refresh.assert_awaited_once_with()
    schedule.assert_called_once_with(30, refresh)


@pytest.mark.asyncio
async def test_monitor_refresh_action_awaits_data_refresh(monkeypatch):
    app = MonitorApp(SimpleNamespace(), "127.0.0.1", 8000, SimpleNamespace(running_tools=[], recent_tools=[]))
    refresh = AsyncMock()
    monkeypatch.setattr(app, "refresh_data", refresh)

    await app.action_refresh()

    refresh.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_monitor_app_toggle_low_power_action(monkeypatch):
    server_config = ServerConfig(low_power=False)
    monkeypatch.setattr("shyhurricane.monitor.get_server_config", lambda: server_config)
    context = SimpleNamespace(
        db="qdrant:6333",
        ingest_queue=Queue(0),
        task_queue=Queue(0),
        spider_result_queue=Queue(0),
        port_scan_result_queue=Queue(0),
        dir_busting_result_queue=Queue(0),
        stores={},
        proxy_host=None,
        proxy_port=None,
        proxy_ca_cert_path=None,
        qdrant_client=object(),
        health_monitor=None,
        low_power=False,
    )
    server = SimpleNamespace(running_tools=[], recent_tools=[])
    monkeypatch.setattr("shyhurricane.monitor.persistent_queue_counts", AsyncMock(return_value=queue_counts()))
    monkeypatch.setattr(
        "shyhurricane.monitor.get_generator_config",
        lambda: SimpleNamespace(describe=lambda: "model"),
    )
    monkeypatch.setattr("shyhurricane.monitor.get_recent_indexed_urls", lambda *args, **kwargs: [])
    monkeypatch.setattr("shyhurricane.monitor.get_domain_and_host_counts", lambda *args, **kwargs: ({}, {}))

    app = MonitorApp(context, "127.0.0.1", 8000, server)

    # Toggle from False to True
    await app.action_toggle_low_power()
    assert context.low_power is True
    assert server_config.low_power is True

    # Toggle from True to False
    await app.action_toggle_low_power()
    assert context.low_power is False
    assert server_config.low_power is False


@pytest.mark.asyncio
async def test_monitor_app_toggle_low_power_with_immutable_context(monkeypatch):
    server_config = ServerConfig(low_power=False)
    monkeypatch.setattr("shyhurricane.monitor.get_server_config", lambda: server_config)
    context = object()
    server = SimpleNamespace(running_tools=[], recent_tools=[])

    app = MonitorApp(context, "127.0.0.1", 8000, server)

    async def mock_collect(*args, **kwargs):
        return MonitorData(
            bound_address="127.0.0.1:8000",
            proxy_address="not started",
            model="model",
            model_health=None,
            certificate_fingerprint=None,
            database="db",
            qdrant_host_bind=None,
            qdrant_http_port=None,
            qdrant_health=None,
            low_power=server_config.low_power,
            document_counts={},
            domain_count=0,
            host_count=0,
            top_domains=[],
            top_hosts=[],
            queue_sizes={},
            recent_urls=[],
            running_tools=[],
        )

    monkeypatch.setattr("shyhurricane.monitor.collect_monitor_data", mock_collect)

    await app.action_toggle_low_power()
    assert server_config.low_power is True


@pytest.mark.asyncio
async def test_monitor_app_key_press_toggles_low_power(monkeypatch):
    server_config = ServerConfig(low_power=False)
    monkeypatch.setattr("shyhurricane.monitor.get_server_config", lambda: server_config)
    context = SimpleNamespace(
        db="qdrant:6333",
        ingest_queue=Queue(0),
        task_queue=Queue(0),
        spider_result_queue=Queue(0),
        port_scan_result_queue=Queue(0),
        dir_busting_result_queue=Queue(0),
        stores={},
        proxy_host=None,
        proxy_port=None,
        proxy_ca_cert_path=None,
        qdrant_client=object(),
        health_monitor=None,
        low_power=False,
    )
    server = SimpleNamespace(running_tools=[], recent_tools=[])
    monkeypatch.setattr("shyhurricane.monitor.persistent_queue_counts", AsyncMock(return_value=queue_counts()))
    monkeypatch.setattr(
        "shyhurricane.monitor.get_generator_config",
        lambda: SimpleNamespace(describe=lambda: "model"),
    )
    monkeypatch.setattr("shyhurricane.monitor.get_recent_indexed_urls", lambda *args, **kwargs: [])
    monkeypatch.setattr("shyhurricane.monitor.get_domain_and_host_counts", lambda *args, **kwargs: ({}, {}))

    app = MonitorApp(context, "127.0.0.1", 8000, server)
    async with app.run_test() as pilot:
        assert context.low_power is False
        assert "Low power: disabled" in app.query_one("#configuration-content", Static).content

        # Press 'l' (lowercase)
        await pilot.press("l")
        assert context.low_power is True
        assert server_config.low_power is True
        assert "Low power: enabled" in app.query_one("#configuration-content", Static).content


@pytest.mark.asyncio
async def test_monitor_refresh_key_updates_data_and_ignores_unrelated_keys(monkeypatch):
    server_config = ServerConfig(low_power=False)
    monkeypatch.setattr("shyhurricane.monitor.get_server_config", lambda: server_config)
    context = SimpleNamespace(
        db="qdrant:6333",
        ingest_queue=Queue(0),
        task_queue=Queue(0),
        spider_result_queue=Queue(0),
        port_scan_result_queue=Queue(0),
        dir_busting_result_queue=Queue(0),
        stores={},
        proxy_host=None,
        proxy_port=None,
        proxy_ca_cert_path=None,
        qdrant_client=object(),
        health_monitor=None,
        low_power=False,
    )
    server = SimpleNamespace(running_tools=[], recent_tools=[])
    queue_sizes = AsyncMock(return_value=queue_counts())
    monkeypatch.setattr("shyhurricane.monitor.persistent_queue_counts", queue_sizes)
    monkeypatch.setattr(
        "shyhurricane.monitor.get_generator_config",
        lambda: SimpleNamespace(describe=lambda: "model"),
    )
    monkeypatch.setattr("shyhurricane.monitor.get_recent_indexed_urls", lambda *args, **kwargs: [])
    monkeypatch.setattr("shyhurricane.monitor.get_domain_and_host_counts", lambda *args, **kwargs: ({}, {}))

    app = MonitorApp(context, "127.0.0.1", 8000, server)
    async with app.run_test() as pilot:
        queue_sizes.reset_mock()
        server.running_tools = ["port_scan"]

        await pilot.press("x")
        queue_sizes.assert_not_awaited()
        assert "No MCP tools run" in app.query_one("#tools", Static).content

        await pilot.press("r")
        queue_sizes.assert_awaited_once()
        assert "port_scan" in app.query_one("#tools", Static).content
        assert server_config.low_power is False
        assert not getattr(server, "should_exit", False)

        server.recent_tools = [("port_scan", "complete")]
        server.running_tools = ["spider_website"]
        await pilot.press("r")
        assert queue_sizes.await_count == 2
        assert "spider_website" in app.query_one("#tools", Static).content
        content = app.query_one("#tools", Static).content
        assert "[green]●[/green] port_scan" in content
        assert content.index("spider_website") < content.index("port_scan")
        assert app.query_one("#tools", Static).styles.overflow_y == "auto"

        server.running_tools = []
        await pilot.press("r")
        content = app.query_one("#tools", Static).content
        assert "[b]MCP tools[/b]" in content
        assert "port_scan" in content
        assert "No MCP tools run" not in content


def test_graph_panel_separates_progress_counts_and_failures_into_lines():
    graph = {
        "publication_revision": 42, "publication_revision_delta": 3,
        "seconds_since_observed_progress": 31.2,
        "analyses": {"complete": 9, "processing": 1, "failed": 2}, "queue_depth": 12,
    }
    assert format_graph_panel(graph).splitlines() == [
        "[b]Graph activity[/b]", "Publication revision: 42", "Change since sample: +3",
        "Last observed advance: 31s ago", "Completed analyses: 9", "Processing: 1",
        "Queue depth: 12", "Failed: 2",
    ]
    assert "Graph" not in format_database_panel({"network": 48})
    graph["continuations"] = {
        "pending": 1, "running": 0, "failed": 2, "stage": "planning",
        "contexts_completed": 100, "contexts_discovered": 12538,
    }
    text = format_graph_panel(graph)
    assert "Link stage: planning\nContexts: 100/12538" in text
    assert "Continuations: 1 pending / 0 running\nContinuation failures: 2" in text
    graph["publication_revision_delta"] = 0
    assert "Change since sample: +0" in format_graph_panel(graph)
    assert "Publication revision: unavailable" in format_graph_panel(None)
    graph = {"activity_stale": True, "activity_error": "ClientError"}
    text = format_graph_panel(graph)
    assert "Change since sample: awaiting baseline" in text and "Last observed advance: not yet observed" in text
    assert "Activity: stale or awaiting refresh\nActivity error: ClientError" in text
    graph["statistics_error"] = "OperationalError"
    assert "Analysis error: OperationalError" in format_graph_panel(graph)
    graph["activity_error_code"] = "Neo.ClientError.Transaction.TransactionTimedOut"
    assert "Activity error: Neo.ClientError.Transaction.TransactionTimedOut" in format_graph_panel(graph)


def queue_counts(ingest=0, doc_type=0, graph=0):
    return {name: {"pending": pending, "processing": 0, "failed": 0}
            for name, pending in (("ingest", ingest), ("type_specific_index", doc_type),
                                  ("scan_findings", 0), ("graph", graph))}


def test_queue_panel_failed_counts():
    from shyhurricane.monitor import format_queue_panel

    assert format_queue_panel({"index": 0, "scan findings": 2, "graph": None},
                              {"index": 3, "scan findings": 0}) == (
        "index: 0, 3 failed\nscan findings: 2"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("result", [{"ingest": 0, "scan_findings": 3}, {"ingest": "database locked"}])
async def test_monitor_retry_failed_action(monkeypatch, result):
    retry = AsyncMock(return_value=result)
    monkeypatch.setattr("shyhurricane.monitor.retry_failed_queue_items", retry)
    app = MonitorApp(SimpleNamespace(db="db"), "localhost", 8000, SimpleNamespace())
    app.notify = Mock()
    app.refresh_data = AsyncMock()
    await app.action_retry_failed()
    retry.assert_awaited_once_with("db")
    app.refresh_data.assert_awaited_once()
    assert app._retrying_failed is False
    assert app.notify.call_args.kwargs["severity"] == (
        "warning" if isinstance(result["ingest"], str) else "information"
    )
    app._retrying_failed = True
    await app.action_retry_failed()
    retry.assert_awaited_once()


@pytest.mark.asyncio
async def test_monitor_retry_error_and_key_binding(monkeypatch):
    monkeypatch.setattr("shyhurricane.monitor.retry_failed_queue_items", AsyncMock(side_effect=OSError("failed")))
    app = MonitorApp(SimpleNamespace(db="db"), "localhost", 8000, SimpleNamespace())
    app.notify = Mock()
    app.refresh_data = AsyncMock()
    async with app.run_test() as pilot:
        await pilot.press("f")
    app.notify.assert_called_once_with("Unable to retry failed queue items; see logs", severity="error")
    assert app._retrying_failed is False


@pytest.mark.asyncio
async def test_monitor_reports_queue_read_failures_as_unavailable(monkeypatch):
    import sqlite3

    context = SimpleNamespace(
        db="db", stores={}, task_queue=Queue(0), spider_result_queue=Queue(0),
        port_scan_result_queue=Queue(0), dir_busting_result_queue=Queue(0), proxy_host=None,
        proxy_port=None, proxy_ca_cert_path=None, health_monitor=None, low_power=False,
    )
    monkeypatch.setattr("shyhurricane.monitor.persistent_queue_counts",
                        AsyncMock(side_effect=sqlite3.OperationalError("locked")))
    monkeypatch.setattr("shyhurricane.monitor.graph_status", AsyncMock(return_value={}))
    monkeypatch.setattr("shyhurricane.monitor.get_generator_config", lambda: SimpleNamespace(describe=lambda: "model"))
    monkeypatch.setattr("shyhurricane.monitor.get_recent_indexed_urls", AsyncMock(return_value=[]))
    monkeypatch.setattr("shyhurricane.monitor.get_domain_and_host_counts", AsyncMock(return_value=({}, {})))
    data = await collect_monitor_data(context, "localhost", 8000, [])
    assert all(data.queue_sizes[name] is None for name in ("index", "type-specific index", "scan findings", "graph"))
    assert data.queue_failures == {}


def test_format_tools_panel_status_order_empty_state_and_escaping():
    assert format_tools_panel([], []) == "[b]MCP tools[/b]\nNo MCP tools run"
    assert format_tools_panel(["scan"], [("scan", "failed"), ("[bold]", "complete")]) == (
        "[b]MCP tools[/b]\n[yellow]●[/yellow] scan\n[red]●[/red] scan\n"
        "[green]●[/green] " + "\\[bold]"
    )
    assert format_tools_panel([], [("scan", "complete")]) == (
        "[b]MCP tools[/b]\n[green]●[/green] scan"
    )


@pytest.mark.asyncio
async def test_three_middle_panels_keep_graph_separate_and_scrollable(monkeypatch):
    data = MonitorData(
        bound_address="localhost:8000", proxy_address="not started", model="model", model_health=True,
        certificate_fingerprint=None, database="db", qdrant_host_bind="localhost", qdrant_http_port=6333,
        qdrant_health=True, low_power=False, document_counts={"network": 48}, domain_count=1, host_count=1,
        top_domains=[("example.com", 48)], top_hosts=[("www.example.com", 48)],
        queue_sizes={"index": 3, "graph": 12}, queue_failures={"graph": 2}, recent_urls=[], running_tools=[],
        graph={"publication_revision": 42, "publication_revision_delta": 3, "seconds_since_observed_progress": 31,
               "queue_depth": 12, "analyses": {"complete": 9, "processing": 1, "failed": 2},
               "continuations": {"pending": 1, "running": 0, "failed": 2, "stage": "planning",
                                 "contexts_completed": 100, "contexts_discovered": 12538}},
    )
    monkeypatch.setattr("shyhurricane.monitor.collect_monitor_data", AsyncMock(return_value=data))
    app = MonitorApp(SimpleNamespace(), "localhost", 8000, SimpleNamespace(running_tools=[], recent_tools=[]))
    async with app.run_test(size=(150, 60)) as pilot:
        await pilot.pause()
        configuration, queues, database, graph_panel, domains, urls, tools = [
            app.query_one(f"#{name}")
            for name in ("configuration", "queues", "database", "graph-panel", "domains", "urls", "tools")
        ]
        graph = app.query_one("#graph", Static)
        assert configuration.region.y == queues.region.y < database.region.y
        assert database.region.y == graph_panel.region.y == domains.region.y < urls.region.y == tools.region.y
        assert database.region.right < graph_panel.region.x and graph_panel.region.right < domains.region.x
        assert configuration.region.width > graph_panel.region.width and urls.region.width > graph_panel.region.width
        assert "network: 48" in database.content and "Publication revision" not in database.content
        assert "Queue depth: 12" in graph.content and "Change since sample: +3" in graph.content
        assert "Last observed advance: 31s ago" in graph.content
        assert queues.content == "[b]Queue status[/b]\nindex: 3"
        await pilot.resize_terminal(80, 24)
        await pilot.pause()
        assert graph_panel.max_scroll_y > 0
        graph_panel.scroll_end(animate=False, immediate=True)
        await pilot.pause()
        assert graph_panel.scroll_y > 0


@pytest.mark.parametrize("state,error,minimums,expected", [
    ("disabled", None, (0, 0), "Disk guard: disabled"),
    ("checking", None, (3, 2147483648), "Disk: checking; indexing paused"),
    ("paused", "missing [mount]", (3, 2147483648), "disk measurement unavailable"),
    ("healthy", None, (3, 2147483648), "4.00 GiB (4.00%) free (healthy)"),
    ("paused", None, (3, 2147483648), "resume at 4% and 2.5 GiB"),
    ("paused", None, (0, 2147483648), "resume at 2.5 GiB"),
    ("paused", None, (3, 0), "resume at 4%"),
])
def test_disk_status_rendering(state, error, minimums, expected):
    from shyhurricane.monitor import format_disk_status

    snapshot = {
        "state": state, "error": error, "free_bytes": 4 * 1024**3, "free_percent": 4,
        "min_free_percent": minimums[0], "min_free_bytes": minimums[1],
        "resume_margin_percent": 1, "resume_margin_bytes": 512 * 1024**2,
    }
    assert expected in format_disk_status(snapshot)
    assert format_disk_status(None) == "Disk: unavailable"


def test_graph_panel_reports_investigation_progress_and_errors(monkeypatch):
    monkeypatch.setattr("shyhurricane.monitor.time.time", lambda: 220)
    panel = format_graph_panel({"investigation": {
        "completed": 3, "pending": 2, "failed": 1, "stale": 2, "policy_version": 1,
        "last_successful_refresh": 100, "error": "ServiceUnavailable",
    }})
    assert "Investigations: 3 completed / 2 pending / 1 failed" in panel
    assert "Investigation lag: 2 findings; policy 1" in panel
    assert "Investigation last refresh: 2m ago" in panel
    assert "Investigation error: ServiceUnavailable" in panel


@pytest.mark.parametrize(("timestamp", "now", "expected"), [
    (95, 100, "5s ago"),
    (40, 100, "1m ago"),
    (-3500, 100, "1h ago"),
    (-86300, 100, "1d ago"),
    (110, 100, "0s ago"),
    (None, 100, "awaiting results"),
])
def test_investigation_refresh_duration(timestamp, now, expected):
    from shyhurricane.monitor import format_duration_since

    assert format_duration_since(timestamp, now) == expected


@pytest.mark.parametrize(("elapsed", "expected"), [
    (31.9, "31s ago"),
    (60, "1m ago"),
    (3600, "1h ago"),
    (86400, "1d ago"),
    (-10, "0s ago"),
    (None, "not yet observed"),
])
def test_graph_last_advance_duration(monkeypatch, elapsed, expected):
    monkeypatch.setattr("shyhurricane.monitor.time.time", lambda: 100000)
    panel = format_graph_panel({"seconds_since_observed_progress": elapsed})
    assert f"Last observed advance: {expected}" in panel


def test_graph_panel_displays_derived_work_counts():
    panel = format_graph_panel({"investigation": {"work": {
        "derive": {"pending": 3, "failed": 1}, "hotspot": {"pending": 2, "failed": 0},
    }}})
    assert "Investigation derive work: 3 pending / 1 failed" in panel
    assert "Investigation hotspot work: 2 pending / 0 failed" in panel


@pytest.mark.asyncio
async def test_monitor_literal_urls_and_markup_recovery(monkeypatch):
    from rich.text import Text

    data = MonitorData(
        bound_address="localhost:8000", proxy_address="not started", model="model", model_health=True,
        certificate_fingerprint=None, database="db", qdrant_host_bind="localhost", qdrant_http_port=6333,
        qdrant_health=True, low_power=False, document_counts={}, domain_count=0, host_count=0,
        top_domains=[], top_hosts=[], queue_sizes={}, running_tools=[],
        recent_urls=["https://example.com/", "https://[::1]/", "https://example.com/[/bad]",
                     "https://example.com/[bold]literal[/bold]"],
    )
    monkeypatch.setattr("shyhurricane.monitor.collect_monitor_data", AsyncMock(return_value=data))
    monkeypatch.setattr("shyhurricane.monitor.format_configuration_panel", lambda data: "[/bad]")
    app = MonitorApp(SimpleNamespace(), "localhost", 8000, SimpleNamespace(running_tools=[], recent_tools=[]))
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.query_one("#configuration-content", Static).content.plain == "[/bad]"
        assert app.query_one("#urls", Static).content.plain == (
            "Last five URLs indexed\n" + "\n".join(data.recent_urls)
        )
        assert "No MCP tools run" in app.query_one("#tools", Static).content
        app.update_panel("#configuration-content", "[b]Recovered[/b]")
        assert app.query_one("#configuration-content", Static).content == "[b]Recovered[/b]"
        await app.refresh_data()
        assert app.is_running
        data.recent_urls.clear()
        await app.refresh_data()
        assert "No URLs indexed" in app.query_one("#urls", Static).content.plain
        data.qdrant_freshness["urls"] = {"status": "unavailable"}
        await app.refresh_data()
        assert "Unavailable" in app.query_one("#urls", Static).content.plain
        assert isinstance(app.query_one("#urls", Static).content, Text)


@pytest.mark.parametrize("ready,tools,count,expected", [
    (True, [], 0, "idle"), (True, [], 1, "working"),
    (False, [], 1, "blocked"), (False, ["tool"], 1, "working"),
    (True, [], None, "blocked"),
])
def test_terminal_activity(ready, tools, count, expected):
    from types import SimpleNamespace

    from shyhurricane.monitor import terminal_status

    data = SimpleNamespace(model_health=True, qdrant_health=True, graph={"healthy": True},
                           disk={"state": "disabled"}, queue_sizes={"queue": count})
    assert terminal_status(data, ready, tools) == ("#00ff00", expected)
    data.model_health = None
    assert terminal_status(data, ready, tools)[0] == "#ffa500"
    data.qdrant_health = False
    assert terminal_status(data, ready, tools)[0] == "#ff0000"


@pytest.mark.parametrize("graph", [
    {"investigation": {"work": {"reconcile": {"pending": 1}}}},
    {"continuations": {"running": 1}}, {"analyses": {"processing": 1}},
    {"queue_depth": 1},
])
def test_terminal_background_work(graph):
    from shyhurricane.monitor import terminal_status

    data = SimpleNamespace(model_health=True, qdrant_health=True, graph=graph,
                           disk={"state": "healthy"}, queue_sizes={})
    assert terminal_status(data, True, [])[1] == "working"
    assert terminal_status(data, False, [])[1] == "blocked"


def test_terminal_unknown_counts_preserve_previous_activity():
    from shyhurricane.monitor import terminal_status

    data = SimpleNamespace(model_health=True, qdrant_health=True, graph={"error": "unavailable"},
                           disk={"state": "checking"}, queue_sizes={})
    assert terminal_status(data, True, [], "working") == ("#ffa500", "working")
    data.disk = {"state": "paused"}
    assert terminal_status(data, True, [])[0] == "#ff0000"


def test_terminal_output_and_cleanup(monkeypatch):
    from pathlib import Path
    from unittest.mock import Mock

    monkeypatch.setenv("TERM_PROGRAM", "iTerm.app")
    monkeypatch.setattr("shyhurricane.monitor.sys.stdout.isatty", lambda: True)
    monkeypatch.setattr("shyhurricane.monitor.resolve_data_dir", lambda: Path("/tmp/assessment\x1b\n"))
    context = SimpleNamespace(health_monitor=SimpleNamespace(ready=SimpleNamespace(is_set=lambda: True)))
    app = MonitorApp(context, "127.0.0.1", 8000, SimpleNamespace(running_tools=[]))
    driver = Mock(is_headless=False)
    app._driver = driver
    data = SimpleNamespace(model_health=True, qdrant_health=True, graph={"healthy": True},
                           disk={"state": "healthy"}, queue_sizes={})
    app.publish_terminal_status(data)
    assert driver.write.call_args_list[0].args == ("\x1b]1;shyhurricane - assessment\x1b\\",)
    assert driver.write.call_args_list[1].args == ("\x1b]21337;indicator=#00ff00;status=idle;status-color=\x1b\\",)
    app.publish_terminal_status(data)
    assert driver.write.call_count == 2
    data.queue_sizes = {"queue": 1}
    app.publish_terminal_status(data)
    assert driver.write.call_args.args == (
        "\x1b]21337;indicator=#00ff00;status=working;status-color=#ffa500\x1b\\",
    )
    context.health_monitor.ready.is_set = lambda: False
    app.publish_terminal_status(data)
    assert driver.write.call_args.args == (
        "\x1b]21337;indicator=#00ff00;status=blocked;status-color=#ff0000\x1b\\",
    )
    data.queue_sizes = {}
    app.publish_terminal_status(data)
    assert driver.write.call_args.args == (
        "\x1b]21337;indicator=#00ff00;status=idle;status-color=\x1b\\",
    )
    app.on_unmount()
    assert driver.write.call_args.args == ("\x1b]21337;status=;indicator=;status-color=\x1b\\",)
    driver.reset_mock()
    driver.is_headless = True
    app.publish_terminal_status(data)
    driver.write.assert_not_called()
    app._driver = None
    app.publish_terminal_status(data)
    app.on_unmount()
