from types import SimpleNamespace

import pytest

from shyhurricane.db import get_domain_and_host_counts
from shyhurricane.monitor import (
    MonitorData,
    collect_monitor_data,
    format_database_panel,
    format_domain_and_host_panel,
    top_counts,
)


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


def test_top_counts_limits_results_and_sorts_ties_by_name():
    assert top_counts({"beta.test": 3, "alpha.test": 3, "gamma.test": 2}, limit=2) == [
        ("alpha.test", 3),
        ("beta.test", 3),
    ]
    assert top_counts({}) == []


def test_format_database_panel_sorts_counts_descending_with_name_tiebreaker():
    assert format_database_panel({"content": 8, "network": 12, "metadata": 12}) == (
        "[b]Database statistics[/b]\nmetadata: 12\nnetwork: 12\ncontent: 8"
    )
    assert format_database_panel({}) == "[b]Database statistics[/b]\nNo collections"


def test_format_domain_and_host_panel_includes_top_counts_and_empty_states():
    data = MonitorData(
        bound_address="127.0.0.1:8000",
        proxy_address="not started",
        model="Ollama llama3.2:3b at localhost:11434",
        certificate_fingerprint=None,
        database="db",
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


@pytest.mark.asyncio
async def test_get_domain_and_host_counts_deduplicates_case_insensitively(monkeypatch):
    async def records(*args, **kwargs):
        for metadata in (
            {"domain": "Example.test", "host": "www.example.test"},
            {"domain": "example.test", "host": "WWW.EXAMPLE.TEST"},
            {"domain": "other.test", "host": "api.other.test"},
            {},
        ):
            yield SimpleNamespace(payload={"meta": metadata})

    monkeypatch.setattr("shyhurricane.db.scroll_qdrant_collection", records)

    domain_counts, host_counts = await get_domain_and_host_counts(object(), 1)

    assert domain_counts == {"example.test": 2, "other.test": 1}
    assert host_counts == {"www.example.test": 2, "api.other.test": 1}


@pytest.mark.asyncio
async def test_collect_monitor_data_includes_runtime_configuration_and_statistics(monkeypatch, tmp_path):
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
        qdrant_client=object(),
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

    monkeypatch.setattr("shyhurricane.monitor.get_doc_type_queue", lambda db: Queue(5))
    monkeypatch.setattr(
        "shyhurricane.monitor.get_generator_config",
        lambda: SimpleNamespace(describe=lambda: "OpenAI gpt-5-nano"),
    )
    monkeypatch.setattr("shyhurricane.monitor.get_recent_indexed_urls", recent_urls)
    monkeypatch.setattr("shyhurricane.monitor.get_domain_and_host_counts", domain_and_host_counts)

    data = await collect_monitor_data(context, "127.0.0.1", 8000, ["port_scan"])

    assert data == MonitorData(
        bound_address="127.0.0.1:8000",
        proxy_address="127.0.0.1:8010",
        model="OpenAI gpt-5-nano",
        certificate_fingerprint=None,
        database="/tmp/shyhurricane.db",
        document_counts={"content": 12, "network": 8},
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
            "tasks": 2,
            "spider results": 1,
            "port scan results": 0,
            "directory busting results": 4,
        },
        recent_urls=["https://example.test/second", "https://example.test/first"],
        running_tools=["port_scan"],
    )


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
    )

    monkeypatch.setattr("shyhurricane.monitor.get_doc_type_queue", lambda db: Queue(0))
    monkeypatch.setattr(
        "shyhurricane.monitor.get_generator_config",
        lambda: SimpleNamespace(describe=lambda: "Ollama llama3.2:3b at localhost:11434"),
    )

    async def unavailable_urls(*args, **kwargs):
        raise RuntimeError("database unavailable")

    async def unavailable_domain_and_host_counts(*args, **kwargs):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr("shyhurricane.monitor.get_recent_indexed_urls", unavailable_urls)
    monkeypatch.setattr(
        "shyhurricane.monitor.get_domain_and_host_counts", unavailable_domain_and_host_counts
    )

    data = await collect_monitor_data(context, "0.0.0.0", 8000, [])

    assert data.proxy_address == "not started"
    assert data.model == "Ollama llama3.2:3b at localhost:11434"
    assert data.recent_urls == []
    assert data.domain_count == 0
    assert data.host_count == 0
    assert data.top_domains == []
    assert data.top_hosts == []
    assert data.running_tools == []