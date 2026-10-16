import logging
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from qdrant_client.http import models as qm
from rich.markup import escape
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.widgets import Footer, Header, Static

from shyhurricane.db import get_domain_and_host_counts
from shyhurricane.graph.status import graph_status
from shyhurricane.index.web_resources_pipeline import WEB_RESOURCE_VERSION
from shyhurricane.mcp_server.generator_config import get_generator_config
from shyhurricane.persistent_queue import active_queue_size, persistent_queue_counts, retry_failed_queue_items
from shyhurricane.server_config import get_server_config

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MonitorData:
    bound_address: str
    proxy_address: str
    model: str
    model_health: bool | None
    certificate_fingerprint: str | None
    database: str
    qdrant_host_bind: str | None
    qdrant_http_port: int | None
    qdrant_health: bool | None
    low_power: bool
    document_counts: dict[str, int]
    domain_count: int
    host_count: int
    top_domains: list[tuple[str, int]]
    top_hosts: list[tuple[str, int]]
    queue_sizes: dict[str, int | None]
    recent_urls: list[str]
    running_tools: list[str]
    recent_tools: list[tuple[str, str]] = field(default_factory=list)
    graph: dict | None = None
    queue_failures: dict[str, int] = field(default_factory=dict)


def certificate_fingerprint(certificate_path: Path | None) -> str | None:
    if certificate_path is None:
        return None
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        certificate = x509.load_pem_x509_certificate(Path(certificate_path).read_bytes())
        return certificate.fingerprint(hashes.SHA256()).hex(":")
    except (OSError, ValueError):
        return None


def queue_size(queue) -> int:
    if hasattr(queue, "unack_count") and hasattr(queue, "_count"):
        return active_queue_size(queue)
    total = getattr(queue, "total", None)
    if total is not None:
        try:
            return total() if callable(total) else total
        except (NotImplementedError, OSError):
            pass
    for method_name in ("active_size", "qsize"):
        method = getattr(queue, method_name, None)
        if method is not None:
            try:
                return method()
            except (NotImplementedError, OSError):
                pass
    return 0


async def get_recent_indexed_urls(qdrant_client) -> list[str]:
    filters = qm.Filter(
        must=[qm.FieldCondition(key="meta.version", match=qm.MatchValue(value=WEB_RESOURCE_VERSION))]
    )
    records, _ = await qdrant_client.scroll(
        collection_name="network",
        scroll_filter=filters,
        limit=5,
        with_payload=["meta.url"],
        with_vectors=False,
        order_by=qm.OrderBy(key="meta.timestamp_float", direction=qm.Direction.DESC),
    )
    return [
        metadata["url"]
        for record in records
        if (metadata := record.payload.get("meta", {})).get("url")
    ]


def top_counts(counts: dict[str, int], limit: int = 5) -> list[tuple[str, int]]:
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]


def format_database_panel(document_counts: dict[str, int], graph: dict | None = None) -> str:
    counts = f"Findings: {document_counts.get('finding', 0)}"
    other_counts = {name: count for name, count in document_counts.items() if name != "finding"}
    for name, count in top_counts(other_counts):
        counts += f"\n{name}: {count}"
    if graph:
        counts += "\n[b]Application graph (estimates)[/b]"
        for key, label in (("current", "Current graph"), ("retained_history", "Retained history")):
            summary = graph.get(key)
            if summary is None:
                counts += f"\n{label}: unavailable"
                continue
            entities, relationships = summary["entity_estimate"], summary["relationship_estimate"]
            values = f"≈{entities} entities / ≈{relationships} relationships" if entities is not None else "unavailable"
            counts += f"\n{label}: {values}"
            counts += f"\nCaptures: {summary['captures']} / resources: {summary['resources']}"
            if not summary["coverage_complete"]:
                counts += f" (partial: {summary['covered_captures']} captures counted)"
        if graph.get("statistics_stale"):
            counts += "\nStatistics: stale or awaiting first refresh"
        counts += (f"\nQueued: {graph.get('queue_depth', 0)}"
                   f"\nFailed: {graph.get('analyses', {}).get('failed', 0)}"
                   f"\nUnresolved references: {graph.get('unresolved_references', 'unavailable')}")
    return f"[b]Database statistics[/b]\n{counts}"


def format_domain_and_host_panel(data: MonitorData) -> str:
    domains = "\n".join(f"{domain}: {count}" for domain, count in data.top_domains) or "No domains indexed"
    hosts = "\n".join(f"{host}: {count}" for host, count in data.top_hosts) or "No hosts indexed"
    return (
        f"[b]Domains and hosts[/b]\nDomains: {data.domain_count}\nHosts: {data.host_count}\n"
        f"[b]Top domains[/b]\n{domains}\n[b]Top hosts[/b]\n{hosts}"
    )


def health_label(healthy: bool | None) -> str:
    if healthy is None:
        return "(unavailable)"
    return "🟢" if healthy else "🔴"


def format_configuration_panel(data: MonitorData) -> str:
    fingerprint = data.certificate_fingerprint or "unavailable"
    qdrant_host_bind = data.qdrant_host_bind or "unavailable"
    qdrant_http_port = data.qdrant_http_port if data.qdrant_http_port is not None else "unavailable"
    low_power = "enabled" if data.low_power else "disabled"
    return (
        "[b]Configuration[/b]\n"
        f"Model: {data.model} {health_label(data.model_health)}\n"
        f"Qdrant: {data.database} {qdrant_host_bind}:{qdrant_http_port} {health_label(data.qdrant_health)}\n"
        f"Neo4j: {(data.graph or {}).get('uri', 'unavailable')} "
        f"{health_label((data.graph or {}).get('healthy'))}\n"
        f"Low power: {low_power}\n"
        f"MCP: {data.bound_address}\n"
        f"Proxy: {data.proxy_address}\nTLS SHA-256: {fingerprint}"
    )


async def collect_monitor_data(
    server_context, host: str, port: int, running_tools: Iterable[str],
    recent_tools: Iterable[tuple[str, str]] = (),
) -> MonitorData:
    document_counts = {}
    for collection_name, store in server_context.stores.items():
        try:
            document_counts[collection_name] = await store.count_documents_async()
        except Exception:
            logger.debug("Unable to load document count for %s", collection_name, exc_info=True)
            document_counts[collection_name] = 0
    try:
        counts = await persistent_queue_counts(server_context.db)
    except (OSError, sqlite3.Error):
        logger.warning("Unable to read queue counts", exc_info=True)
        counts = {}
    labels = {"index": "ingest", "type-specific index": "type_specific_index",
              "scan findings": "scan_findings", "graph": "graph"}
    graph = await graph_status(server_context)
    queues = {
        **{label: counts[name]["pending"] + counts[name]["processing"] if name in counts else None
           for label, name in labels.items()},
        "tasks": queue_size(server_context.task_queue),
        "spider results": queue_size(server_context.spider_result_queue),
        "port scan results": queue_size(server_context.port_scan_result_queue),
        "directory busting results": queue_size(server_context.dir_busting_result_queue),
    }
    proxy_address = "not started"
    if server_context.proxy_host is not None and server_context.proxy_port is not None:
        proxy_address = f"{server_context.proxy_host}:{server_context.proxy_port}"
    try:
        recent_urls = await get_recent_indexed_urls(server_context.qdrant_client)
    except Exception:
        logger.debug("Unable to load recently indexed URLs", exc_info=True)
        recent_urls = []
    try:
        domain_counts, host_counts = await get_domain_and_host_counts(
            server_context.qdrant_client, WEB_RESOURCE_VERSION
        )
        domain_count, host_count = len(domain_counts), len(host_counts)
        top_domains, top_hosts = top_counts(domain_counts), top_counts(host_counts)
    except Exception:
        logger.debug("Unable to load domain and host counts", exc_info=True)
        domain_count, host_count = 0, 0
        top_domains, top_hosts = [], []
    health_monitor = getattr(server_context, "health_monitor", None)
    low_power = getattr(server_context, "low_power", None)
    if low_power is None:
        low_power = getattr(get_server_config(), "low_power", False)
    return MonitorData(
        bound_address=f"{host}:{port}",
        proxy_address=proxy_address,
        model=get_generator_config().describe(),
        model_health=health_monitor.llm_healthy if health_monitor is not None else None,
        certificate_fingerprint=certificate_fingerprint(server_context.proxy_ca_cert_path),
        database=server_context.db,
        qdrant_host_bind=getattr(server_context, "qdrant_host", None),
        qdrant_http_port=getattr(server_context, "qdrant_port", None),
        qdrant_health=health_monitor.qdrant_healthy if health_monitor is not None else None,
        low_power=low_power,
        document_counts=document_counts,
        domain_count=domain_count,
        host_count=host_count,
        top_domains=top_domains,
        top_hosts=top_hosts,
        queue_sizes=queues,
        recent_urls=recent_urls,
        running_tools=sorted(running_tools),
        recent_tools=list(recent_tools),
        graph=graph,
        queue_failures={label: counts[name]["failed"] for label, name in labels.items() if name in counts},
    )


def format_queue_panel(sizes: dict[str, int | None], failures: dict[str, int]) -> str:
    lines = []
    for name, size in sizes.items():
        line = f"{name}: {size if size is not None else 'unavailable'}"
        if failures.get(name, 0) > 0:
            line += f", {failures[name]} failed"
        lines.append(line)
    return "\n".join(lines)


def format_tools_panel(running_tools: list[str], recent_tools: list[tuple[str, str]]) -> str:
    colors = {"running": "yellow", "complete": "green", "failed": "red"}
    entries = [(name, "running") for name in running_tools] + recent_tools
    rows = [f"[{colors[status]}]●[/{colors[status]}] {escape(name)}" for name, status in entries]
    tools = "\n".join(rows) or "No MCP tools run"
    return f"[b]MCP tools[/b]\n{tools}"


class MonitorApp(App[None]):
    TITLE = "shyhurricane"
    CSS = """
    Screen { layout: vertical; }
    #panels { layout: grid; grid-size: 2; grid-gutter: 1; padding: 1; }
    .panel { border: round $primary; padding: 1; height: 1fr; }
    #domains { height: 19; }
    #urls, #tools { height: 12; }
    #tools { overflow-y: auto; }
    """
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("f", "retry_failed", "Retry failed"),
        Binding("l", "toggle_low_power", "Toggle low power"),
    ]

    def __init__(self, server_context, host: str, port: int, server, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.server_context = server_context
        self.host = host
        self.port = port
        self.server = server
        self._retrying_failed = False

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="panels"):
            yield Static("Loading configuration…", id="configuration", classes="panel")
            yield Static("Loading queue status…", id="queues", classes="panel")
            yield Static("Loading database statistics…", id="database", classes="panel")
            yield Static("Loading domain and host statistics…", id="domains", classes="panel")
            yield Static("Loading recent URLs…", id="urls", classes="panel")
            yield Static("Loading MCP tools…", id="tools", classes="panel")
        yield Footer()

    async def on_mount(self) -> None:
        await self.refresh_data()
        self.set_interval(30, self.refresh_data)

    async def refresh_data(self) -> None:
        data = await collect_monitor_data(
            self.server_context, self.host, self.port, self.server.running_tools, self.server.recent_tools
        )
        if not self.is_running:
            return
        self.query_one("#configuration", Static).update(format_configuration_panel(data))
        queues = format_queue_panel(data.queue_sizes, data.queue_failures)
        self.query_one("#queues", Static).update(f"[b]Queue status[/b]\n{queues}")
        self.query_one("#database", Static).update(format_database_panel(data.document_counts, data.graph))
        self.query_one("#domains", Static).update(format_domain_and_host_panel(data))
        urls = "\n".join(data.recent_urls) or "No URLs indexed"
        self.query_one("#urls", Static).update(f"[b]Last five URLs indexed[/b]\n{urls}")
        self.query_one("#tools", Static).update(format_tools_panel(data.running_tools, data.recent_tools))

    async def action_refresh(self) -> None:
        await self.refresh_data()

    async def action_retry_failed(self) -> None:
        if self._retrying_failed:
            return
        self._retrying_failed = True
        try:
            results = await retry_failed_queue_items(self.server_context.db)
            message = "; ".join(
                f"{name}: {value} marked pending" if isinstance(value, int) else f"{name}: {value}"
                for name, value in results.items()
            )
            self.notify(message, severity="warning" if any(isinstance(v, str) for v in results.values()) else "information")
            await self.refresh_data()
        except Exception:
            logger.exception("Unable to retry failed queue items")
            self.notify("Unable to retry failed queue items; see logs", severity="error")
        finally:
            self._retrying_failed = False

    async def action_toggle_low_power(self) -> None:
        current_low_power = getattr(self.server_context, "low_power", None)
        if current_low_power is None:
            current_low_power = getattr(get_server_config(), "low_power", False)
        new_low_power = not current_low_power

        if self.server_context is not None:
            set_low_power = getattr(self.server_context, "set_low_power", None)
            if callable(set_low_power):
                set_low_power(new_low_power)
            try:
                self.server_context.low_power = new_low_power
            except (AttributeError, TypeError):
                pass
        server_config = get_server_config()
        if server_config is not None and hasattr(server_config, "low_power"):
            try:
                server_config.low_power = new_low_power
            except (AttributeError, TypeError):
                pass
        await self.refresh_data()

    def action_quit(self) -> None:
        self.server.should_exit = True
        self.exit()


async def run_monitor(server_context, host: str, port: int, server) -> None:
    await MonitorApp(server_context, host, port, server).run_async()
