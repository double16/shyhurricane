"""Bounded, request-scoped waits for query-relevant persistent indexing."""

import argparse
import asyncio
import logging
import math
import sqlite3
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps
from inspect import signature
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from shyhurricane.persistent_queue import PERSISTENT_QUEUES, persistent_queue_path
from shyhurricane.queue_scopes import scoped_queue_rows
from shyhurricane.server_config import get_server_config

logger = logging.getLogger(__name__)
POLL_SECONDS = 1.0
PROGRESS_SECONDS = 5.0


class IndexingStatus(BaseModel):
    status: Literal["complete", "timed_out", "paused", "failed", "unavailable", "disabled"]
    waited_seconds: float = 0
    potentially_incomplete: bool = False
    stages: dict[str, dict[str, int]] = Field(default_factory=dict)
    skipped_stages: list[str] = Field(default_factory=list)


class IndexingOnlyResult(BaseModel):
    indexing: IndexingStatus


def indexing_timeout(value: str) -> float:
    try:
        seconds = float(value)
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError
        return seconds
    except ValueError as error:
        raise argparse.ArgumentTypeError("Indexing wait timeout must be finite and nonnegative") from error


@dataclass
class WaitBudget:
    remaining: float = field(default_factory=lambda: get_server_config().indexing_wait_timeout_seconds)
    waited: float = 0
    last: IndexingStatus | None = None
    in_wait: bool = False


_budget: ContextVar[WaitBudget | None] = ContextVar("indexing_wait_budget", default=None)


def indexing_scope(*, fresh=False):
    """Share only indexing-wait time across nested operations and resolver rounds."""

    def decorate(function):
        @wraps(function)
        async def wrapped(*args, **kwargs):
            if not fresh and _budget.get() is not None:
                return await function(*args, **kwargs)
            token = _budget.set(WaitBudget())
            try:
                return await function(*args, **kwargs)
            finally:
                _budget.reset(token)

        return wrapped

    return decorate


def attach_indexing(function):
    @wraps(function)
    async def wrapped(*args, **kwargs):
        result = await function(*args, **kwargs)
        budget = _budget.get()
        if isinstance(result, BaseModel) and "indexing" in type(result).model_fields and budget is not None:
            result.indexing = budget.last
        return result

    return wrapped


def url_matcher(scopes, *, exact=False):
    """Use graph/site hostname boundaries, effective ports and URL-prefix semantics."""
    from shyhurricane.graph.model import web_url
    from shyhurricane.graph.query import scope_predicate

    if exact:
        urls = {web_url(scope) for scope in scopes} - {None}
        return lambda url: web_url(url) in urls
    predicates = []
    for scope in scopes:
        if not scope:
            continue
        parsed = urlsplit(scope if "://" in scope else f"//{scope}")
        if parsed.query or parsed.fragment:
            canonical = web_url(scope)
            predicates.append(lambda url, wanted=canonical: wanted is not None and web_url(url) == wanted)
        else:
            predicates.append(scope_predicate(scope))
    return lambda url: not predicates or any(predicate(url) for predicate in predicates)


def inventory_matcher(query, *, domains=False, path=None):
    from shyhurricane.utils import extract_domain, query_to_netloc

    host, port = query_to_netloc(query)

    def matches(url):
        parsed = urlsplit(url)
        hostname = parsed.hostname or ""
        candidate = extract_domain(hostname) if domains else hostname
        effective_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return (
            (not host or (host.lower() in candidate if domains else candidate.endswith(host.lower())))
            and (domains or port is None or port <= 0 or port == effective_port)
            and (not path or path in url)
        )

    return matches


def _artifacts(db, matches, deadline):
    """Resolve retained dependency URLs, ticket scopes, and undelivered graph obligations."""
    path = persistent_queue_path(db, "graph_state") / "artifacts.sqlite"
    if not path.exists():
        return set(), {}, []
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=max(0, deadline - time.monotonic()))
    try:
        connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        connection.execute("BEGIN")
        captures = dict(connection.execute("SELECT id,url FROM captures"))
        dependencies = {}
        for capture_id, url in connection.execute("SELECT capture_id,url FROM refs"):
            dependencies.setdefault(captures.get(capture_id), set()).add(url)
        urls = {url for url in captures.values() if matches(url)}
        pending = list(urls)
        while pending:
            url = pending.pop()
            for target in dependencies.get(url, ()):
                if target not in urls:
                    urls.add(target)
                    pending.append(target)
            if time.monotonic() >= deadline:
                raise TimeoutError
        has_scheduler = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='reanalysis'"
        ).fetchone()
        outbox = (
            list(connection.execute("SELECT capture_id FROM reanalysis WHERE state='pending' AND delivered=0"))
            if has_scheduler
            else []
        )
        return urls, captures, outbox
    finally:
        connection.close()


def read_indexing_status(server, matches, stages, deadline, doc_id=None):
    """Read upstream before downstream so a durable handoff cannot disappear between reads."""
    counts = {}
    unresolved = False
    dependencies, captures, outbox = set(), {}, []
    for stage in stages:
        if stage == "graph":
            dependencies, captures, outbox = _artifacts(server.db, matches, deadline)
        values = {"pending": 0, "processing": 0, "failed": 0}
        seen = set()
        for row_id, status, url, document, capture, unknown in scoped_queue_rows(
            persistent_queue_path(server.db, PERSISTENT_QUEUES[stage]), max(0, deadline - time.monotonic())
        ):
            if time.monotonic() >= deadline:
                raise TimeoutError
            if unknown is None or unknown:
                unresolved = True
                continue
            if capture and not url:
                url = captures.get(capture)
                if url is None:
                    unresolved = True
                    continue
            if doc_id and stage == "ingest" and url:
                unresolved = True
            relevant = (document == doc_id) if doc_id else bool(url and (matches(url) or url in dependencies))
            if relevant and row_id not in seen:
                seen.add(row_id)
                values["failed" if status == 9 else "processing" if status == 2 else "pending"] += 1
        if stage == "graph":
            for (capture,) in outbox:
                url = captures.get(capture)
                if url is None:
                    unresolved = True
                elif matches(url) or url in dependencies:
                    values["pending"] += 1
        counts[stage] = values
    return counts, unresolved


async def _notify(ctx, message, deadline):
    from shyhurricane.mcp_server.progress import report_progress

    try:
        async with asyncio.timeout(max(0, deadline - time.monotonic())):
            await report_progress(ctx, message)
    except Exception:
        logger.warning("Cannot send indexing progress", exc_info=True)


async def wait_for_indexing(ctx, server, matches, *, semantic=False, graph=False, doc_id=None):
    budget = _budget.get() or WaitBudget()
    if budget.in_wait:
        return budget.last
    if get_server_config().indexing_wait_timeout_seconds == 0:
        budget.last = IndexingStatus(status="disabled", potentially_incomplete=True)
        return budget.last
    # A tracker without a configured database cannot establish indexing completion.
    try:
        database = server.db
    except AttributeError:
        database = None
    if not isinstance(database, str):
        budget.last = IndexingStatus(status="unavailable", potentially_incomplete=True)
        return budget.last
    started = time.monotonic()
    deadline = started + budget.remaining
    stages = ["ingest"] + (["type_specific_index"] if semantic else []) + (["graph"] if graph else [])
    counts = {}
    skipped = []
    status = "timed_out"
    last_report = None
    empty_reads = 0
    budget.in_wait = True
    try:
        while time.monotonic() < deadline:
            try:
                async with asyncio.timeout(max(0, deadline - time.monotonic())):
                    counts, unresolved = await asyncio.to_thread(
                        read_indexing_status,
                        server,
                        matches,
                        stages,
                        deadline,
                        doc_id,
                    )
            except TimeoutError:
                break
            except Exception:
                if time.monotonic() >= deadline:
                    break
                logger.warning("Cannot read scoped indexing status", exc_info=True)
                status = "unavailable"
                break
            if unresolved:
                status = "unavailable"
                break
            skipped = ["type_specific_index"] if semantic and server.low_power else []
            active = sum(
                value["pending"] + value["processing"] for stage, value in counts.items() if stage not in skipped
            )
            if not active:
                # Recheck dependencies/outbox once after graph publication may have changed references.
                empty_reads += 1
                if graph and empty_reads < 2:
                    continue
                failed = any(value["failed"] for value in counts.values())
                paused = any(counts[stage]["pending"] + counts[stage]["processing"] for stage in skipped)
                status = "failed" if failed else "paused" if paused else "complete"
                break
            empty_reads = 0
            now = time.monotonic()
            if last_report is None or now - last_report >= PROGRESS_SECONDS:
                details = ", ".join(
                    f"{stage}: {value['pending']} pending, {value['processing']} processing"
                    for stage, value in counts.items()
                )
                await _notify(ctx, f"Waiting for indexing ({budget.waited + now - started:.1f}s); {details}", deadline)
                last_report = now
            remaining = max(0, deadline - time.monotonic())
            if remaining <= 0.02:
                break
            # Reserve a small part of the same budget for the final progress notification.
            await asyncio.sleep(min(POLL_SECONDS, max(0, remaining - 0.02)))
    finally:
        elapsed = time.monotonic() - started
        budget.waited += elapsed
        budget.remaining = max(0, budget.remaining - elapsed)
        budget.in_wait = False
    budget.last = IndexingStatus(
        status=status,
        waited_seconds=round(budget.waited, 3),
        potentially_incomplete=status != "complete",
        stages=counts,
        skipped_stages=skipped,
    )
    if last_report is not None:
        # Completion notifications must not extend the indexing deadline.
        notification_started = time.monotonic()
        try:
            await _notify(ctx, f"Indexing wait {status}; querying available data", deadline)
        finally:
            elapsed = time.monotonic() - notification_started
            budget.waited += elapsed
            budget.remaining = max(0, budget.remaining - elapsed)
            budget.last.waited_seconds = round(budget.waited, 3)
    return budget.last


def indexed_inventory(*, domains=False):
    """Wrap public inventory calls while allowing internal inventories to bypass a second wait."""

    def decorate(function):
        function_signature = signature(function)

        @indexing_scope()
        @wraps(function)
        async def wrapped(*args, **kwargs):
            bound = function_signature.bind(*args, **kwargs)
            bound.apply_defaults()
            arguments = bound.arguments
            server = await function.__globals__["get_server_context"]()
            query = arguments.get("query", arguments.get("domain_query", arguments.get("host_query")))
            status = await wait_for_indexing(
                arguments["ctx"],
                server,
                inventory_matcher(query, domains=domains, path=arguments.get("path_query")),
            )
            result = await function(*args, **kwargs)
            result.indexing = status
            return result

        return wrapped

    return decorate
