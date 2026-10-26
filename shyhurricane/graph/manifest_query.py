"""Paged inventory queries never depend on the size of the materialized Neo4j graph."""

import sqlite3

from shyhurricane.graph.cursors import QueryCursors
from shyhurricane.graph.discovery import INTERPRETATION
from shyhurricane.graph.model import identity, optional_filter


def manifest_query(
    artifacts,
    scope,
    *,
    kind=None,
    role=None,
    capture_id=None,
    after="",
    limit=1000,
    seen=(),
    expires=None,
    url=None,
    method=None,
    historical=False,
    as_of=None,
    watermark=None,
    coverage=None,
    kinds=None,
    context_url=None,
    exclude_kinds=(),
    cursor_store=None,
):
    if not 1 <= limit <= 1000:
        raise ValueError("Graph page size must be between 1 and 1000")
    url, method, context_url = map(optional_filter, (url, method, context_url))
    watermark = artifacts.manifest.watermark() if watermark is None else watermark
    gaps = []
    timed_out = False
    records = []
    known = set(seen)
    cursor = after
    # A physical scan budget is resumable, rather than silently eliminating old/duplicate-heavy prefixes.
    try:
        for _ in range(5):
            rows, next_cursor = artifacts.manifest.page(
                scope,
                kind=kind,
                role=role,
                capture_id=capture_id,
                after=cursor,
                limit=limit,
                url=url,
                method=method,
                historical=historical,
                as_of=as_of,
                watermark=watermark,
                kinds=kinds,
                context_url=context_url,
                exclude_kinds=exclude_kinds,
            )
            cursor = next_cursor
            for record in rows:
                if len(records) >= limit:
                    cursor = records[-1]["manifest_id"]
                    break
                logical = record.get("id") or record["manifest_id"]
                if logical not in known:
                    known.add(logical)
                    records.append(record)
            if cursor is None or len(records) >= limit:
                break
    except TimeoutError:
        timed_out = True
        gaps.append("Discovery page retrieval exceeded the query budget; continue the query")
    if coverage is None or coverage.get("discovery") == "unknown":
        try:
            coverage = artifacts.manifest.coverage(
                capture_id, scope=scope, historical=historical, as_of=as_of, watermark=watermark
            )
        except TimeoutError:
            timed_out = True
            coverage = {"discovery": "unknown", "flow": "unknown"}
            gaps.append("Discovery coverage calculation exceeded the query budget")
            if cursor is None:
                cursor = records[-1]["manifest_id"] if records else after
    token = None
    if cursor is not None:
        store = cursor_store
        try:
            from shyhurricane.graph.budget import QueryBudget

            budget = artifacts.budget or QueryBudget()
            with budget.checkpoint():
                store = store or QueryCursors(artifacts.root, budget)
            with store.budget.checkpoint():
                token = store.save(
                {
                    "operation": "manifest",
                    "scope": scope,
                    "kind": kind,
                    "role": role,
                    "capture_id": capture_id,
                    "after": cursor,
                    "seen": sorted(known),
                    "url": url,
                    "method": method,
                    "historical": historical,
                    "as_of": as_of,
                    "watermark": watermark,
                    "coverage": coverage,
                    "kinds": kinds,
                    "context_url": context_url,
                    "exclude_kinds": exclude_kinds,
                },
                expires=expires,
            )
        except (TimeoutError, OSError, ValueError, sqlite3.Error):
            timed_out = True
            gaps.append("Continuation checkpoint failed; restart required")
        finally:
            if cursor_store is None and store is not None:
                store.close()
    return {
        "results": records,
        "instructions": INTERPRETATION,
        "coverage": coverage,
        "omitted_regions": [],
        "analysis_gaps": gaps,
        "retrieval_truncated": token is not None or timed_out,
        "truncation_reasons": (["time_limit"] if timed_out else []) + (["page_limit"] if token else []),
        "continuation_token": token,
    }


def expand_analysis(artifacts, queue, scope, capture_id, unit_id):
    import json

    from shyhurricane.graph.query import scope_predicate

    row = artifacts.connection.execute(
        "SELECT u.capture_id,u.source_path,c.url,c.path FROM graph_manifest_units u "
        "JOIN captures c ON c.id=u.capture_id WHERE u.id=? AND u.capture_id=?",
        (unit_id, capture_id),
    ).fetchone()
    matches = scope_predicate(scope)
    artifacts.connection.create_function("graph_expansion_scope", 1, matches, deterministic=True)
    in_context = row is not None and artifacts.connection.execute(
        "SELECT EXISTS (SELECT 1 FROM graph_unit_contexts WHERE unit_id IN "
        "(SELECT ? UNION SELECT parent_id FROM graph_unit_parents WHERE unit_id=?) "
        "AND graph_expansion_scope(url))", (unit_id, unit_id),
    ).fetchone()[0]
    if row is None or not (matches(row[2]) or in_context):
        raise ValueError("Analysis unit is unavailable in the requested scope")
    budget = artifacts.budget
    chunks = []
    size = 0
    with artifacts.resolve(row[3]).open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            if budget is not None:
                budget.check()
            size += len(chunk)
            if size > 64 * 1024 * 1024:
                raise ValueError("Retained capture exceeds the expansion submission size limit")
            chunks.append(chunk)
    event = json.loads(b"".join(chunks))
    if budget is not None:
        budget.check()
    work_id = identity("expand", capture_id, unit_id)
    item = {**event, "rebuild_token": work_id, "analysis_unit_id": unit_id, "offline_analysis": True}
    result = {"work_id": work_id, "capture_id": capture_id, "analysis_unit_id": unit_id, "status": "pending"}
    if queue is None:
        return item, result
    queue.put(item)
    return result
