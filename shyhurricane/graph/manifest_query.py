"""Paged inventory queries never depend on the size of the materialized Neo4j graph."""

import sqlite3

from shyhurricane.graph.cursors import QueryCursors
from shyhurricane.graph.discovery import INTERPRETATION, present_manifest
from shyhurricane.graph.model import compact_event, identity, optional_filter


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
    detail=None,
):
    if not 1 <= limit <= 1000:
        raise ValueError("Graph page size must be between 1 and 1000")
    if detail is not None:
        present_manifest({}, detail)
    url, method, context_url = map(optional_filter, (url, method, context_url))
    watermark = artifacts.manifest.watermark() if watermark is None else watermark
    if "expires" in watermark:
        expires = min(expires or watermark["expires"], watermark["expires"])
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
                    "detail": detail,
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
        "results": records if detail is None else [present_manifest(record, detail) for record in records],
        "instructions": INTERPRETATION,
        "coverage": coverage,
        "omitted_regions": [],
        "analysis_gaps": gaps,
        "retrieval_truncated": token is not None or timed_out,
        "truncation_reasons": (["time_limit"] if timed_out else []) + (["page_limit"] if token else []),
        "continuation_token": token,
    }


def expand_analysis(artifacts, queue, scope, capture_id, unit_id):
    selected = artifacts.manifest.inventory_reader().lookup_unit(scope, unit_id, capture_id)
    row = artifacts.connection.execute(
        "SELECT c.path FROM captures c WHERE c.id=?", (capture_id,),
    ).fetchone()
    if selected is None or row is None or not selected["artifact"]:
        raise ValueError("Analysis unit is unavailable in the requested scope")
    budget = artifacts.budget
    event = artifacts.read(row[0], limit=64 * 1024 * 1024)
    if budget is not None:
        budget.check()
    work_id = identity("expand", capture_id, unit_id, selected["generation"])
    item = {**compact_event(event), "rebuild_token": work_id, "analysis_unit_id": unit_id, "offline_analysis": True,
            "inventory_generation": selected["generation"], "inventory_artifact": selected["artifact"]}
    result = {"work_id": work_id, "capture_id": capture_id, "analysis_unit_id": unit_id, "status": "pending"}
    if queue is None:
        return item, result
    queue.put(item)
    return result
