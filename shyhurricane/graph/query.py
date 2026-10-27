"""Bounded, deterministic semantic queries; no user-supplied Cypher."""

import json
import logging
import sqlite3
import time
from collections import deque
from itertools import batched
from urllib.parse import urlsplit

from neo4j.exceptions import Neo4jError

from shyhurricane.graph.budget import QueryBudget
from shyhurricane.graph.config import graph_timeouts
from shyhurricane.graph.discovery import INTERPRETATION, ResourceDiscovery, in_context, present
from shyhurricane.graph.model import FLOW_KINDS, JOURNEY_KINDS, identity, optional_filter, web_url
from shyhurricane.graph.visibility import public_properties, visible_node, visible_relationship

logger = logging.getLogger(__name__)

MAX_RESULTS = 1000
MAX_ENTITIES = 10000


def scope_predicate(scope: str):
    explicit = "://" in scope
    parsed = urlsplit(scope if explicit else f"https://{scope}")
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("scope must be a hostname, host:port, or HTTP(S) URL prefix")
    if explicit and parsed.scheme not in {"http", "https"}:
        raise ValueError("scope URL must use HTTP or HTTPS")
    if not explicit and parsed.path not in {"", "/"}:
        raise ValueError("Use an HTTP(S) URL when scope includes a path prefix")
    port = parsed.port

    def contains(url):
        candidate = urlsplit(url)
        host = candidate.hostname or ""
        matched = host == parsed.hostname or (not explicit and host.endswith(f".{parsed.hostname}"))
        candidate_port = candidate.port or (443 if candidate.scheme in {"https", "wss"} else 80)
        if port is not None and candidate_port != port:
            return False
        return (
            matched
            and (not explicit or candidate.scheme == parsed.scheme)
            and (not explicit or candidate.path.startswith(parsed.path or "/"))
        )

    return contains


class GraphQuery:
    def __init__(self, store, *, budget=None, artifacts=None):
        self.store = store
        self.budget = budget or QueryBudget()
        self.cursor_store = None
        self.artifacts = artifacts

    def read(self, statement, **parameters):
        return self.budget.read(self.store, statement, **parameters)

    def snapshot(self, scope, **arguments):
        try:
            return self._snapshot(scope, **arguments)
        except (TimeoutError, Neo4jError) as error:
            if isinstance(error, Neo4jError) and "TransactionTimedOut" not in (error.code or ""):
                raise
            return {}, [], {
                "analysis_gaps": [
                    "Snapshot selection exceeded its query budget; lookup migration may still be pending"
                ],
                "analysis_summaries": [], "retrieval_truncated": True, "truncation_reasons": ["time_limit"],
                "instructions": INTERPRETATION,
            }

    def _snapshot(self, scope: str, *, historical=False, as_of: float | None = None, context_url=None, role=None):
        contains = scope_predicate(scope)
        # Filter membership before the bounded working set is selected. Context archives have
        # no digest; ordinary publications always have one, even after retirement.
        element_filter = ""
        if context_url is not None or role is not None:
            element_filter = (
                "AND any(n IN [a,b] WHERE ($role IS NULL OR n.role=$role) "
                "AND ($context_url IS NULL OR n.url=$context_url OR "
                "(n.context_owner_id IS NULL AND $context_url IN coalesce(n.context_urls,[])) OR EXISTS { "
                "MATCH (lookup:GraphContext {owner_id:n.context_owner_id,url:$context_url}) } OR EXISTS { "
                "OPTIONAL MATCH (p:GraphPublication {id:n.context_owner_id}) "
                "OPTIONAL MATCH (archive:GraphPublication {capture_id:n.context_owner_id}) "
                "WHERE archive.digest IS NULL "
                "OPTIONAL MATCH (owner:GraphCapture {id:n.context_owner_id}) "
                "WITH coalesce(p.context_urls,archive.context_urls,owner.context_urls,[]) AS urls "
                "WHERE $context_url IN urls RETURN 1 AS matched })) "
            )
        # Fetch one bounded immutable working set and save result pages after traversal.
        references = self.read(
            "MATCH (c:GraphCapture) WHERE c.complete=true AND ($as_of IS NULL OR c.observed_at <= $as_of) "
            "AND ($historical OR NOT EXISTS { MATCH (newer:GraphCapture) "
            "WHERE newer.complete=true AND newer.resource_key=c.resource_key "
            "AND (newer.observed_at>c.observed_at "
            "OR (newer.observed_at=c.observed_at AND newer.id<c.id)) "
            "AND ($as_of IS NULL OR newer.observed_at <= $as_of) }) "
            "AND (c.host=$host OR c.host ENDS WITH '.'+$host OR EXISTS { "
            "MATCH (document:GraphCapture) WHERE (document.id IN c.context_capture_ids OR EXISTS { "
            "MATCH (membership:GraphDocumentContext {owner_id:c.active_publication_id,capture_id:document.id}) }) "
            "AND (document.host=$host OR document.host ENDS WITH '.'+$host) "
            "AND ($prefix IS NULL OR document.url STARTS WITH $prefix) "
            "AND document.complete=true AND ($as_of IS NULL OR document.observed_at <= $as_of) "
            "AND ($historical OR NOT EXISTS { MATCH (newer:GraphCapture) "
            "WHERE newer.complete=true AND newer.resource_key=document.resource_key "
            "AND (newer.observed_at>document.observed_at "
            "OR (newer.observed_at=document.observed_at AND newer.id<document.id)) "
            "AND ($as_of IS NULL OR newer.observed_at <= $as_of) }) }) "
            "WITH c,c.active_publication_id AS selected_generation "
            "MATCH (a:GraphEntity)-[r:RELATES]->(b:GraphEntity) WHERE r.capture_id=c.id "
            f"AND {visible_relationship('r', 'c')} AND {visible_node('a', 'c')} AND {visible_node('b', 'c')} "
            "AND (r.context_capture_id IS NULL OR EXISTS { MATCH (context:GraphCapture {id:r.context_capture_id}) "
            "WHERE context.complete=true AND ($as_of IS NULL OR context.observed_at <= $as_of) "
            "AND ($historical OR NOT EXISTS { MATCH (next:GraphCapture) WHERE next.complete=true "
            "AND next.resource_key=context.resource_key "
            "AND (next.observed_at>context.observed_at "
            "OR (next.observed_at=context.observed_at AND next.id<context.id)) "
            "AND ($as_of IS NULL OR next.observed_at <= $as_of) }) }) "
            "AND all(n IN [a,b] WHERE n.capture_id IS NULL OR n.capture_id=c.id "
            "OR EXISTS { MATCH (owner:GraphCapture {id:n.capture_id}) "
            "WHERE owner.complete=true AND ($as_of IS NULL OR owner.observed_at <= $as_of) "
            "AND ($historical OR NOT EXISTS { MATCH (later:GraphCapture) "
            "WHERE later.complete=true AND later.resource_key=owner.resource_key "
            "AND (later.observed_at>owner.observed_at OR (later.observed_at=owner.observed_at AND later.id<owner.id)) "
            "AND ($as_of IS NULL OR later.observed_at <= $as_of) }) }) "
            f"{element_filter}"
            "RETURN r.id AS membership_id,c.id AS capture_id, "
            "CASE WHEN a._owner_capture_id=c.id THEN a._publication_id "
            "WHEN b._owner_capture_id=c.id THEN b._publication_id ELSE null END AS publication_id "
            "ORDER BY r.id LIMIT 20001",
            context_url=context_url,
            role=role,
            as_of=as_of,
            historical=historical,
            prefix=scope if "://" in scope else None,
            host=urlsplit(scope if "://" in scope else "https://" + scope).hostname,
        )
        nodes = {}
        relationships = []
        gaps = set()
        analyses = {}
        truncated = len(references) > 20000
        reasons = ["relationship_limit"] if truncated else []
        rows, hydration_gaps, hydration_reasons = self.hydrate(references[:20000])
        gaps.update(hydration_gaps)
        reasons.extend(hydration_reasons)
        truncated |= bool(hydration_reasons)
        for row in rows:
            source, target = public_properties(row["source"]), public_properties(row["target"])
            source = {**source, "context_urls": row.get("source_context_urls") or source.get("context_urls", [])}
            target = {**target, "context_urls": row.get("target_context_urls") or target.get("context_urls", [])}
            if not contains(source["url"]) and not any(contains(url) for url in source.get("context_urls", [])):
                continue
            if len(nodes) + sum(item["id"] not in nodes for item in (source, target)) > MAX_ENTITIES:
                truncated = True
                reasons.append("entity_limit")
                break
            for node in (source, target):
                previous_contexts = nodes.get(node["id"], {}).get("context_urls", [])
                nodes[node["id"]] = {
                    **node,
                    "context_urls": list(dict.fromkeys([*previous_contexts, *node["context_urls"]])),
                }
            relationships.append({**public_properties(row["relationship"]), "observed_at": row["observed_at"]})
            gaps.update(row["gaps"] or [])
            for analysis in json.loads(row.get("analysis_details") or "[]"):
                analyses[json.dumps(analysis, sort_keys=True)] = analysis
        return (
            nodes,
            relationships,
            {
                "analysis_gaps": sorted(gaps),
                "analysis_summaries": list(analyses.values()),
                "retrieval_truncated": truncated,
                "truncation_reasons": reasons,
                "instructions": "Possible relationships from captured artifacts; absence is not proof. "
                "No browser-session identity or backend execution is established. " + INTERPRETATION,
            },
        )

    def hydrate(self, references, *, state=None):
        """Hydrate complete membership windows within the immutable-generation grace period."""
        state = {} if state is None else state
        started = state.setdefault("started", time.monotonic())
        deadline = min(started + 120, self.budget.deadline)
        entities, metadata, contexts = (state.setdefault(key, {}) for key in ("entities", "metadata", "contexts"))
        attempted_nodes, attempted_owners, attempted_contexts = (
            state.setdefault(key, set()) for key in ("attempted_nodes", "attempted_owners", "attempted_contexts")
        )
        timed_out, memory_blocked, unavailable = (
            state.get(key, False) for key in ("timed_out", "memory_blocked", "unavailable")
        )
        subdivisions = state.get("subdivisions", 0)
        result = []

        def fetch(batch, statement, parameter, stage):
            nonlocal timed_out, memory_blocked, unavailable, subdivisions
            read_started = time.monotonic()
            remaining = deadline - read_started
            if remaining < 0.001:
                timed_out = True
                return []
            try:
                rows = self.read(statement, timeout=min(graph_timeouts().read, remaining), **{parameter: list(batch)})
                if len(rows) < len(batch):
                    unavailable = True
                logger.debug(
                    "Graph hydration stage=%s batch=%s returned=%s seconds=%.3f remaining_seconds=%.3f",
                    stage,
                    len(batch),
                    len(rows),
                    time.monotonic() - read_started,
                    max(0, deadline - time.monotonic()),
                )
                return rows
            except TimeoutError:
                timed_out = True
                return []
            except Neo4jError as error:
                code = error.code or ""
                if "TransactionTimedOut" in code and time.monotonic() >= deadline:
                    timed_out = True
                    return []
                if not code.endswith("MemoryPoolOutOfMemoryError") and "TransactionTimedOut" not in code:
                    raise
                logger.warning(
                    "Graph hydration resource limit stage=%s batch=%s seconds=%.3f remaining_seconds=%.3f",
                    stage,
                    len(batch),
                    time.monotonic() - read_started,
                    max(0, deadline - time.monotonic()),
                )
                if len(batch) == 1:
                    if "TransactionTimedOut" in code:
                        timed_out = True
                    else:
                        memory_blocked = True
                    return []
                subdivisions += 1
                middle = len(batch) // 2
                return fetch(batch[:middle], statement, parameter, stage) + fetch(
                    batch[middle:], statement, parameter, stage
                )

        def read_batches(values, statement, parameter, stage):
            for batch in batched(values, 500):
                yield from fetch(batch, statement, parameter, stage)
                if timed_out:
                    break

        for window in batched(references, 500):
            if time.monotonic() >= deadline:
                timed_out = True
                break
            edges = {
                row["relationship"]["id"]: row
                for row in read_batches(
                    [reference["membership_id"] for reference in window],
                    "MATCH (a:GraphEntity)-[r:RELATES]->(b:GraphEntity) USING INDEX SEEK r:RELATES(id) "
                    "WHERE r.id IN $ids RETURN a.id AS source_id,b.id AS target_id,properties(r) AS relationship",
                    "ids",
                    "relationships",
                )
            }
            owners = {
                (
                    reference["capture_id"],
                    reference["publication_id"] or identity("legacy-publication", reference["capture_id"]),
                )
                for reference in window
            } - attempted_owners
            for row in read_batches(
                [{"capture": capture, "publication": publication} for capture, publication in sorted(owners)],
                "UNWIND $owners AS owner OPTIONAL MATCH (p:GraphPublication {id:owner.publication}) "
                "OPTIONAL MATCH (c:GraphCapture {id:owner.capture}) "
                "WITH owner,p,c WHERE p IS NOT NULL OR c IS NOT NULL "
                "RETURN owner.capture AS capture_id,owner.publication AS publication_id, "
                "coalesce(p.gaps,c.gaps,[]) AS gaps,coalesce(p.observed_at,c.observed_at) AS observed_at, "
                "coalesce(p.analysis_details,c.analysis_details) AS analysis_details",
                "owners",
                "metadata",
            ):
                metadata[(row["capture_id"], row["publication_id"])] = row
            attempted_owners.update(owners)
            node_ids = {row[key] for row in edges.values() for key in ("source_id", "target_id")} - attempted_nodes
            for row in read_batches(
                sorted(node_ids),
                "MATCH (n:GraphEntity) USING INDEX SEEK n:GraphEntity(id) "
                "WHERE n.id IN $ids RETURN properties(n) AS node",
                "ids",
                "entities",
            ):
                entities[row["node"]["id"]] = row["node"]
            attempted_nodes.update(node_ids)
            context_ids = {
                entities[key]["context_owner_id"] for key in entities if entities[key].get("context_owner_id")
            } - attempted_contexts
            for row in read_batches(
                [{"id": value, "legacy": identity("legacy-publication", value)} for value in sorted(context_ids)],
                "UNWIND $contexts AS owner OPTIONAL MATCH (p:GraphPublication {id:owner.id}) "
                "OPTIONAL MATCH (archive:GraphPublication {id:owner.legacy}) "
                "OPTIONAL MATCH (c:GraphCapture {id:owner.id}) "
                "WITH owner,p,archive,c WHERE p IS NOT NULL OR archive IS NOT NULL OR c IS NOT NULL "
                "RETURN owner.id AS id, "
                "CASE WHEN EXISTS { MATCH (lookup:GraphContext {owner_id:p.id}) } "
                "THEN COLLECT { MATCH (context:GraphContext {owner_id:p.id}) RETURN context.url } "
                "ELSE coalesce(p.context_urls,archive.context_urls,c.context_urls,[]) END AS context_urls",
                "contexts",
                "contexts",
            ):
                contexts[row["id"]] = row["context_urls"]
            attempted_contexts.update(context_ids)
            for reference in window:
                row = edges.get(reference["membership_id"])
                owner = metadata.get(
                    (
                        reference["capture_id"],
                        reference["publication_id"] or identity("legacy-publication", reference["capture_id"]),
                    )
                )
                if row is None or owner is None or row["source_id"] not in entities or row["target_id"] not in entities:
                    continue
                source, target = entities[row["source_id"]], entities[row["target_id"]]
                if any(
                    node.get("context_owner_id") and node["context_owner_id"] not in contexts
                    for node in (source, target)
                ):
                    continue
                result.append(
                    {
                        **row,
                        "source": source,
                        "target": target,
                        "gaps": owner["gaps"],
                        "analysis_details": owner.get("analysis_details"),
                        "observed_at": owner["observed_at"],
                        "source_context_urls": contexts.get(source.get("context_owner_id")),
                        "target_context_urls": contexts.get(target.get("context_owner_id")),
                    }
                )
        gaps, reasons = [], []
        if len(result) < len(references):
            for condition, reason, message in (
                (timed_out, "time_limit", "Snapshot hydration budget reached"),
                (memory_blocked, "memory_limit", "Snapshot record exceeds the Neo4j transaction memory budget"),
                (
                    unavailable,
                    "generation_unavailable",
                    "Selected generation became unavailable; repeat the graph query",
                ),
            ):
                if condition:
                    reasons.append(reason)
                    gaps.append(message)
        log = logger.warning if reasons else logger.info
        log(
            "Graph hydration complete selected=%s completed=%s seconds=%.3f subdivisions=%s reasons=%s",
            len(references),
            len(result),
            time.monotonic() - started,
            subdivisions,
            reasons,
        )
        state.update(
            timed_out=timed_out, memory_blocked=memory_blocked, unavailable=unavailable, subdivisions=subdivisions
        )
        return result, gaps, reasons

    def endpoints(self, scope, *, url=None, method=None, historical=False, as_of=None, detail="inventory"):
        url, method = map(optional_filter, (url, method))
        if detail == "inventory":
            if self.artifacts is not None:
                from shyhurricane.graph.manifest_query import manifest_query

                return manifest_query(self.artifacts, scope, kind="resource", url=url, method=method,
                                      historical=historical, as_of=as_of)
            from shyhurricane.graph.inventory import endpoint_inventory

            return endpoint_inventory(self, scope, url=url, method=method, historical=historical, as_of=as_of)
        if detail != "summary":
            raise ValueError("detail must be inventory or summary")
        from shyhurricane.graph.traversal import ASSOCIATIONS, TraversalSnapshot

        reader = TraversalSnapshot(self, scope, historical=historical, as_of=as_of)
        if reader.indexed():
            reader.candidates(scope, kinds=["resource"],
                              url=web_url(url, fragment=True) if url else None, method=method)
            selected = list(reader.nodes)
            if len(selected) > MAX_RESULTS:
                reader.limit("result_limit")
                selected = sorted(selected, key=lambda key: (
                    reader.nodes[key]["url"], reader.nodes[key].get("method", ""), key
                ))[:MAX_RESULTS]
            relationships = reader.load(selected, "both", ASSOCIATIONS | {"HOSTED_AT"})
            for batch in batched([reader.nodes[key]["url"] for key in selected], 500):
                reader._indexed_context(batch)
            discovery = ResourceDiscovery(reader.nodes, list(relationships.values()))
            scripts = sorted({script for key in selected for script in discovery.associated(key)[2]})
            relationships.update(reader.load(scripts, "both", ASSOCIATIONS))
            reader.describe()
            nodes, metadata = reader.nodes, reader.metadata
            relationships = list(relationships.values())
            allowed = set(selected)
        else:
            nodes, relationships, metadata = self.snapshot(scope, historical=historical, as_of=as_of)
            allowed = None
        discovery = ResourceDiscovery(nodes, relationships)
        contains = scope_predicate(scope)
        matches = [
            node
            for node in discovery.resources.values()
            if (allowed is None or node["id"] in allowed)
            and (contains(node["url"]) or any(contains(value) for value in node.get("context_urls", [])))
            and (url is None or node["url"] == web_url(url, fragment=True))
            and (method is None or node.get("method", "").upper() == method.upper())
        ]
        matches.sort(key=lambda item: (item["url"], item.get("method", ""), item["id"]))
        if len(matches) > MAX_RESULTS:
            metadata["retrieval_truncated"] = True
            metadata["truncation_reasons"].append("result_limit")
        metadata["instructions"] += (
            " Overview counts describe the selected bounded snapshot; examples are limited to three per section. "
            "Referenced means no capture is present in this snapshot. Script contexts are associations, not paths."
        )
        return {**metadata, "results": [discovery.overview(node["id"], scope) for node in matches[:MAX_RESULTS]]}

    def elements(
        self,
        scope,
        *,
        kinds=None,
        role=None,
        url=None,
        context_url=None,
        detail="compact",
        historical=False,
        as_of=None,
    ):
        url, context_url = map(optional_filter, (url, context_url))
        present({}, detail)
        normalized_context = web_url(context_url, fragment=True) if context_url is not None else None
        if self.artifacts is not None:
            from shyhurricane.graph.manifest_query import manifest_query

            result = manifest_query(self.artifacts, scope, kinds=kinds, role=role, url=url,
                                    context_url=normalized_context, historical=historical, as_of=as_of,
                                    exclude_kinds=() if kinds else ("relationship", "reference", "candidate_source"))
            try:
                result["omitted_regions"] = self.omitted_regions(scope)
            except TimeoutError:
                result.setdefault("analysis_gaps", []).append(
                    "Deferred analysis-unit details exceeded the query budget"
                )
                result["retrieval_truncated"] = True
                if "time_limit" not in result["truncation_reasons"]:
                    result["truncation_reasons"].append("time_limit")
            return result
        from shyhurricane.graph.traversal import TraversalSnapshot

        reader = TraversalSnapshot(self, scope, historical=historical, as_of=as_of)
        if reader.indexed():
            reader.candidates(scope, kinds=kinds, role=role, context_url=normalized_context,
                              url=web_url(url, fragment=True) if url else None)
            if not reader.metadata["retrieval_truncated"]:
                reader.boundaries(scope, kinds=kinds, role=role, context_url=normalized_context,
                                  url=web_url(url, fragment=True) if url else None)
            reader.describe()
            nodes, metadata = reader.nodes, reader.metadata
        else:
            nodes, _, metadata = self.snapshot(
                scope, historical=historical, as_of=as_of, context_url=normalized_context, role=role
            )
        matches = [
            node
            for node in nodes.values()
            if (not kinds or node["kind"] in kinds)
            and (not role or node.get("role") == role)
            and (not url or node["url"] == web_url(url, fragment=True))
            and (context_url is None or in_context(node, normalized_context))
        ]
        matches.sort(
            key=lambda item: (
                {"resource": 0, "field": 1, "element": 1}.get(item["kind"], 2) if not kinds else 0,
                item.get("name", ""),
                item["id"],
            )
        )
        metadata["retrieval_truncated"] |= len(matches) > MAX_RESULTS
        if len(matches) > MAX_RESULTS:
            metadata["truncation_reasons"].append("result_limit")
        return {**metadata, "results": [present(node, detail) for node in matches[:MAX_RESULTS]]}

    def paths(
        self,
        scope,
        start,
        *,
        end=None,
        direction="forward",
        mode="relationships",
        detail="compact",
        kinds=None,
        max_depth=8,
        historical=False,
        as_of=None,
        _resume=None,
        _expires=None,
    ):
        present({}, detail)
        if direction not in {"forward", "backward"}:
            raise ValueError("direction must be forward or backward")
        if type(max_depth) is not int or not 1 <= max_depth <= 32:
            raise ValueError("max_depth must be between 1 and 32")
        from shyhurricane.graph.traversal import TraversalSnapshot

        reader = TraversalSnapshot(self, scope, historical=historical, as_of=as_of, resume=_resume)
        if _resume is not None:
            reader.parameters["revision"] = _resume["revision"]
            reader.nodes.update(_resume["nodes"])
            reader.memberships.update(_resume.get("memberships", {}))
            reader.selected_memberships.update(_resume.get("selected_memberships", []))
            reader.association_edges.update(_resume.get("association_edges", {}))
            reader.associated.update(_resume.get("associated", []))
            for field in ("analysis_gaps", "analysis_summaries"):
                reader.metadata[field] = _resume.get(field, [])
            for key, values in _resume["storage"].items():
                reader.storage[key].update(values)
            reader.resolved.update(_resume.get("resolved", []))
        nodes, metadata = reader.nodes, reader.metadata
        start_role = ("sink" if direction == "backward" else "source") if mode == "flow" else None
        end_role = ("source" if direction == "backward" else "sink") if mode == "flow" else None
        seeds_complete = _resume is not None and _resume.get("seeds_complete", True)
        starts = _resume["starts"] if seeds_complete else reader.select(start, start_role)
        targets = (set(_resume["targets"]) if seeds_complete
                   else set(reader.select(end, end_role, boundary=True)) if end else set())
        seeds_complete = not reader.stopped
        if mode == "flow":
            metadata.update(
                resolved_start_ids=starts[:20],
                resolved_end_ids=sorted(targets)[:20],
                resolved_start_count=len(starts),
                resolved_end_count=len(targets),
                seed_ids_limited=len(starts) > 20 or len(targets) > 20,
            )
            metadata["instructions"] += (
                " Resource entry points select associated source/sink candidates; resolved IDs identify the seeds. "
                "Seed ID examples are limited to 20 per side; counts cover all seeds. "
                "Seed selection does not create flow edges. Paths contain only existing flow relationships."
            )
        allowed = FLOW_KINDS if mode == "flow" else JOURNEY_KINDS if mode == "journey" else None
        if kinds:
            allowed = set(kinds) & allowed if allowed is not None else set(kinds)
        reverse = direction == "backward"
        adjacent = reader.adjacent
        pending = deque(_resume["pending"] if _resume and _resume.get("seeds_complete", True)
                        else (([key], [], None) for key in starts))
        reached = {tuple(item) for item in _resume["reached"]} if _resume else {(key, key, None) for key in starts}
        result = []
        expansions = 0
        scope_boundary = False
        cpu_started = time.thread_time()
        contains = scope_predicate(scope)
        while (
            pending
            and len(result) < MAX_RESULTS
            and expansions < MAX_ENTITIES
            and self.budget.remaining() > 0
            and not reader.stopped
            and time.thread_time() - cpu_started < 10
        ):
            # Prefetch only this breadth-first layer; repeated path states share adjacency.
            depth = len(pending[0][1])
            frontier = list(
                dict.fromkeys(
                    path[-1]
                    for path, steps, _ in pending
                    if len(steps) == depth and not (end and steps and path[-1] in targets)
                )
            )[:500]
            reader.expand(frontier, direction, allowed, probe=depth >= max_depth, depth=depth)
            if (metadata["retrieval_truncated"] and pending[0][0][-1] not in adjacent
                    and pending[0][0][-1] not in reader.probes):
                metadata["analysis_gaps"].append("Frontier loading incomplete; unfinished work retained")
                break
            visited, steps, context = pending.popleft()
            current = visited[-1]
            if steps and (
                (end and current in targets)
                or (not end and (mode != "flow" or nodes[current].get("role") == ("source" if reverse else "sink")))
            ):
                result.append(
                    {
                        "nodes": [present(nodes[key], detail) for key in visited],
                        "steps": [present(step, detail, step=True) for step in steps],
                        "possible_path": True,
                    }
                )
                if end:
                    continue
            inside = contains(nodes[current]["url"]) or any(
                contains(url) for url in nodes[current].get("context_urls", [])
            )
            if len(steps) >= max_depth or not inside:
                scope_boundary |= not inside and bool(adjacent.get(current) or reader.probes.get(current))
                if (adjacent.get(current) or reader.probes.get(current)) and len(steps) >= max_depth:
                    metadata["retrieval_truncated"] = True
                    metadata["truncation_reasons"].append("depth_limit")
                continue
            for item in adjacent.get(current, []):
                expansions += 1
                target = item["source"] if reverse else item["target"]
                boundary_context = None if nodes[current].get("persistent_storage") else context
                next_context = item.get("context_capture_id") or boundary_context
                if (mode == "flow" and boundary_context
                        and item.get("context_capture_id") not in {None, boundary_context}):
                    continue
                signature = (visited[0], target, next_context)
                if (target not in visited
                        and (mode not in {"flow", "journey"} and end is None or signature not in reached)):
                    reached.add(signature)
                    pending.append(([*visited, target], [*steps, item], next_context))
        # Destinations already hydrated by completed frontiers remain valid even if
        # the next read or metadata operation exhausts the request budget.
        if reader.stopped or self.budget.remaining() <= 0:
            unfinished = deque()
            for visited, steps, context in pending:
                terminal = bool(steps) and (
                    (end and visited[-1] in targets)
                    or (not end and mode == "flow" and nodes[visited[-1]].get("role") == end_role)
                )
                if terminal and len(result) < MAX_RESULTS:
                    result.append({"nodes": [present(nodes[key], detail) for key in visited],
                                   "steps": [present(step, detail, step=True) for step in steps],
                                   "possible_path": True})
                else:
                    unfinished.append((visited, steps, context))
            pending = unfinished
        metadata["retrieval_truncated"] |= bool(pending)
        if pending:
            if len(result) >= MAX_RESULTS:
                metadata["truncation_reasons"].append("result_limit")
            if expansions >= MAX_ENTITIES:
                metadata["truncation_reasons"].append("expansion_limit")
            if self.budget.remaining() <= 0 or time.thread_time() - cpu_started >= 10:
                metadata["truncation_reasons"].append("time_limit")
        metadata["truncation_reasons"] = sorted(set(metadata["truncation_reasons"]))
        if not starts:
            metadata["analysis_gaps"].append(
                "Start element is absent or has no associated flow seeds in the selected captured evidence"
            )
        if end and not targets:
            metadata["analysis_gaps"].append(
                "End element is absent or has no associated flow seeds in the selected captured evidence"
            )
        if starts and (not end or targets) and not result:
            metadata["analysis_gaps"].append(
                "Selected seeds have no discovered path within the reported traversal limits"
            )
            if mode == "flow":
                destination_role = "source" if reverse else "sink"
                if not any(node.get("role") == destination_role for node in nodes.values()):
                    metadata["analysis_gaps"].append(
                        f"No {destination_role} operations were reached in the explored captured graph"
                    )
                if not metadata["retrieval_truncated"] and not any(adjacent.get(seed) for seed in starts):
                    metadata["analysis_gaps"].append(
                        "Selected seeds have no incoming flow edges"
                        if reverse
                        else "Selected seeds have no outgoing flow edges"
                    )
                if scope_boundary:
                    metadata["analysis_gaps"].append(
                        "Traversal stopped at the requested scope boundary; "
                        "related captured resources may require a broader scope"
                    )
                metadata["analysis_gaps"].append(
                    "No source-to-sink path was discovered in the selected captured graph; "
                    + (
                        "traversal was truncated"
                        if metadata["retrieval_truncated"]
                        else "reported traversal limits were not reached; unresolved analysis may leave missing links"
                    )
                )
        if metadata["retrieval_truncated"]:
            metadata["analysis_gaps"] = [
                gap.replace("is absent or has no associated", "could not be fully resolved or has no selected")
                for gap in metadata["analysis_gaps"]
            ]
        reader.finish(len(result))
        metadata_started = time.monotonic()
        if self.artifacts is not None:
            try:
                metadata["coverage"] = self.artifacts.manifest.coverage(scope=scope, historical=historical, as_of=as_of)
                metadata["omitted_regions"] = self.omitted_regions(scope)
            except TimeoutError:
                metadata.setdefault("coverage", {"discovery": "unknown", "flow": "unknown"})
                metadata.setdefault("omitted_regions", [])
                reader.limit("time_limit", "Graph metadata exceeded the query budget")
            logger.debug("Graph request=%s stage=metadata seconds=%.3f",
                         self.budget.request_id, time.monotonic() - metadata_started)
            if (pending or not seeds_complete) and "generation_unavailable" not in metadata["truncation_reasons"]:
                from shyhurricane.graph.cursors import QueryCursors

                checkpoint_started = time.monotonic()
                cursors = self.cursor_store
                try:
                    with self.budget.checkpoint():
                        cursors = cursors or QueryCursors(self.artifacts.root, self.budget)
                    with self.budget.checkpoint(), cursors.transaction():
                        token = cursors.save({
                            "operation": "paths",
                            "parameters": {
                                "scope": scope, "start": start, "end": end, "direction": direction, "mode": mode,
                                "detail": detail, "kinds": kinds, "max_depth": max_depth,
                                "historical": historical, "as_of": as_of,
                            },
                            "search": {
                                "revision": reader.parameters["revision"], "nodes": nodes,
                                "storage": {key: sorted(values) for key, values in reader.storage.items()},
                                "resolved": sorted(reader.resolved), "reads": reader.read_cache,
                                "seeds_complete": seeds_complete, "memberships": reader.memberships,
                                "selected_memberships": sorted(reader.selected_memberships),
                                "association_edges": reader.association_edges,
                                "associated": sorted(reader.associated),
                                "analysis_gaps": metadata["analysis_gaps"],
                                "analysis_summaries": metadata["analysis_summaries"],
                                "starts": starts, "targets": sorted(targets), "pending": list(pending),
                                "reached": sorted(reached, key=str),
                            },
                        }, expires=_expires)
                        self.pin_query(token, reader.parameters["revision"], expires=_expires)
                        metadata["continuation_token"] = token
                except (TimeoutError, OSError, ValueError, Neo4jError, sqlite3.Error) as error:
                    reader.limit(
                        "time_limit", f"Continuation checkpoint failed; restart required: {type(error).__name__}"
                    )
                    metadata.pop("continuation_token", None)
                finally:
                    if self.cursor_store is None and cursors is not None:
                        cursors.close()
                    logger.debug("Graph request=%s stage=checkpoint seconds=%.3f",
                                 self.budget.request_id, time.monotonic() - checkpoint_started)
        return {**metadata, "results": result}

    def pin_query(self, token, revision, *, expires=None):
        from shyhurricane.graph.cursors import TTL_SECONDS

        rows = self.budget.read(
            self.store,
            "MERGE (p:GraphReadPin {id:$id}) SET p.revision=$revision,p.expires=$expires RETURN p.id AS id",
            timeout=graph_timeouts().control, access_mode="WRITE",
            id=identity(token), revision=revision,
            expires=expires if expires is not None else time.time() + TTL_SECONDS,
        )

        if not any(row["id"] == identity(token) for row in rows):
            raise TimeoutError("Graph revision pin could not be confirmed")

    def omitted_regions(self, scope):
        if self.artifacts is None:
            return []
        records, _ = self.artifacts.manifest.page(scope, kind="analysis_unit", limit=1000)
        return [{"analysis_unit_id": row["analysis_unit_id"], "capture_id": row["capture_id"],
                 "status": row["materialization"], "flow": row["flow"], "error": row["error"],
                 "source_path": row["source_path"]}
                for row in records if row["expandable"] and
                (row["flow"] != "complete" or row["materialization"] != "complete")]

    def continue_query(self, token, limit=1000):
        from shyhurricane.graph.cursors import QueryCursors
        from shyhurricane.graph.manifest_query import manifest_query

        if self.artifacts is None:
            raise ValueError("Graph analysis continuations are unavailable")
        cursors = QueryCursors(self.artifacts.root, self.budget)
        result = None
        try:
            with cursors.locked(token):
                self.cursor_store = cursors
                cached = cursors.response(token)
                if cached is not None:
                    return cached
                state, expires = cursors.load(token)
                with cursors.transaction():
                    if state["operation"] == "manifest":
                        result = manifest_query(
                            self.artifacts, **{key: value for key, value in state.items() if key != "operation"},
                            limit=limit, expires=expires, cursor_store=cursors,
                        )
                    elif state["operation"] == "paths":
                        result = self.paths(**state["parameters"], _resume=state["search"], _expires=expires)
                    else:
                        raise ValueError("Unsupported graph continuation")
                    with self.budget.checkpoint():
                        cursors.complete(token, result)
                    return result
        except (TimeoutError, OSError, ValueError, sqlite3.Error):
            if result is None:
                raise
            result.pop("continuation_token", None)
            result["retrieval_truncated"] = True
            result.setdefault("analysis_gaps", []).append("Continuation checkpoint failed; restart required")
            reasons = result.setdefault("truncation_reasons", [])
            if "time_limit" not in reasons:
                reasons.append("time_limit")
            return result
        finally:
            self.cursor_store = None
            cursors.close()

    def expansion(self, scope, capture_id, unit_id):
        from shyhurricane.graph.manifest_query import expand_analysis

        return expand_analysis(self.artifacts, None, scope, capture_id, unit_id)

    def evidence(self, evidence_id):
        rows = self.read(
            "MATCH (e:GraphEvidence {id:$id}) "
            "WHERE (e._publication_id IS NULL AND EXISTS { "
            "MATCH (c:GraphCapture {id:e.capture_id}) "
            "WHERE c.complete=true }) OR EXISTS { MATCH (p:GraphPublication {id:e._publication_id}) "
            "WHERE p.published_at IS NOT NULL } "
            "OPTIONAL MATCH (context:GraphCapture {id:e.context_owner_id}) "
            "OPTIONAL MATCH (publication:GraphPublication {id:e.context_owner_id}) "
            "OPTIONAL MATCH (analysis:GraphPublication {id:e._publication_id}) "
            "OPTIONAL MATCH (capture:GraphCapture {id:e.capture_id}) "
            "RETURN properties(e) AS evidence, "
            "CASE WHEN EXISTS { MATCH (lookup:GraphContext {owner_id:publication.id}) } THEN "
            "COLLECT { MATCH (lookup:GraphContext {owner_id:publication.id}) RETURN lookup.url } "
            "ELSE coalesce(publication.context_urls,context.context_urls) END AS context_urls, "
            "coalesce(analysis.analysis_details,capture.analysis_details) AS analysis_details",
            id=evidence_id,
        )
        if not rows:
            return None
        evidence = {
            key: value
            for key, value in rows[0]["evidence"].items()
            if not key.startswith("_") and key != "context_owner_id"
        }
        evidence = {**evidence, "context_urls": rows[0].get("context_urls") or evidence.get("context_urls", [])}
        evidence["analysis_summaries"] = json.loads(rows[0].get("analysis_details") or "[]")
        return evidence
