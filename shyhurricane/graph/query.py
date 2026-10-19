"""Bounded, deterministic semantic queries; no user-supplied Cypher."""

import json
import logging
import time
from collections import deque
from itertools import batched
from urllib.parse import urlsplit

from neo4j.exceptions import Neo4jError

from shyhurricane.graph.config import graph_timeouts
from shyhurricane.graph.discovery import INTERPRETATION, ResourceDiscovery, in_context, present
from shyhurricane.graph.model import FLOW_KINDS, JOURNEY_KINDS, identity, web_url
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
    def __init__(self, store):
        self.store = store

    def snapshot(self, scope: str, *, historical=False, as_of: float | None = None, context_url=None, role=None):
        contains = scope_predicate(scope)
        # Filter membership before the bounded working set is selected. Context archives have
        # no digest; ordinary publications always have one, even after retirement.
        element_filter = ""
        if context_url is not None or role is not None:
            element_filter = (
                "AND any(n IN [a,b] WHERE ($role IS NULL OR n.role=$role) "
                "AND ($context_url IS NULL OR n.url=$context_url OR "
                "(n.context_owner_id IS NULL AND $context_url IN coalesce(n.context_urls,[])) OR EXISTS { "
                "OPTIONAL MATCH (p:GraphPublication {id:n.context_owner_id}) "
                "OPTIONAL MATCH (archive:GraphPublication {capture_id:n.context_owner_id}) "
                "WHERE archive.digest IS NULL "
                "OPTIONAL MATCH (owner:GraphCapture {id:n.context_owner_id}) "
                "WITH coalesce(p.context_urls,archive.context_urls,owner.context_urls,[]) AS urls "
                "WHERE $context_url IN urls RETURN 1 AS matched })) "
            )
        # Fetch one bounded immutable working set and save result pages after traversal.
        references = self.store.read(
            "MATCH (c:GraphCapture) WHERE c.complete=true AND ($as_of IS NULL OR c.observed_at <= $as_of) "
            "AND ($historical OR NOT EXISTS { MATCH (newer:GraphCapture) "
            "WHERE newer.complete=true AND newer.resource_key=c.resource_key AND newer.observed_at>c.observed_at "
            "AND ($as_of IS NULL OR newer.observed_at <= $as_of) }) "
            "AND (c.host=$host OR c.host ENDS WITH '.'+$host OR EXISTS { "
            "MATCH (document:GraphCapture) WHERE document.id IN c.context_capture_ids "
            "AND (document.host=$host OR document.host ENDS WITH '.'+$host) "
            "AND ($prefix IS NULL OR document.url STARTS WITH $prefix) "
            "AND document.complete=true AND ($as_of IS NULL OR document.observed_at <= $as_of) "
            "AND ($historical OR NOT EXISTS { MATCH (newer:GraphCapture) "
            "WHERE newer.complete=true AND newer.resource_key=document.resource_key "
            "AND newer.observed_at>document.observed_at AND ($as_of IS NULL OR newer.observed_at <= $as_of) }) }) "
            "WITH c,c.active_publication_id AS selected_generation "
            "MATCH (a:GraphEntity)-[r:RELATES]->(b:GraphEntity) WHERE r.capture_id=c.id "
            f"AND {visible_relationship('r', 'c')} AND {visible_node('a', 'c')} AND {visible_node('b', 'c')} "
            "AND (r.context_capture_id IS NULL OR EXISTS { MATCH (context:GraphCapture {id:r.context_capture_id}) "
            "WHERE context.complete=true AND ($as_of IS NULL OR context.observed_at <= $as_of) "
            "AND ($historical OR NOT EXISTS { MATCH (next:GraphCapture) WHERE next.complete=true "
            "AND next.resource_key=context.resource_key AND next.observed_at>context.observed_at "
            "AND ($as_of IS NULL OR next.observed_at <= $as_of) }) }) "
            "AND all(n IN [a,b] WHERE n.capture_id IS NULL OR n.capture_id=c.id "
            "OR EXISTS { MATCH (owner:GraphCapture {id:n.capture_id}) "
            "WHERE owner.complete=true AND ($as_of IS NULL OR owner.observed_at <= $as_of) "
            "AND ($historical OR NOT EXISTS { MATCH (later:GraphCapture) "
            "WHERE later.complete=true AND later.resource_key=owner.resource_key "
            "AND later.observed_at>owner.observed_at "
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
        deadline = started + 120
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
                rows = self.store.read(statement, timeout=min(graph_timeouts().read, remaining), **{parameter: list(batch)})
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
            except Neo4jError as error:
                code = error.code or ""
                if "TransactionTimedOut" in code and time.monotonic() >= deadline:
                    timed_out = True
                    return []
                if not code.endswith("MemoryPoolOutOfMemoryError"):
                    raise
                logger.warning(
                    "Graph hydration memory limit stage=%s batch=%s seconds=%.3f remaining_seconds=%.3f",
                    stage,
                    len(batch),
                    time.monotonic() - read_started,
                    max(0, deadline - time.monotonic()),
                )
                if len(batch) == 1:
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
                "coalesce(p.context_urls,archive.context_urls,c.context_urls,[]) AS context_urls",
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

    def endpoints(self, scope, *, url=None, method=None, historical=False, as_of=None):
        nodes, relationships, metadata = self.snapshot(scope, historical=historical, as_of=as_of)
        discovery = ResourceDiscovery(nodes, relationships)
        contains = scope_predicate(scope)
        matches = [
            node
            for node in discovery.resources.values()
            if (contains(node["url"]) or any(contains(value) for value in node.get("context_urls", [])))
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
        present({}, detail)
        normalized_context = web_url(context_url, fragment=True) if context_url is not None else None
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
    ):
        present({}, detail)
        if direction not in {"forward", "backward"}:
            raise ValueError("direction must be forward or backward")
        if type(max_depth) is not int or not 1 <= max_depth <= 32:
            raise ValueError("max_depth must be between 1 and 32")
        from shyhurricane.graph.traversal import TraversalSnapshot

        reader = TraversalSnapshot(self, scope, historical=historical, as_of=as_of)
        nodes, metadata = reader.nodes, reader.metadata
        start_role = ("sink" if direction == "backward" else "source") if mode == "flow" else None
        end_role = ("source" if direction == "backward" else "sink") if mode == "flow" else None
        starts = reader.select(start, start_role)
        targets = set(reader.select(end, end_role, boundary=True)) if end else set()
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
        pending = deque(([key], []) for key in starts)
        result = []
        expansions = 0
        scope_boundary = False
        cpu_started = time.thread_time()
        contains = scope_predicate(scope)
        while (
            pending
            and len(result) < MAX_RESULTS
            and expansions < MAX_ENTITIES
            and time.thread_time() - cpu_started < 10
        ):
            # Prefetch only this breadth-first layer; repeated path states share adjacency.
            depth = len(pending[0][1])
            frontier = list(
                dict.fromkeys(
                    path[-1]
                    for path, steps in pending
                    if len(steps) == depth and not (end and steps and path[-1] in targets)
                )
            )[:500]
            reader.expand(frontier, direction, allowed, probe=depth >= max_depth, depth=depth)
            visited, steps = pending.popleft()
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
                if target not in visited:
                    pending.append(([*visited, target], [*steps, item]))
                if expansions >= MAX_ENTITIES:
                    break
        metadata["retrieval_truncated"] |= bool(pending)
        if pending:
            if len(result) >= MAX_RESULTS:
                metadata["truncation_reasons"].append("result_limit")
            if expansions >= MAX_ENTITIES:
                metadata["truncation_reasons"].append("expansion_limit")
            if time.thread_time() - cpu_started >= 10:
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
        return {**metadata, "results": result}

    def evidence(self, evidence_id):
        rows = self.store.read(
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
            "coalesce(publication.context_urls,context.context_urls) AS context_urls, "
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
