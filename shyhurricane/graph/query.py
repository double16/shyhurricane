"""Bounded, deterministic semantic queries; no user-supplied Cypher."""

import json
import time
from collections import defaultdict, deque
from itertools import batched
from urllib.parse import urlsplit

from neo4j.exceptions import Neo4jError

from shyhurricane.graph.discovery import INTERPRETATION, ResourceDiscovery, in_context, present
from shyhurricane.graph.model import FLOW_KINDS, JOURNEY_KINDS, identity, web_url
from shyhurricane.graph.visibility import public_properties, visible_node, visible_relationship

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

    def snapshot(self, scope: str, *, historical=False, as_of: float | None = None):
        contains = scope_predicate(scope)
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
            "RETURN r.id AS membership_id,c.id AS capture_id, "
            "CASE WHEN a._owner_capture_id=c.id THEN a._publication_id "
            "WHEN b._owner_capture_id=c.id THEN b._publication_id ELSE null END AS publication_id "
            "ORDER BY r.id LIMIT 20001",
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

    def hydrate(self, references):
        """Load a fixed membership set within the retired-generation cleanup grace period."""
        deadline = time.monotonic() + 120
        edges, entities, metadata, contexts = {}, {}, {}, {}
        timed_out = False
        memory_blocked = False

        def fetch(batch, statement, parameter):
            nonlocal timed_out, memory_blocked
            if time.monotonic() >= deadline:
                timed_out = True
                return []
            try:
                return self.store.read(statement, **{parameter: list(batch)})
            except Neo4jError as error:
                if not (error.code or "").endswith("MemoryPoolOutOfMemoryError"):
                    raise
                if len(batch) == 1:
                    memory_blocked = True
                    return []
                middle = len(batch) // 2
                return fetch(batch[:middle], statement, parameter) + fetch(batch[middle:], statement, parameter)

        def read_batches(values, statement, parameter):
            nonlocal timed_out
            for batch in batched(values, 500):
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                yield from fetch(batch, statement, parameter)

        owners = sorted(
            {
                (
                    reference["capture_id"],
                    reference["publication_id"] or identity("legacy-publication", reference["capture_id"]),
                )
                for reference in references
            }
        )
        for row in read_batches(
            [{"capture": capture, "publication": publication} for capture, publication in owners],
            "UNWIND $owners AS owner OPTIONAL MATCH (p:GraphPublication {id:owner.publication}) "
            "OPTIONAL MATCH (c:GraphCapture {id:owner.capture}) "
            "RETURN owner.capture AS capture_id,owner.publication AS publication_id, "
            "coalesce(p.gaps,c.gaps,[]) AS gaps,coalesce(p.observed_at,c.observed_at) AS observed_at, "
            "coalesce(p.analysis_details,c.analysis_details) AS analysis_details",
            "owners",
        ):
            metadata[(row["capture_id"], row["publication_id"])] = row
        for row in read_batches(
            [reference["membership_id"] for reference in references],
            "UNWIND $ids AS id MATCH (a:GraphEntity)-[r:RELATES {id:id}]->(b:GraphEntity) "
            "RETURN a.id AS source_id,b.id AS target_id,properties(r) AS relationship",
            "ids",
        ):
            edges[row["relationship"]["id"]] = row
        node_ids = sorted({row[key] for row in edges.values() for key in ("source_id", "target_id")})
        for row in read_batches(
            node_ids, "UNWIND $ids AS id MATCH (n:GraphEntity {id:id}) RETURN properties(n) AS node", "ids"
        ):
            entities[row["node"]["id"]] = row["node"]
        context_ids = sorted({node["context_owner_id"] for node in entities.values() if node.get("context_owner_id")})
        for row in read_batches(
            [{"id": value, "legacy": identity("legacy-publication", value)} for value in context_ids],
            "UNWIND $contexts AS owner OPTIONAL MATCH (p:GraphPublication {id:owner.id}) "
            "OPTIONAL MATCH (archive:GraphPublication {id:owner.legacy}) "
            "OPTIONAL MATCH (c:GraphCapture {id:owner.id}) RETURN owner.id AS id, "
            "coalesce(p.context_urls,archive.context_urls,c.context_urls,[]) AS context_urls",
            "contexts",
        ):
            contexts[row["id"]] = row["context_urls"]
        result = []
        for reference in references:
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
                node.get("context_owner_id") and node["context_owner_id"] not in contexts for node in (source, target)
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
        if len(result) < len(references):
            if memory_blocked:
                return result, ["Snapshot record exceeds the Neo4j transaction memory budget"], ["memory_limit"]
            return (
                result,
                [
                    (
                        "Snapshot hydration budget reached"
                        if timed_out
                        else "Selected generation became unavailable; repeat the graph query"
                    )
                ],
                ["time_limit" if timed_out else "generation_unavailable"],
            )
        return result, [], []

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
        nodes, _, metadata = self.snapshot(scope, historical=historical, as_of=as_of)
        matches = [
            node
            for node in nodes.values()
            if (not kinds or node["kind"] in kinds)
            and (not role or node.get("role") == role)
            and (not url or node["url"] == web_url(url, fragment=True))
            and (context_url is None or in_context(node, web_url(context_url, fragment=True)))
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
        nodes, relationships, metadata = self.snapshot(scope, historical=historical, as_of=as_of)

        discovery = ResourceDiscovery(nodes, relationships)
        start_role = ("sink" if direction == "backward" else "source") if mode == "flow" else None
        end_role = ("source" if direction == "backward" else "sink") if mode == "flow" else None
        starts = discovery.select(start, start_role)
        targets = set(discovery.select(end, end_role)) if end else set()
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
        adjacent = defaultdict(list)
        reverse = direction == "backward"
        for item in relationships:
            if allowed is None or item["kind"] in allowed:
                adjacent[item["target"] if reverse else item["source"]].append(item)
        pending = deque(([key], []) for key in starts)
        result = []
        expansions = 0
        deadline = time.monotonic() + 10
        contains = scope_predicate(scope)
        while pending and len(result) < MAX_RESULTS and expansions < MAX_ENTITIES and time.monotonic() < deadline:
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
                if adjacent[current] and len(steps) >= max_depth:
                    metadata["retrieval_truncated"] = True
                    metadata["truncation_reasons"].append("depth_limit")
                continue
            for item in adjacent[current]:
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
            if time.monotonic() >= deadline:
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
        return {**metadata, "results": result}

    def evidence(self, scope, evidence_id):
        contains = scope_predicate(scope)
        rows = self.store.read(
            "MATCH (e:GraphEvidence {id:$id}) "
            "WHERE (e._publication_id IS NULL AND EXISTS { MATCH (c:GraphCapture {id:e.capture_id}) "
            "WHERE c.complete=true }) OR EXISTS { MATCH (p:GraphPublication {id:e._publication_id}) "
            "WHERE p.published_at IS NOT NULL } "
            "OPTIONAL MATCH (context:GraphCapture {id:e.context_owner_id}) "
            "OPTIONAL MATCH (publication:GraphPublication {id:e.context_owner_id}) "
            "OPTIONAL MATCH (analysis:GraphPublication {id:e._publication_id}) "
            "OPTIONAL MATCH (capture:GraphCapture {id:e.capture_id}) "
            "RETURN properties(e) AS evidence, coalesce(publication.context_urls,context.context_urls) AS context_urls, "
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
        if contains(evidence["url"]) or any(contains(url) for url in evidence.get("context_urls", [])):
            return evidence
        return None
