"""Request-scoped, revision-consistent seed resolution and bounded graph frontiers."""

import json
import logging
import time
from collections import defaultdict
from itertools import batched

from neo4j.exceptions import Neo4jError

from shyhurricane.graph.discovery import INTERPRETATION, ResourceDiscovery
from shyhurricane.graph.model import web_url
from shyhurricane.graph.visibility import (
    public_properties,
    publication_at,
    visible_node,
    visible_relationship,
)

logger = logging.getLogger(__name__)
ASSOCIATIONS = {"CONTAINS", "SENDS_FIELD", "SETS_COOKIE", "SUBMITS_TO", "SENDS_COOKIE", "LOADS", "IMPORTS"}


class TraversalSnapshot:
    def __init__(self, service, scope, *, historical=False, as_of=None):
        from shyhurricane.graph.query import scope_predicate

        self.service = service
        self.store = service.store
        self.contains = scope_predicate(scope)
        self.started = time.monotonic()
        self.hydration = {"started": self.started}
        self.parameters = {"historical": historical, "as_of": as_of}
        self.nodes = {}
        self.storage = defaultdict(set)
        self.representatives = {}
        self.resolved = set()
        self.associated = set()
        self.memberships = {}
        self.selected_memberships = set()
        self.association_edges = {}
        self.adjacent = {}
        self.probes = {}
        self.metadata = {
            "analysis_gaps": [],
            "analysis_summaries": [],
            "retrieval_truncated": False,
            "truncation_reasons": [],
            "instructions": "Paths describe bounded captured evidence; absence is not proof. " + INTERPRETATION,
        }
        rows = self.read(
            "/* traversal:revision */ MATCH (n:GraphState {id:'publication_revision'}) "
            "RETURN coalesce(n.value,0) AS revision"
        )
        self.parameters["revision"] = rows[0]["revision"] if rows else 0

    @property
    def stopped(self):
        return "time_limit" in self.metadata["truncation_reasons"]

    def limit(self, reason, message=None):
        self.metadata["retrieval_truncated"] = True
        if reason not in self.metadata["truncation_reasons"]:
            self.metadata["truncation_reasons"].append(reason)
        if message and message not in self.metadata["analysis_gaps"]:
            self.metadata["analysis_gaps"].append(message)

    def read(self, statement, **parameters):
        remaining = self.started + 120 - time.monotonic()
        if remaining < 0.001:
            self.limit("time_limit", "Traversal database budget reached")
            return []
        before = time.monotonic()
        try:
            rows = self.store.read(statement, timeout=min(10, remaining), **self.parameters, **parameters)
            logger.debug(
                "Graph frontier read stage=%s batch=%s rows=%s seconds=%.3f remaining_seconds=%.3f",
                statement.split("*/", 1)[0].removeprefix("/* traversal:"),
                len(parameters.get("ids", [])),
                len(rows),
                time.monotonic() - before,
                max(0, self.started + 120 - time.monotonic()),
            )
            return rows
        except Neo4jError as error:
            if "TransactionTimedOut" in (error.code or "") and time.monotonic() >= self.started + 120:
                self.limit("time_limit", "Traversal database budget reached")
                return []
            if not (error.code or "").endswith("MemoryPoolOutOfMemoryError"):
                raise
            ids = parameters.get("ids", [])
            if len(ids) > 1:
                middle = len(ids) // 2
                rows = self.read(statement, **{**parameters, "ids": ids[:middle]}) + self.read(
                    statement, **{**parameters, "ids": ids[middle:]}
                )
                # Preserve the global keyset page after splitting anchor IDs. Advancing to
                # the largest key of two full pages would skip the tail of the other half.
                if parameters.get("limit") and rows and ("membership_id" in rows[0] or "seed" in rows[0]):
                    by_id = {row.get("membership_id") or row["seed"]["id"]: row for row in rows}
                    return [by_id[key] for key in sorted(by_id)[: parameters["limit"]]]
                return rows
            if parameters.get("limit", 1) > 1:
                return self.read(statement, **{**parameters, "limit": max(1, parameters["limit"] // 2)})
            self.limit("memory_limit", "Traversal record exceeds the Neo4j transaction memory budget")
            return []

    def capture_visible(self, alias):
        available = (
            f"({alias}.complete=true AND (EXISTS {{ MATCH (generation:GraphPublication {{capture_id:{alias}.id}}) "
            f"WHERE {publication_at('generation')} }} OR ({alias}.active_publication_id IS NULL)))"
        )
        newer = (
            f"NOT EXISTS {{ MATCH (newer:GraphCapture {{resource_key:{alias}.resource_key}}) "
            f"WHERE newer.observed_at>{alias}.observed_at AND newer.complete=true "
            "AND ($as_of IS NULL OR newer.observed_at<=$as_of) "
            f"AND (newer.active_publication_id IS NULL OR EXISTS {{ "
            f"MATCH (later:GraphPublication {{capture_id:newer.id}}) WHERE {publication_at('later')} }}) }}"
        )
        return f"({available} AND ($as_of IS NULL OR {alias}.observed_at<=$as_of) AND ($historical OR {newer}))"

    def node_visible(self, alias):
        return (
            f"({visible_node(alias, revision='$revision')} AND "
            f"(coalesce({alias}.capture_id,{alias}._owner_capture_id) IS NULL OR EXISTS {{ "
            f"MATCH (owner:GraphCapture {{id:coalesce({alias}.capture_id,{alias}._owner_capture_id)}}) "
            f"WHERE {self.capture_visible('owner')} }}))"
        )

    def context_rows(self, ids):
        from shyhurricane.graph.model import identity

        contexts = self.hydration.setdefault("contexts", {})
        for batch in batched(sorted(set(ids) - contexts.keys()), 500):
            rows = self.read(
                "/* traversal:contexts */ UNWIND $ids AS owner "
                "OPTIONAL MATCH (p:GraphPublication {id:owner.id}) "
                "OPTIONAL MATCH (archive:GraphPublication {id:owner.legacy}) "
                "OPTIONAL MATCH (c:GraphCapture {id:owner.id}) "
                "WITH owner,p,archive,c WHERE p IS NOT NULL OR archive IS NOT NULL OR c IS NOT NULL "
                "RETURN owner.id AS id,coalesce(p.context_urls,archive.context_urls,c.context_urls,[]) AS context_urls",
                ids=[{"id": value, "legacy": identity("legacy-publication", value)} for value in batch],
            )
            contexts.update({row["id"]: row["context_urls"] for row in rows})
            if len(rows) < len(batch) and not self.stopped:
                self.limit("generation_unavailable", "Selected context generation became unavailable")
        return contexts

    def cache_nodes(self, records):
        records = sorted(records, key=lambda node: node["id"])
        contexts = self.context_rows(node["context_owner_id"] for node in records if node.get("context_owner_id"))
        for raw in records:
            owner = raw.get("context_owner_id")
            if owner and owner not in contexts:
                continue
            node = public_properties(raw)
            node["context_urls"] = contexts[owner] if owner else raw.get("context_urls", [])
            key = node["id"]
            if key not in self.nodes and len(self.nodes) >= 10000:
                self.limit("entity_limit")
                continue
            self.storage[key].add(raw["id"])
            self.hydration.setdefault("entities", {})[raw["id"]] = raw
            self.hydration.setdefault("attempted_nodes", set()).add(raw["id"])
            previous = self.nodes.get(key, {})
            merged = sorted(set(previous.get("context_urls", [])) | set(node["context_urls"]))
            if raw["id"] >= self.representatives.get(key, ""):
                self.nodes[key] = {**node, "context_urls": merged}
                self.representatives[key] = raw["id"]
            else:
                previous["context_urls"] = merged

    def lookup(self, ids, url=None):
        for batch in batched(ids, 500):
            after = ""
            while not self.stopped:
                rows = self.read(
                    "/* traversal:seeds */ CALL () { "
                    "MATCH (n:GraphEntity) USING INDEX SEEK n:GraphEntity(id) WHERE n.id IN $ids RETURN n UNION "
                    "MATCH (n:GraphEntity) USING INDEX SEEK n:GraphEntity(_logical_id) "
                    "WHERE n._logical_id IN $ids RETURN n UNION "
                    "MATCH (n:GraphEntity) USING INDEX SEEK n:GraphEntity(url) "
                    "WHERE n.url=$url AND n.kind='resource' RETURN n } "
                    f"WITH n WHERE n.id>$after AND {self.node_visible('n')} "
                    "RETURN properties(n) AS seed ORDER BY n.id LIMIT $limit",
                    ids=list(batch),
                    url=url,
                    after=after,
                    limit=500,
                )
                records = {row["seed"]["id"]: row["seed"] for row in rows}
                self.cache_nodes(records.values())
                if not records or "entity_limit" in self.metadata["truncation_reasons"]:
                    break
                after = max(records)
                # A memory-reduced page can be shorter than 500; advance until an empty page.
        self.resolved.update(ids)

    def inside(self, node):
        return self.contains(node["url"]) or any(self.contains(url) for url in node.get("context_urls", []))

    def references(self, keys, direction, kinds, *, probe=False):
        physical = sorted({value for key in keys for value in self.storage[key]})
        for batch in batched(physical, 500):
            after = ""
            while not self.stopped:
                pattern = (
                    "(anchor)-[r:RELATES]->(other:GraphEntity)"
                    if direction == "forward"
                    else (
                        "(other:GraphEntity)-[r:RELATES]->(anchor)"
                        if direction == "backward"
                        else "(anchor)-[r:RELATES]-(other:GraphEntity)"
                    )
                )
                limit = 1 if probe else min(501, 20001 - len(self.selected_memberships))
                rows = self.read(
                    "/* traversal:frontier */ MATCH (anchor:GraphEntity) USING INDEX SEEK anchor:GraphEntity(id) "
                    f"WHERE anchor.id IN $ids MATCH {pattern} "
                    "WITH startNode(r) AS a,endNode(r) AS b,r "
                    "MATCH (c:GraphCapture {id:r.capture_id}) "
                    f"WHERE r.id>$after AND {self.capture_visible('c')} "
                    f"AND {visible_relationship('r', revision='$revision')} "
                    f"AND {self.node_visible('a')} AND {self.node_visible('b')} "
                    "AND ($kinds IS NULL OR r.kind IN $kinds) "
                    "AND (r.context_capture_id IS NULL OR EXISTS { "
                    "MATCH (context:GraphCapture {id:r.context_capture_id}) "
                    f"WHERE {self.capture_visible('context')} }}) "
                    "RETURN DISTINCT r.id AS membership_id,c.id AS capture_id, "
                    "CASE WHEN a._owner_capture_id=c.id THEN a._publication_id "
                    "WHEN b._owner_capture_id=c.id THEN b._publication_id ELSE null END AS publication_id "
                    "ORDER BY membership_id LIMIT $limit",
                    ids=list(batch),
                    after=after,
                    kinds=None if kinds is None else sorted(kinds),
                    limit=limit,
                )
                rows = sorted(
                    {row["membership_id"]: row for row in rows}.values(), key=lambda row: row["membership_id"]
                )
                if not rows:
                    break
                if probe:
                    yield from rows[:1]
                    return
                for row in rows:
                    if (
                        row["membership_id"] not in self.selected_memberships
                        and len(self.selected_memberships) >= 20000
                    ):
                        self.limit("relationship_limit")
                        return
                    self.selected_memberships.add(row["membership_id"])
                    yield row
                after = rows[-1]["membership_id"]

    def load(self, keys, direction, kinds):
        unresolved = sorted(set(keys) - self.resolved)
        if unresolved:
            self.lookup(unresolved)
        loaded = {}
        for batch in batched(self.references(keys, direction, kinds), 500):
            missing = [ref for ref in batch if ref["membership_id"] not in self.memberships]
            rows, gaps, reasons = self.service.hydrate(missing, state=self.hydration)
            for reason in reasons:
                self.limit(reason)
            for gap in gaps:
                if gap not in self.metadata["analysis_gaps"]:
                    self.metadata["analysis_gaps"].append(gap)
            for ref in missing:
                self.memberships[ref["membership_id"]] = None
            for row in rows:
                self.cache_nodes([row["source"], row["target"]])
                source, target = public_properties(row["source"])["id"], public_properties(row["target"])["id"]
                source_record = {
                    **public_properties(row["source"]),
                    "context_urls": row["source_context_urls"]
                    if row["source_context_urls"] is not None
                    else row["source"].get("context_urls", []),
                }
                if source not in self.nodes or target not in self.nodes or not self.inside(source_record):
                    continue
                edge = public_properties(row["relationship"])
                edge["observed_at"] = row["observed_at"]
                self.memberships[row["relationship"]["id"]] = edge
                self.metadata["analysis_gaps"] = sorted(set(self.metadata["analysis_gaps"]) | set(row["gaps"]))
                for analysis in json.loads(row.get("analysis_details") or "[]"):
                    if analysis not in self.metadata["analysis_summaries"]:
                        self.metadata["analysis_summaries"].append(analysis)
            for ref in batch:
                edge = self.memberships[ref["membership_id"]]
                if edge is not None:
                    loaded[ref["membership_id"]] = edge
        return loaded

    def contextual(self, url):
        after = ""
        while not self.stopped:
            rows = self.read(
                "/* traversal:contextual */ CALL () { "
                "MATCH (p:GraphPublication) WHERE $url IN p.context_urls "
                f"AND {publication_at('p')} WITH p UNWIND [p.id,CASE WHEN p.digest IS NULL "
                "THEN p.capture_id ELSE null END] AS owner "
                "MATCH (n:GraphEntity {context_owner_id:owner}) RETURN n UNION "
                "MATCH (c:GraphCapture) WHERE c.active_publication_id IS NULL AND $url IN c.context_urls "
                "MATCH (n:GraphEntity {context_owner_id:c.id}) RETURN n UNION "
                "MATCH (n:GraphEntity) WHERE n.context_owner_id IS NULL AND $url IN n.context_urls RETURN n } "
                f"WITH n WHERE n.id>$after AND {self.node_visible('n')} "
                "RETURN properties(n) AS seed ORDER BY n.id LIMIT $limit",
                url=url,
                after=after,
                limit=500,
            )
            records = {row["seed"]["id"]: row["seed"] for row in rows}
            self.cache_nodes(records.values())
            if not records or "entity_limit" in self.metadata["truncation_reasons"]:
                break
            after = max(records)

    def select(self, value, role, *, boundary=False):
        self.lookup([value], web_url(value, fragment=True))
        selected = [
            key
            for key, node in self.nodes.items()
            if (
                key == value
                or value in self.storage[key]
                or (node["kind"] == "resource" and node["url"] == web_url(value, fragment=True))
            )
            and (boundary or self.inside(node))
        ]
        if role is None:
            return sorted(selected)
        for key in selected:
            node = self.nodes[key]
            if node["kind"] != "resource" or key in self.associated:
                continue
            self.associated.add(key)
            self.contextual(node["url"])
            self.association_edges.update(self.load([key], "both", ASSOCIATIONS))
            discovery = ResourceDiscovery(self.nodes, list(self.association_edges.values()))
            scripts = (discovery.loads[key] | discovery.contexts[node["url"]]) & discovery.resources.keys()
            if scripts:
                self.association_edges.update(self.load(sorted(scripts), "both", ASSOCIATIONS))
        discovery = ResourceDiscovery(self.nodes, list(self.association_edges.values()))
        seeds = set()
        for key in selected:
            seeds.update(discovery.select(key, role))
        logger.debug("Graph frontier resolved seeds=%s role=%s", len(seeds), role)
        return sorted(seeds)

    def expand(self, keys, direction, kinds, *, probe=False, depth=0):
        if self.stopped:
            return
        missing = sorted(set(keys) - self.adjacent.keys() - self.probes.keys())
        for key in list(missing):
            if probe or not self.inside(self.nodes[key]):
                self.probes[key] = bool(list(self.references([key], direction, kinds, probe=True)))
                missing.remove(key)
        if not missing:
            return
        edges = self.load(missing, direction, kinds)
        for key in missing:
            self.adjacent[key] = [
                edge
                for _, edge in sorted(edges.items())
                if edge["source" if direction == "forward" else "target"] == key
            ]
        logger.debug(
            "Graph frontier expanded depth=%s nodes=%s memberships=%s cached_nodes=%s",
            depth,
            len(missing),
            len(edges),
            len(self.nodes),
        )

    def finish(self, paths):
        self.metadata["truncation_reasons"] = sorted(set(self.metadata["truncation_reasons"]))
        logger.info(
            "Graph frontier complete paths=%s memberships=%s cached_nodes=%s seconds=%.3f reasons=%s",
            paths,
            len(self.memberships),
            len(self.nodes),
            time.monotonic() - self.started,
            self.metadata["truncation_reasons"],
        )
