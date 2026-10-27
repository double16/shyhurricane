"""Request-scoped, revision-consistent seed resolution and bounded graph frontiers."""

import json
import logging
import time
from collections import defaultdict
from itertools import batched
from urllib.parse import urlsplit

from neo4j.exceptions import Neo4jError

from shyhurricane.graph.config import graph_timeouts
from shyhurricane.graph.discovery import INTERPRETATION, ResourceDiscovery, in_context
from shyhurricane.graph.lookup import MIGRATION_ID, reverse_host
from shyhurricane.graph.model import identity, web_url
from shyhurricane.graph.visibility import (
    public_properties,
    publication_at,
    visible_node,
    visible_relationship,
)

logger = logging.getLogger(__name__)
ASSOCIATIONS = {"CONTAINS", "SENDS_FIELD", "SETS_COOKIE", "SUBMITS_TO", "SENDS_COOKIE", "LOADS", "IMPORTS"}


class TraversalSnapshot:
    def __init__(self, service, scope, *, historical=False, as_of=None, resume=None):
        from shyhurricane.graph.query import scope_predicate

        self.service = service
        self.store = service.store
        self.contains = scope_predicate(scope)
        self.started = service.budget.started
        self.budget = service.budget
        self.read_cache = (resume or {}).get("reads", {})
        self.lookup_ready = None
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
        self.loaded = {}
        self.adjacent = {}
        self.probes = {}
        self.metadata = {
            "analysis_gaps": [],
            "analysis_summaries": [],
            "retrieval_truncated": False,
            "truncation_reasons": [],
            "instructions": "Paths describe bounded captured evidence; absence is not proof. " + INTERPRETATION,
        }
        if resume is not None:
            self.parameters["revision"] = resume["revision"]
            return
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
        remaining = self.budget.remaining()
        if remaining < 0.001:
            self.limit("time_limit", "Traversal database budget reached")
            return []
        key = identity(statement, json.dumps(parameters, sort_keys=True))
        if key in self.read_cache:
            return self.read_cache[key]
        before = time.monotonic()
        try:
            rows = self.service.read(
                statement, timeout=min(graph_timeouts().read, remaining), **self.parameters, **parameters
            )
            logger.debug(
                "Graph frontier read stage=%s batch=%s rows=%s seconds=%.3f remaining_seconds=%.3f",
                statement.split("*/", 1)[0].removeprefix("/* traversal:"),
                len(parameters.get("ids", [])),
                len(rows),
                time.monotonic() - before,
                max(0, self.started + 120 - time.monotonic()),
            )
            self.read_cache[key] = rows
            return rows
        except TimeoutError:
            self.limit("time_limit", "Traversal database budget reached")
            return []
        except Neo4jError as error:
            if "TransactionTimedOut" in (error.code or "") and self.budget.remaining() <= 0:
                self.limit("time_limit", "Traversal database budget reached")
                return []
            if "TransactionTimedOut" not in (error.code or "") and not (error.code or "").endswith(
                "MemoryPoolOutOfMemoryError"
            ):
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
            if "TransactionTimedOut" in (error.code or ""):
                self.limit("time_limit", "Traversal read could not complete within its transaction budget")
            else:
                self.limit("memory_limit", "Traversal record exceeds the Neo4j transaction memory budget")
            return []

    def capture_visible(self, alias):
        available = (
            f"({alias}.complete=true AND (EXISTS {{ MATCH (generation:GraphPublication {{capture_id:{alias}.id}}) "
            f"WHERE {publication_at('generation')} }} OR ({alias}.active_publication_id IS NULL)))"
        )
        newer = (
            f"NOT EXISTS {{ MATCH (newer:GraphCapture {{resource_key:{alias}.resource_key}}) "
            f"WHERE (newer.observed_at>{alias}.observed_at "
            f"OR (newer.observed_at={alias}.observed_at AND newer.id<{alias}.id)) AND newer.complete=true "
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
                "RETURN owner.id AS id, CASE WHEN EXISTS { MATCH (lookup:GraphContext {owner_id:p.id}) } THEN "
                "COLLECT { MATCH (context:GraphContext {owner_id:p.id}) RETURN context.url } "
                "ELSE coalesce(p.context_urls,archive.context_urls,c.context_urls,[]) END AS context_urls",
                ids=[{"id": value, "legacy": identity("legacy-publication", value)} for value in batch],
            )
            contexts.update({row["id"]: row["context_urls"] for row in rows})
            if len(rows) < len(batch) and not self.stopped:
                self.limit("generation_unavailable", "Selected context generation became unavailable")
        return contexts

    def cache_nodes(self, records, *, accept=None):
        records = sorted(records, key=lambda node: node["id"])
        contexts = self.context_rows(node["context_owner_id"] for node in records if node.get("context_owner_id"))
        for raw in records:
            owner = raw.get("context_owner_id")
            if owner and owner not in contexts:
                continue
            node = public_properties(raw)
            node["context_urls"] = contexts[owner] if owner else raw.get("context_urls", [])
            if accept is not None and not accept(node):
                continue
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
        if not self.stopped:
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
        signature = (direction, None if kinds is None else tuple(sorted(kinds)))
        cached = {key: self.loaded[(key, signature)] for key in keys if (key, signature) in self.loaded}
        keys = sorted(set(keys) - cached.keys())
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
            if not reasons:
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
                edge = self.memberships.get(ref["membership_id"])
                if edge is not None:
                    loaded[ref["membership_id"]] = edge
        if not self.metadata["retrieval_truncated"]:
            for key in keys:
                self.loaded[(key, signature)] = {
                    member: edge for member, edge in loaded.items()
                    if edge["source"] == key or edge["target"] == key
                }
        for edges in cached.values():
            loaded.update(edges)
        return loaded

    def indexed(self):
        if self.lookup_ready is None:
            rows = self.read(
                "/* traversal:lookup-state */ MATCH (m:GraphState {id:$lookup}) RETURN m.complete AS ready",
                lookup=MIGRATION_ID,
            )
            self.lookup_ready = bool(rows and rows[0]["ready"])
        return self.lookup_ready

    def context_candidates(self, predicate):
        # Owner metadata is immutable for publications. Capture-owned compatibility rows
        # apply only until their first publication; archived generations cover older revisions.
        field = "url" if predicate.startswith("lookup.url") else "id"
        return (
            f"MATCH (lookup:GraphContext) USING INDEX SEEK lookup:GraphContext({field}) WHERE " + predicate + " "
            "CALL (lookup) { "
            "WITH lookup WHERE lookup.owner_kind='GraphEntity' "
            "MATCH (n:GraphEntity {id:lookup.owner_id}) WHERE n.context_owner_id IS NULL RETURN n UNION "
            "WITH lookup WHERE lookup.owner_kind='GraphPublication' "
            "MATCH (p:GraphPublication {id:lookup.owner_id}) "
            f"WHERE {publication_at('p')} "
            "UNWIND [p.id,CASE WHEN p.digest IS NULL THEN p.capture_id ELSE null END] AS owner "
            "MATCH (n:GraphEntity {context_owner_id:owner}) RETURN n UNION "
            "WITH lookup WHERE lookup.owner_kind='GraphCapture' "
            "MATCH (c:GraphCapture {id:lookup.owner_id}) WHERE c.active_publication_id IS NULL "
            "MATCH (n:GraphEntity {context_owner_id:c.id}) RETURN n } RETURN n "
        )

    def candidate_filter(self):
        return (
            f"{self.node_visible('n')} "
            "AND ($kinds IS NULL OR n.kind IN $kinds) AND ($role IS NULL OR n.role=$role) "
            "AND ($url IS NULL OR n.url=$url) "
            "AND ($method IS NULL OR toUpper(coalesce(n.method,''))=$method) "
            "AND EXISTS { MATCH (n)-[r:RELATES]-(other:GraphEntity) "
            "MATCH (c:GraphCapture {id:r.capture_id}) "
            f"WHERE {self.capture_visible('c')} AND {visible_relationship('r', revision='$revision')} "
            f"AND {self.node_visible('other')} "
            "AND (r.context_capture_id IS NULL OR EXISTS { "
            "MATCH (context:GraphCapture {id:r.context_capture_id}) "
            f"WHERE {self.capture_visible('context')} }}) }} "
        )

    def lookup_pages(self, label, field, value, *, exact=False, filters="true", parameters=None):
        """Use compound index order so each page need not sort the whole scoped graph."""
        after_value, after = value, ""
        cursor_filter = "n.id>$after" if exact else (
            f"n.{field}>$after_value OR (n.{field}=$after_value AND n.id>$after)"
        )
        while not self.stopped:
            rows = self.read(
                f"/* traversal:candidates */ MATCH (n:{label}) USING INDEX SEEK n:{label}({field},id) "
                f"WHERE n.{field} {'=' if exact else 'STARTS WITH'} $value "
                f"AND n.id IS NOT NULL AND "
                f"({cursor_filter}) "
                f"AND {filters} "
                f"RETURN properties(n) AS seed,n.{field} AS cursor ORDER BY n.{field},n.id LIMIT $limit",
                value=value, after_value=after_value, after=after, limit=500, **(parameters or {}),
            )
            if not rows:
                return
            yield rows
            after_value, after = rows[-1]["cursor"], rows[-1]["seed"]["id"]

    def candidates(self, scope, *, kinds=None, role=None, url=None, context_url=None, method=None):
        """Select direct nodes, then context-owned nodes, without a global union/sort."""
        parsed = urlsplit(scope if "://" in scope else "https://" + scope)
        exact = bool(context_url or url)
        field = "url" if exact or "://" in scope else "_reverse_host"
        value = (context_url or url
                 or (web_url(scope, fragment=True) if "://" in scope else reverse_host(parsed.geturl())))
        parameters = {"url": url, "kinds": kinds or None, "role": role,
                      "method": method.upper() if method is not None else None}

        def cache(rows):
            self.cache_nodes((row["seed"] for row in rows), accept=lambda node: (
                self.inside(node) and (context_url is None or in_context(node, context_url))
            ))
            if len(self.nodes) > 1000:
                self.limit("result_limit")
                return False
            return not self.stopped

        for rows in self.lookup_pages("GraphEntity", field, value, exact=exact,
                                      filters=self.candidate_filter(), parameters=parameters):
            if not cache(rows):
                return
        # An in-scope exact URL is fully covered by the direct URL index, including
        # context-owned nodes. Context discovery is only needed to admit nodes whose
        # own URL is outside scope through an in-scope document association.
        if url is not None and self.contains(url):
            return
        context_field = "url" if context_url or "://" in scope else "reverse_host"
        context_value = (context_url
                         or (web_url(scope, fragment=True) if "://" in scope else reverse_host(parsed.geturl())))
        for owners in self.lookup_pages("GraphContext", context_field, context_value, exact=bool(context_url)):
            after = ""
            while not self.stopped:
                rows = self.read(
                    "/* traversal:context-candidates */ CALL () { "
                    + self.context_candidates("lookup.id IN $lookup_ids")
                    + f"}} WITH n WHERE n.id>$after AND {self.candidate_filter()} "
                    "RETURN DISTINCT properties(n) AS seed ORDER BY seed.id LIMIT $limit",
                    lookup_ids=[row["seed"]["id"] for row in owners], after=after, limit=500, **parameters,
                )
                if not rows:
                    break
                if not cache(rows):
                    return
                after = max(row["seed"]["id"] for row in rows)

    def boundaries(self, scope, *, kinds=None, role=None, url=None, context_url=None):
        """Include matching outgoing boundary nodes without hydrating unrelated edges."""
        parsed = urlsplit(scope if "://" in scope else "https://" + scope)
        field = "url" if url or "://" in scope else "_reverse_host"
        value = url or (web_url(scope, fragment=True) if "://" in scope else reverse_host(parsed.geturl()))
        examined = 0
        for anchors in self.lookup_pages("GraphEntity", field, value, exact=bool(url),
                                         filters=self.node_visible('n')):
            examined += len(anchors)
            contexts = self.context_rows(row["seed"]["context_owner_id"] for row in anchors
                                         if row["seed"].get("context_owner_id"))
            ids = [row["seed"]["id"] for row in anchors if self.inside({
                **row["seed"], "context_urls": contexts.get(row["seed"].get("context_owner_id"),
                                                            row["seed"].get("context_urls", [])),
            })]
            after = ""
            while ids and not self.stopped:
                rows = self.read(
                    "/* traversal:boundary-candidates */ MATCH (anchor:GraphEntity) "
                    "USING INDEX SEEK anchor:GraphEntity(id) WHERE anchor.id IN $ids "
                    "MATCH (anchor)-[edge:RELATES]->(:GraphEntity) "
                    "WITH edge,endNode(edge) AS n "
                    "MATCH (capture:GraphCapture {id:edge.capture_id}) "
                    f"WHERE n.id>$after AND {self.capture_visible('capture')} "
                    f"AND {visible_relationship('edge', revision='$revision')} AND {self.candidate_filter()} "
                    "AND (edge.context_capture_id IS NULL OR EXISTS { "
                    "MATCH (context:GraphCapture {id:edge.context_capture_id}) "
                    f"WHERE {self.capture_visible('context')} }}) "
                    "RETURN DISTINCT properties(n) AS seed ORDER BY seed.id LIMIT $limit",
                    ids=ids, after=after, limit=500, url=url, kinds=kinds or None, role=role, method=None,
                )
                if not rows:
                    break
                self.cache_nodes((row["seed"] for row in rows), accept=(
                    None if context_url is None else lambda node: in_context(node, context_url)
                ))
                if len(self.nodes) > 1000:
                    self.limit("result_limit")
                    return
                after = max(row["seed"]["id"] for row in rows)
            if examined >= 10000:
                self.limit("entity_limit", "Boundary candidate selection reached its entity budget")
                return

    def contextual(self, url):
        if self.indexed():
            self._indexed_context(url)
            return
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

    def _indexed_context(self, url):
        urls = [url] if isinstance(url, str) else list(url)
        after = ""
        while not self.stopped:
            rows = self.read(
                "/* traversal:indexed-context */ CALL () { "
                + self.context_candidates("lookup.url IN $urls")
                + f"}} WITH n WHERE n.id>$after AND {self.node_visible('n')} "
                "RETURN properties(n) AS seed ORDER BY n.id LIMIT $limit",
                urls=urls, after=after, limit=500,
            )
            if not rows:
                break
            self.cache_nodes(row["seed"] for row in rows)
            after = max(row["seed"]["id"] for row in rows)
            if "entity_limit" in self.metadata["truncation_reasons"]:
                break

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
            self.contextual(node["url"])
            self.association_edges.update(self.load([key], "both", ASSOCIATIONS))
            discovery = ResourceDiscovery(self.nodes, list(self.association_edges.values()))
            scripts = (discovery.loads[key] | discovery.contexts[node["url"]]) & discovery.resources.keys()
            if scripts:
                self.association_edges.update(self.load(sorted(scripts), "both", ASSOCIATIONS))
            if not self.stopped:
                self.associated.add(key)
        discovery = ResourceDiscovery(self.nodes, list(self.association_edges.values()))
        seeds = set()
        for key in selected:
            seeds.update(discovery.select(key, role))
        logger.debug("Graph frontier resolved seeds=%s role=%s", len(seeds), role)
        return sorted(seeds)

    def probe(self, keys, direction, kinds):
        """Return one existence result per physical anchor, in bounded batches."""
        physical = sorted({value for key in keys for value in self.storage[key]})
        found = {}
        pattern = ("(anchor)-[r:RELATES]->(other:GraphEntity)" if direction == "forward"
                   else "(other:GraphEntity)-[r:RELATES]->(anchor)")
        for batch in batched(physical, 500):
            rows = self.read(
                "/* traversal:probe */ UNWIND $ids AS id MATCH (anchor:GraphEntity {id:id}) "
                f"RETURN id, EXISTS {{ MATCH {pattern} "
                "MATCH (c:GraphCapture {id:r.capture_id}) "
                f"WHERE {self.capture_visible('c')} AND {visible_relationship('r', revision='$revision')} "
                f"AND {self.node_visible('anchor')} AND {self.node_visible('other')} "
                "AND ($kinds IS NULL OR r.kind IN $kinds) "
                "AND (r.context_capture_id IS NULL OR EXISTS { "
                "MATCH (context:GraphCapture {id:r.context_capture_id}) "
                f"WHERE {self.capture_visible('context')} }}) }} AS found",
                ids=list(batch), kinds=None if kinds is None else sorted(kinds),
            )
            found.update({row["id"]: row["found"] for row in rows})
            if self.stopped:
                break
        for key in keys:
            anchors = self.storage[key]
            if anchors and anchors <= found.keys():
                self.probes[key] = any(found[anchor] for anchor in anchors)

    def expand(self, keys, direction, kinds, *, probe=False, depth=0):
        if self.stopped:
            return
        missing = sorted(set(keys) - self.adjacent.keys() - self.probes.keys())
        probing = [key for key in missing if probe or not self.inside(self.nodes[key])]
        self.probe(probing, direction, kinds)
        missing = [key for key in missing if key not in probing]
        if not missing:
            return
        edges = self.load(missing, direction, kinds)
        grouped = defaultdict(list)
        for _, edge in sorted(edges.items()):
            grouped[edge["source" if direction == "forward" else "target"]].append(edge)
        if not self.metadata["retrieval_truncated"]:
            for key in missing:
                self.adjacent[key] = grouped[key]
        logger.debug(
            "Graph frontier expanded depth=%s nodes=%s memberships=%s cached_nodes=%s",
            depth,
            len(missing),
            len(edges),
            len(self.nodes),
        )

    def describe(self):
        owners = sorted({
            (raw.get("_owner_capture_id") or raw.get("capture_id"), raw.get("_publication_id"))
            for raw in self.hydration.get("entities", {}).values()
            if raw.get("_owner_capture_id") or raw.get("capture_id")
        }, key=lambda item: (item[0], item[1] or ""))
        for batch in batched(owners, 500):
            rows = self.read(
                "/* traversal:metadata */ UNWIND $owners AS owner "
                "OPTIONAL MATCH (p:GraphPublication {id:owner.publication}) "
                "OPTIONAL MATCH (c:GraphCapture {id:owner.capture}) "
                "RETURN coalesce(p.gaps,c.gaps,[]) AS gaps, "
                "coalesce(p.analysis_details,c.analysis_details,'[]') AS analysis_details",
                owners=[{"capture": capture, "publication": publication or identity("legacy-publication", capture)}
                        for capture, publication in batch],
            )
            for row in rows:
                self.metadata["analysis_gaps"] = sorted(set(self.metadata["analysis_gaps"]) | set(row["gaps"]))
                for analysis in json.loads(row["analysis_details"]):
                    if analysis not in self.metadata["analysis_summaries"]:
                        self.metadata["analysis_summaries"].append(analysis)

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
