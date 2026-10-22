"""Progressive resource inventory without context expansion or summary hydration."""

from itertools import batched

from neo4j.exceptions import Neo4jError

from shyhurricane.graph.lookup import reverse_host
from shyhurricane.graph.model import web_url
from shyhurricane.graph.traversal import TraversalSnapshot
from shyhurricane.graph.visibility import public_properties, visible_relationship

INVENTORY_SECONDS = 30
PAGE_SIZE = 250
VALIDATION_SIZE = 25
SCAN_LIMIT = 5000
RESULT_LIMIT = 1000


class InventorySnapshot(TraversalSnapshot):
    """Stop failed reads promptly and keep previously validated resource records."""

    def read(self, statement, *, optional=False, **parameters):
        try:
            return self.service.read(statement, timeout=5, **self.parameters, **parameters)
        except TimeoutError:
            self.limit("classification_limit" if optional else "time_limit",
                       "Inventory database budget reached; returned records are partial")
        except Neo4jError as error:
            if "TransactionTimedOut" in (error.code or ""):
                self.limit("classification_limit" if optional else "time_limit",
                           "Inventory read exceeded its transaction budget")
            elif (error.code or "").endswith("MemoryPoolOutOfMemoryError"):
                self.limit("memory_limit", "Inventory read exceeded the transaction memory budget")
            else:
                raise
        return []


def endpoint_inventory(service, scope, *, url=None, method=None, historical=False, as_of=None):
    service.budget.deadline = min(service.budget.deadline, service.budget.started + INVENTORY_SECONDS)
    reader = InventorySnapshot(service, scope, historical=historical, as_of=as_of)
    results = {}
    reader.metadata["instructions"] += (
        " Inventory includes own-URL matches only, including assets. Inputs, scripts and source/sink "
        "details are uncomputed, not zero. For those details request find_application_endpoints "
        "with detail='summary', an exact url and method when known, or use focused relationship/element "
        "tools. External dependencies require relationship discovery. Unknown capture status means "
        "classification did not finish. Saved pages navigate this bounded inventory."
    )
    if not reader.indexed():
        reader.limit("lookup_unavailable", "Resource lookup migration is pending; retry after indexing")
        return {**reader.metadata, "results": []}
    url = web_url(url, fragment=True) if url else None
    if url is not None and not reader.contains(url):
        return {**reader.metadata, "results": []}
    exact = url is not None
    field = "url" if exact or "://" in scope else "_reverse_host"
    index = f"graph_resource_{field}_page"
    indexes = reader.read(
        "/* inventory:indexes */ SHOW INDEXES YIELD name,state WHERE name=$index RETURN state",
        index=index,
    )
    if not indexes or indexes[0]["state"] != "ONLINE":
        reader.limit("lookup_unavailable", "Resource inventory index is unavailable or building; retry when online")
        return {**reader.metadata, "results": []}
    value = url or (web_url(scope, fragment=True) if "://" in scope else reverse_host("https://" + scope))
    after_value, after = value, ""
    scanned = 0
    while not reader.stopped and scanned < SCAN_LIMIT and len(results) < RESULT_LIMIT:
        cursor = "n.id>$after" if exact else (
            f"n.{field}>$after_value OR (n.{field}=$after_value AND n.id>$after)"
        )
        page = reader.read(
            "/* inventory:candidates */ MATCH (n:GraphEntity) "
            f"USING INDEX SEEK n:GraphEntity(kind,{field},id) "
            f"WHERE n.kind='resource' AND n.{field} {'=' if exact else 'STARTS WITH'} $value "
            f"AND n.id IS NOT NULL AND ({cursor}) "
            f"RETURN n.id AS id,coalesce(n._logical_id,n.id) AS logical_id,n.url AS url,n.{field} AS cursor "
            f"ORDER BY n.{field},n.id LIMIT $limit",
            value=value, after_value=after_value, after=after, limit=min(PAGE_SIZE, SCAN_LIMIT - scanned),
        )
        if not page:
            break
        scanned += len(page)
        for batch in batched([row for row in page if reader.contains(row["url"])], VALIDATION_SIZE):
            if reader.stopped or len(results) >= RESULT_LIMIT:
                break
            ids = [row["id"] for row in batch if row["logical_id"] not in results]
            if not ids:
                continue
            records = reader.read(
                "/* inventory:validate */ UNWIND $ids AS id MATCH (n:GraphEntity {id:id}) "
                "USING INDEX SEEK n:GraphEntity(id) "
                f"WHERE {reader.candidate_filter()} RETURN properties(n) AS seed",
                ids=ids, kinds=["resource"], role=None, url=url,
                method=method.upper() if method is not None else None,
            )
            selected = set()
            for row in records:
                node = public_properties(row["seed"])
                if node["id"] not in results and len(results) < RESULT_LIMIT:
                    selected.add(node["id"])
                    results[node["id"]] = {
                        "id": node["id"], "url": node["url"], "method": node.get("method", "GET"),
                        "capture_status": "unknown",
                        "follow_up": [{"tool": "find_application_endpoints", "arguments": {
                            "scope": scope, "url": node["url"], "method": node.get("method", "GET"),
                            "historical": historical, "as_of": as_of, "detail": "summary",
                        }}],
                    }
            if not selected or reader.stopped or "classification_limit" in reader.metadata["truncation_reasons"]:
                continue
            statuses = reader.read(
                "/* inventory:capture-status */ UNWIND $resources AS resource "
                "RETURN resource.id AS id, EXISTS { "
                "MATCH (c:GraphCapture {resource_key:resource.key}) "
                "USING INDEX SEEK c:GraphCapture(resource_key,observed_at) "
                f"WHERE c.observed_at IS NOT NULL AND {reader.capture_visible('c')} "
                "MATCH (n:GraphEntity)-[r:RELATES]->(other:GraphEntity) "
                "USING INDEX SEEK r:RELATES(capture_id) "
                "WHERE r.capture_id=c.id AND coalesce(n._logical_id,n.id)=resource.id "
                "AND r.kind='HOSTED_AT' "
                "AND r.classification='observed' "
                f"AND {visible_relationship('r', revision='$revision')} "
                f"AND {reader.node_visible('n')} AND {reader.node_visible('other')} "
                "AND (r.context_capture_id IS NULL OR EXISTS { "
                "MATCH (context:GraphCapture {id:r.context_capture_id}) "
                f"WHERE {reader.capture_visible('context')} }}) }} AS captured",
                resources=[{"id": key, "key": f"{results[key]['method'].upper()} {results[key]['url']}"}
                           for key in sorted(selected)], optional=True,
            )
            for row in statuses:
                results[row["id"]]["capture_status"] = "captured" if row["captured"] else "referenced"
        after_value, after = page[-1]["cursor"], page[-1]["id"]
    if len(results) >= RESULT_LIMIT:
        reader.limit("result_limit")
    if scanned >= SCAN_LIMIT:
        reader.limit("scan_limit", "Inventory candidate scan cap reached")
    ordered = sorted(results.values(), key=lambda node: (node["url"], node["method"], node["id"]))
    return {**reader.metadata, "results": ordered}
