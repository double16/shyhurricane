"""Plan inferred links using bounded indexed reads before staging a publication."""

from collections import defaultdict

from neo4j.exceptions import Neo4jError

from shyhurricane.graph.model import identity
from shyhurricane.graph.visibility import visible_node

LINK_LIMIT = 20000
READ_BATCH_SIZE = 500


class LinkPlanner:
    def __init__(self, store, projection):
        self.store = store
        self.graph = projection
        self.capture_id = projection.event["id"]
        self.contexts = [item["id"] for item in projection.contexts]
        self.cache = {}
        self.links = {}
        self.proofs = {}
        for edge in sorted(projection.edges.values(), key=lambda item: item["id"]):
            self.proofs.setdefault(edge["target"], edge["evidence_id"])

    def candidates(self, field, value):
        key = (field, value)
        if key in self.cache:
            return self.cache[key]
        result, after, batch_size = [], "", READ_BATCH_SIZE
        while len(result) < LINK_LIMIT:
            limit = min(batch_size, LINK_LIMIT - len(result))
            try:
                rows = self.store.read(
                    f"MATCH (other:GraphEntity) WHERE other.{field}=$value AND other.id>$after "
                    f"AND {visible_node('other')} "
                    "AND coalesce(other._owner_capture_id,other.capture_id,'')<>$capture "
                    "WITH other ORDER BY other.id LIMIT $limit "
                    "OPTIONAL MATCH ()-[proof:RELATES]->(other) "
                    "WHERE proof.capture_id=other.capture_id "
                    "AND coalesce(proof._publication_id,'')=coalesce(other._publication_id,'') "
                    "WITH other, min(proof.evidence_id) AS evidence_id "
                    "OPTIONAL MATCH (c:GraphCapture {id:other.capture_id}) "
                    "RETURN other{.id,.kind,._logical_id,._publication_id,.capture_id,.imported_name,.export_names,"
                    ".parameter_index,.return_value,.selector,.html_id,.field_name} AS node, evidence_id, "
                    "CASE WHEN $capture IN c.context_capture_ids THEN [$capture] ELSE [] END AS contexts "
                    "ORDER BY other.id",
                    value=value,
                    after=after,
                    capture=self.capture_id,
                    limit=limit,
                )
            except Neo4jError as error:
                if not (error.code or "").endswith("MemoryPoolOutOfMemoryError"):
                    raise
                if batch_size == 1:
                    from shyhurricane.graph.publication import PublicationMemoryError

                    raise PublicationMemoryError(
                        "Graph inferred-link read exceeds the transaction memory budget"
                    ) from error
                batch_size = max(1, batch_size // 2)
                continue
            result.extend(rows)
            if len(rows) < limit:
                break
            after = rows[-1]["node"]["id"]
        if len(result) == LINK_LIMIT:
            self.gap()
        self.cache[key] = result
        return result

    def gap(self):
        gap = "Inferred link budget reached"
        if gap not in self.graph.gaps:
            self.graph.gaps.append(gap)

    def add(self, source, target, importer, rule, *, source_local, target_local, proof_local, context=None):
        if len(self.links) >= LINK_LIMIT:
            self.gap()
            return
        logical_source = source.get("_logical_id") or source["id"]
        logical_target = target.get("_logical_id") or target["id"]
        proof = self.proofs.get(importer["id"]) if proof_local else importer.get("evidence_id")
        if not proof:
            return
        key = identity(rule, source["id"], target["id"])
        self.links[key] = {
            "id": key,
            "source": logical_source,
            "target": logical_target,
            "kind": "FLOWS_TO" if rule == "js.module-link" else "READS_FROM",
            "capture_id": importer["capture_id"],
            "evidence_id": proof,
            "classification": "statically_inferred",
            "rule": rule,
            "_source_local": source_local,
            "_target_local": target_local,
            "_proof_local": proof_local,
            "_source_storage_id": source["id"],
            "_target_storage_id": target["id"],
            **({"context_capture_id": context} if context else {}),
        }

    def module(self, importer, exporter, importer_local, exporter_local):
        if importer.get("imported_name") not in (exporter.get("export_names") or []):
            return
        parameter = importer.get("parameter_index")
        returns = importer.get("return_value") is True and exporter.get("return_value") is True
        if not returns and (parameter is None or parameter != exporter.get("parameter_index")):
            return
        source, target = (exporter, importer) if returns else (importer, exporter)
        self.add(
            source,
            target,
            importer,
            "js.module-link",
            source_local=exporter_local if returns else importer_local,
            target_local=importer_local if returns else exporter_local,
            proof_local=importer_local,
        )

    def dom(self, selector, element, selector_local, element_local, contexts):
        candidates = []
        if element.get("html_id"):
            candidates.append(f"#{element['html_id']}")
        if element.get("field_name"):
            candidates.extend([f"[name=\"{element['field_name']}\"]", f"input[name=\"{element['field_name']}\"]"])
        if element.get("capture_id") in contexts and selector.get("selector") in candidates:
            self.add(
                element,
                selector,
                selector,
                "js.dom-selector",
                source_local=element_local,
                target_local=selector_local,
                proof_local=selector_local,
                context=element["capture_id"],
            )

    def plan(self):
        modules, elements = defaultdict(list), defaultdict(list)
        for node in self.graph.nodes.values():
            if node.get("export_names"):
                modules[node.get("module_key")].append(node)
            if node.get("kind") == "element":
                elements[node.get("capture_id")].append(node)
        for node in self.graph.nodes.values():
            if node.get("import_key"):
                for other in modules[node["import_key"]]:
                    self.module(node, other, True, True)
                for row in self.candidates("module_key", node["import_key"]):
                    self.module(node, row["node"], True, False)
            if node.get("export_names") and node.get("module_key"):
                for row in self.candidates("import_key", node["module_key"]):
                    other = {**row["node"], "evidence_id": row["evidence_id"]}
                    self.module(other, node, False, True)
            if node.get("selector"):
                for capture in self.contexts:
                    for element in elements[capture]:
                        self.dom(node, element, True, True, self.contexts)
                    for row in self.candidates("capture_id", capture):
                        if row["node"].get("kind") == "element":
                            self.dom(node, row["node"], True, False, self.contexts)
            if node.get("kind") == "element":
                selectors = []
                if node.get("html_id"):
                    selectors.append(f"#{node['html_id']}")
                if node.get("field_name"):
                    selectors.extend([f"[name=\"{node['field_name']}\"]", f"input[name=\"{node['field_name']}\"]"])
                for selector in selectors:
                    for row in self.candidates("selector", selector):
                        other = {**row["node"], "evidence_id": row["evidence_id"]}
                        self.dom(other, node, False, True, row["contexts"] or [])
        return self.links
