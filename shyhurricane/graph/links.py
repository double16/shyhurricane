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
                    ".parameter_index,.return_value,.selector,.html_id,.field_name,.html_tag,.form_selectors,"
                    ".disabled,.form_successful,.form_data,.form_field,.form_request,"
                    ".form_target_url,.form_target_method,"
                    ".import_key,.module_key,.reexport_name} AS node, evidence_id, "
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
            "kind": "FLOWS_TO"
            if rule == "js.module-link"
            else "REQUESTS"
            if rule == "js.form-request"
            else "READS_FROM",
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

    def module(self, importer, exporter, importer_local, exporter_local, seen=None):
        seen = set() if seen is None else seen
        signature = (exporter["id"], importer.get("parameter_index"), importer.get("return_value", False))
        if signature in seen:
            return
        if len(seen) >= 32 or len(self.links) >= LINK_LIMIT:
            self.gap()
            return
        seen = seen | {signature}
        if importer.get("imported_name") not in (exporter.get("export_names") or []):
            return
        if importer.get("reexport_name") and importer.get("module_key"):
            upstream = [
                (item, True)
                for item in list(self.graph.nodes.values())
                if item.get("import_key") == importer["module_key"]
            ]
            upstream.extend(
                (row["node"] | {"evidence_id": row["evidence_id"]}, False)
                for row in self.candidates("import_key", importer["module_key"])
            )
            for caller, local in upstream:
                self.module(caller, importer, local, importer_local, seen)
            return
        parameter = importer.get("parameter_index")
        if exporter.get("reexport_name") and exporter.get("import_key"):
            if parameter is None and not importer.get("return_value"):
                return
            key = identity(self.capture_id, "reexport", signature)
            proxy_id = self.graph.node(
                "module_interface",
                key,
                capture_id=self.capture_id,
                name=exporter["reexport_name"],
                parameter_index=parameter,
                return_value=importer.get("return_value", False),
            )
            proxy = self.graph.nodes.get(proxy_id)
            if proxy is None:
                self.gap()
                return
            proof = self.proofs.get(exporter["id"]) if exporter_local else exporter.get("evidence_id")
            proxy = {
                **proxy,
                "imported_name": exporter["imported_name"],
                "evidence_id": proof,
                "_proof_external": not exporter_local,
            }
            returns = importer.get("return_value") is True
            self.add(
                proxy if returns else importer,
                importer if returns else proxy,
                importer,
                "js.module-link",
                source_local=True if returns else importer_local,
                target_local=importer_local if returns else True,
                proof_local=importer_local and not importer.get("_proof_external", False),
                context=exporter.get("capture_id"),
            )
            if exporter_local:
                self.proofs[proxy_id] = proof
            candidates = [
                (item, True)
                for item in list(self.graph.nodes.values())
                if item.get("module_key") == exporter["import_key"] and item.get("export_names")
            ]
            candidates.extend(
                (row["node"] | {"evidence_id": row["evidence_id"]}, False)
                for row in self.candidates("module_key", exporter["import_key"])
            )
            if not candidates:
                gap = f"Unresolved re-export: {exporter['import_key']} export {exporter['imported_name']}"
                if gap not in self.graph.gaps:
                    self.graph.gaps.append(gap)
            for candidate, local in candidates:
                self.module(proxy, candidate, True, local, seen)
            return
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
            proof_local=importer_local and not importer.get("_proof_external", False),
        )

    def dom(self, selector, element, selector_local, element_local, contexts):
        candidates = []
        if element.get("html_id"):
            candidates.append(f"#{element['html_id']}")
        if element.get("field_name"):
            candidates.extend([f'[name="{element["field_name"]}"]', f'input[name="{element["field_name"]}"]'])
        if selector.get("form_data"):
            candidates = element.get("form_selectors") or []
            if (
                element.get("disabled")
                or not element.get("form_successful", True)
                or not element.get("field_name")
                or element.get("html_tag") not in {"input", "select", "textarea"}
                or (selector.get("form_field") is not None and selector["form_field"] != element.get("field_name"))
            ):
                return
        if element.get("capture_id") in contexts and selector.get("selector") in candidates:
            if selector.get("form_request"):
                if element.get("html_tag") == "form" and element.get("form_target_url"):
                    target = self.graph.resource(element["form_target_url"], element["form_target_method"])
                    self.add(
                        selector,
                        self.graph.nodes[target],
                        selector,
                        "js.form-request",
                        source_local=selector_local,
                        target_local=True,
                        proof_local=selector_local,
                        context=element["capture_id"],
                    )
                return
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
        for node in list(self.graph.nodes.values()):
            if node.get("import_key"):
                found = False
                for other in modules[node["import_key"]]:
                    found |= node.get("imported_name") in (other.get("export_names") or [])
                    self.module(node, other, True, True)
                for row in self.candidates("module_key", node["import_key"]):
                    found |= node.get("imported_name") in (row["node"].get("export_names") or [])
                    self.module(node, row["node"] | {"evidence_id": row["evidence_id"]}, True, False)
                if not found and (node.get("return_value") or node.get("parameter_index") is not None):
                    gap = f"Unresolved module interface: {node['import_key']} export {node.get('imported_name')}"
                    if gap not in self.graph.gaps:
                        self.graph.gaps.append(gap)
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
                    selectors.extend([f'[name="{node["field_name"]}"]', f'input[name="{node["field_name"]}"]'])
                selectors.extend(node.get("form_selectors") or [])
                for selector in set(selectors):
                    for row in self.candidates("selector", selector):
                        other = {**row["node"], "evidence_id": row["evidence_id"]}
                        self.dom(other, node, False, True, row["contexts"] or [])
        resolved_requests = {link["source"] for link in self.links.values() if link["kind"] == "REQUESTS"}
        for node in self.graph.nodes.values():
            if node.get("form_request") and node["id"] not in resolved_requests:
                gap = f"Unresolved form-bound request: {node['selector']} requires captured form action and method"
                if gap not in self.graph.gaps:
                    self.graph.gaps.append(gap)
        return self.links
