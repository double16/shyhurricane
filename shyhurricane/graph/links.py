"""Plan inferred links using bounded indexed reads before staging a publication."""

import logging
import time
from collections import defaultdict

from neo4j.exceptions import Neo4jError

from shyhurricane.graph.config import graph_timeouts
from shyhurricane.graph.model import identity
from shyhurricane.graph.visibility import visible_node

LINK_LIMIT = 20000
READ_BATCH_SIZE = 500
logger = logging.getLogger(__name__)


class PlanningYield(Exception):
    """The caller must checkpoint and schedule another planning slice."""


def limited_read(error):
    code = error.code or ""
    return code.endswith("MemoryPoolOutOfMemoryError") or "TransactionTimedOut" in code


class LinkPlanner:
    def __init__(self, store, projection):
        self.store = store
        self.graph = projection
        self.capture_id = projection.event["id"]
        self.contexts = sorted({item["id"] for item in projection.contexts})
        self.cache = {}
        self.links = {}
        self.proofs = {}
        self.checkpointing = False
        self.operation = {}
        self.pages = {}
        self.hydrated = {}
        self.cursor = {"phase": "modules", "node": 0, "context": 0, "after_context": "", "after_id": ""}
        self.node_ids = list(projection.nodes)
        self.deadline = float("inf")
        self.reads_left = float("inf")
        self.selection_reads = 0
        self.hydration_reads = 0
        for edge in sorted(projection.edges.values(), key=lambda item: item["id"]):
            self.proofs.setdefault(edge["target"], edge["evidence_id"])

    def guard(self):
        if time.monotonic() >= self.deadline or self.reads_left <= 0:
            raise PlanningYield

    def read(self, statement, **parameters):
        self.guard()
        self.reads_left -= 1
        timeout = min(graph_timeouts().read, self.deadline - time.monotonic())
        if timeout <= 0:
            raise PlanningYield
        self.operation = {"statement": statement, "parameters": {"timeout": timeout, **parameters}}
        return self.store.read(statement, timeout=timeout, **parameters)

    def hydrate(self, ids):
        missing = [key for key in ids if key not in self.hydrated] if self.checkpointing else ids
        if not missing:
            return [self.hydrated[key] for key in ids]
        if len(missing) != len(ids):
            self.hydrate(missing)
            return [self.hydrated[key] for key in ids]
        started = time.monotonic()
        try:
            self.hydration_reads += 1
            rows = self.read(
                "UNWIND $ids AS id MATCH (other:GraphEntity {id:id}) "
                "USING INDEX SEEK other:GraphEntity(id) "
                f"WHERE {visible_node('other')} "
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
                "CASE WHEN $capture IN c.context_capture_ids OR EXISTS { "
                "MATCH (membership:GraphDocumentContext {owner_id:other._publication_id,capture_id:$capture}) "
                "} THEN [$capture] ELSE [] END AS contexts "
                "ORDER BY other.id",
                ids=ids,
                capture=self.capture_id,
            )
        except Neo4jError as error:
            if not limited_read(error):
                raise
            if len(ids) == 1:
                if "TransactionTimedOut" in (error.code or ""):
                    raise
                from shyhurricane.graph.publication import PublicationMemoryError

                raise PublicationMemoryError(
                    "Graph inferred-link hydration exceeds the transaction memory budget"
                ) from error
            middle = len(ids) // 2
            logger.debug("Graph link hydration subdividing records=%s", len(ids))
            return self.hydrate(ids[:middle]) + self.hydrate(ids[middle:])
        if {row["node"]["id"] for row in rows} != set(ids):
            from shyhurricane.graph.publication import PublicationConflict

            raise PublicationConflict("An inferred link candidate changed during hydration; replan the capture")
        logger.debug(
            "Graph link hydration capture=%s records=%s seconds=%.3f",
            self.capture_id, len(rows), time.monotonic() - started,
        )
        if self.checkpointing:
            self.hydrated.update((row["node"]["id"], row) for row in rows)
        return rows

    def candidates(self, field, value):
        key = identity("candidate", field, value)
        if key in self.cache:
            return self.cache[key]
        # Pin equality lookup: the competing id-range index can scan millions of unrelated nodes.
        if field not in {"module_key", "import_key", "capture_id", "selector"}:
            raise ValueError("Unsupported inferred-link candidate field")
        kind = "AND other.kind='element' " if field == "capture_id" else ""
        page = self.pages.setdefault(key, {"result": [], "after": "", "batch_size": READ_BATCH_SIZE})
        result, after, batch_size = page["result"], page["after"], page["batch_size"]
        while len(result) < LINK_LIMIT:
            limit = min(batch_size, LINK_LIMIT - len(result))
            started = time.monotonic()
            try:
                self.selection_reads += 1
                selected = page.get("selected")
                if selected is None:
                    selected = self.read(
                        f"MATCH (other:GraphEntity) USING INDEX SEEK other:GraphEntity({field}) "
                        f"WHERE other.{field}=$value AND other.id>$after {kind}"
                        f"AND {visible_node('other')} "
                        "AND coalesce(other._owner_capture_id,other.capture_id,'')<>$capture "
                        "RETURN other.id AS id ORDER BY other.id LIMIT $limit",
                        value=value,
                        after=after,
                        capture=self.capture_id,
                        limit=limit,
                    )
                page["selected"] = selected
            except Neo4jError as error:
                if not limited_read(error):
                    raise
                if batch_size == 1:
                    if "TransactionTimedOut" in (error.code or ""):
                        raise
                    from shyhurricane.graph.publication import PublicationMemoryError

                    raise PublicationMemoryError(
                        "Graph inferred-link read exceeds the transaction memory budget"
                    ) from error
                batch_size = max(1, batch_size // 2)
                page["batch_size"] = batch_size
                continue
            logger.debug(
                "Graph link selection capture=%s field=%s records=%s seconds=%.3f",
                self.capture_id, field, len(selected), time.monotonic() - started,
            )
            if selected:
                result.extend(self.hydrate([row["id"] for row in selected]))
            page.pop("selected", None)
            if len(selected) < limit:
                break
            after = selected[-1]["id"]
            page["after"] = after
        if len(result) == LINK_LIMIT:
            self.gap()
        self.cache[key] = result
        self.pages.pop(key, None)
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
        started = time.monotonic()
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
        logger.info(
            "Graph link planning capture=%s selection_reads=%s hydration_reads=%s candidates=%s links=%s seconds=%.3f",
            self.capture_id, self.selection_reads, self.hydration_reads,
            sum(map(len, self.cache.values())), len(self.links),
            time.monotonic() - started,
        )
        return self.links

    def checkpoint(self):
        """JSON-only state; no generators, drivers, or executable queue payloads."""
        return {
            "cursor": self.cursor, "node_ids": self.node_ids, "cache": self.cache, "operation": self.operation,
            "pages": self.pages, "hydrated": self.hydrated, "links": self.links, "proofs": self.proofs,
            "selection_reads": self.selection_reads, "hydration_reads": self.hydration_reads,
        }

    def restore(self, state):
        for key, value in state.items():
            if key not in self.checkpoint():
                raise ValueError("Unknown link checkpoint field")
            setattr(self, key, value)

    def module_node(self, node):
        if node.get("import_key"):
            found = False
            exporters = [
                (other, True) for other in list(self.graph.nodes.values())
                if other.get("module_key") == node["import_key"] and other.get("export_names")
            ]
            exporters.extend(
                (row["node"] | {"evidence_id": row["evidence_id"]}, False)
                for row in self.candidates("module_key", node["import_key"])
            )
            for other, local in exporters:
                found |= node.get("imported_name") in (other.get("export_names") or [])
                self.module(node, other, True, local)
            if not found and (node.get("return_value") or node.get("parameter_index") is not None):
                gap = f"Unresolved module interface: {node['import_key']} export {node.get('imported_name')}"
                if gap not in self.graph.gaps:
                    self.graph.gaps.append(gap)
        if node.get("export_names") and node.get("module_key"):
            for row in self.candidates("import_key", node["module_key"]):
                self.module(row["node"] | {"evidence_id": row["evidence_id"]}, node, False, True)

    @staticmethod
    def element_selectors(element):
        result = list(element.get("form_selectors") or [])
        if element.get("html_id"):
            result.append(f"#{element['html_id']}")
        if element.get("field_name"):
            name = element["field_name"]
            result.extend([f'[name="{name}"]', f'input[name="{name}"]'])
        return set(result)

    def context_batch(self, contexts, selectors):
        """Seek matching elements in several contexts; hydrate only the matching page."""
        batch_size = self.cursor.get("batch_size", READ_BATCH_SIZE)
        while True:
            self.guard()
            selected = self.cursor.get("selected")
            if selected is None:
                try:
                    self.selection_reads += 1
                    selected = self.read(
                        "UNWIND $contexts AS context WITH context WHERE context>=$after_context "
                        "MATCH (other:GraphEntity {capture_id:context}) USING INDEX SEEK other:GraphEntity(capture_id) "
                        "WHERE other.kind='element' AND (context>$after_context OR other.id>$after_id) "
                        f"AND {visible_node('other')} "
                        "AND coalesce(other._owner_capture_id,other.capture_id,'')<>$capture "
                        "AND (('#'+other.html_id) IN $selectors "
                        "OR ('[name=\"'+other.field_name+'\"]') IN $selectors "
                        "OR ('input[name=\"'+other.field_name+'\"]') IN $selectors "
                        "OR any(selector IN coalesce(other.form_selectors,[]) WHERE selector IN $selectors)) "
                        "RETURN other.id AS id, other.capture_id AS context "
                        "ORDER BY other.capture_id,other.id LIMIT $limit",
                        contexts=contexts, selectors=list(selectors), capture=self.capture_id,
                        after_context=self.cursor["after_context"], after_id=self.cursor["after_id"],
                        limit=batch_size,
                    )
                except Neo4jError as error:
                    if not limited_read(error) or batch_size == 1:
                        raise
                    batch_size = max(1, batch_size // 2)
                    self.cursor["batch_size"] = batch_size
                    continue
                self.cursor["selected"] = selected
            rows = self.hydrate([row["id"] for row in selected]) if selected else []
            for row in rows:
                self.guard()
                for token in self.element_selectors(row["node"]):
                    for selector in selectors.get(token, []):
                        self.dom(selector, row["node"], True, False, set(contexts))
            self.cursor.pop("selected", None)
            self.hydrated.clear()
            if len(selected) < batch_size:
                self.cursor.update(after_context="", after_id="")
                self.cursor.pop("batch_size", None)
                return
            self.cursor.update(after_context=selected[-1]["context"], after_id=selected[-1]["id"])

    def plan_slice(self, *, seconds=30, reads=200, contexts=100):
        """Return completion; an unfinished slice can be restored in another process."""
        self.checkpointing = True
        self.deadline = time.monotonic() + seconds
        self.reads_left = reads
        try:
            while self.cursor["phase"] == "modules" and self.cursor["node"] < len(self.node_ids):
                self.guard()
                self.module_node(self.graph.nodes[self.node_ids[self.cursor["node"]]])
                self.cursor["node"] += 1
            if self.cursor["phase"] == "modules":
                self.cursor.update(phase="contexts", node=0)
            if self.cursor["phase"] == "contexts":
                grouped = defaultdict(list)
                for node in self.graph.nodes.values():
                    if node.get("selector"):
                        grouped[node["selector"]].append(node)
                batch = self.contexts[self.cursor["context"]:self.cursor["context"] + contexts]
                if batch and grouped:
                    for node in list(self.graph.nodes.values()):
                        self.guard()
                        if node.get("kind") == "element" and node.get("capture_id") in batch:
                            for token in self.element_selectors(node):
                                for selector in grouped.get(token, []):
                                    self.dom(selector, node, True, True, set(batch))
                    self.context_batch(batch, grouped)
                self.cursor["context"] += len(batch)
                if self.cursor["context"] < len(self.contexts):
                    return False
                self.cursor.update(phase="reverse", node=0)
            while self.cursor["phase"] == "reverse" and self.cursor["node"] < len(self.node_ids):
                self.guard()
                node = self.graph.nodes[self.node_ids[self.cursor["node"]]]
                if node.get("kind") == "element":
                    for selector in self.element_selectors(node):
                        for row in self.candidates("selector", selector):
                            self.dom(row["node"] | {"evidence_id": row["evidence_id"]}, node,
                                     False, True, row["contexts"] or [])
                self.cursor["node"] += 1
            resolved = {link["source"] for link in self.links.values() if link["kind"] == "REQUESTS"}
            for node in self.graph.nodes.values():
                if node.get("form_request") and node["id"] not in resolved:
                    gap = f"Unresolved form-bound request: {node['selector']} requires captured form action and method"
                    if gap not in self.graph.gaps:
                        self.graph.gaps.append(gap)
            self.cursor["phase"] = "complete"
            return True
        except PlanningYield:
            return False
        finally:
            self.deadline = self.reads_left = float("inf")
