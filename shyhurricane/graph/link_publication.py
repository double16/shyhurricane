"""Publish inferred relationships and derived entities with immutable structural dependencies."""

import logging

from shyhurricane.graph.lookup import reverse_host
from shyhurricane.graph.model import identity
from shyhurricane.graph.publication import GraphPublisher, PublicationConflict, write_batches

logger = logging.getLogger(__name__)


class LinkPublisher(GraphPublisher):
    active_pointer = "active_link_publication_id"
    staging_pointer = "staging_link_publication_id"

    def publish(self, projection):
        rows = self.store.read(
            "MATCH (c:GraphCapture {id:$id}) RETURN c.active_publication_id AS generation",
            id=projection.event["id"],
        )
        if not rows or not rows[0]["generation"]:
            raise PublicationConflict("Structural publication is unavailable")
        structural = rows[0]["generation"]
        original = set(projection.structural_nodes if projection.structural_nodes is not None else projection.nodes)
        derived = set(projection.nodes) - original
        capture = {
            "id": projection.event["id"],
            "url": projection.url,
            "publication_kind": "links",
            "gaps": projection.gaps,
            "relationship_estimate": len(set(projection.edges) | set(projection.planned_links or {})),
        }
        digest = identity(
            "inferred-links-v2",
            structural,
            projection.planned_links,
            projection.gaps,
            {key: projection.nodes[key] for key in sorted(derived)},
        )
        with self.store.connect().session(database="neo4j") as session:
            generation, completed = self.begin(session, capture, digest)
            if completed:
                return False
            links = {}
            for key, link in (projection.planned_links or {}).items():
                record = dict(link)
                for side in ("source", "target"):
                    local = record[f"_{side}_local"]
                    logical = record[f"_{side}_storage_id"]
                    if local:
                        record[f"_{side}_storage_id"] = identity(
                            generation if logical in derived else structural, logical
                        )
                        # Derived nodes become visible atomically with this publication.
                        record[f"_{side}_local"] = logical in derived
                if record["_proof_local"]:
                    record["evidence_id"] = identity(structural, record["evidence_id"])
                    record["_proof_local"] = False
                links[key] = record
            try:
                self.validate_dependencies(links)
                self.stage_derived(session, projection, generation, derived)
                self.stage(session, capture, generation, projection, links)
                self.validate_dependencies(links)
                self.validate_staging(generation, links)
                self.activate(session, capture, generation)
            except Exception:
                try:
                    self.abandon(session, generation)
                except Exception:
                    logger.warning("Graph link staging retirement deferred: %s", generation, exc_info=True)
                raise
        return True

    def stage_derived(self, session, projection, generation, derived):
        write_batches(
            session,
            projection.event["id"],
            "derived-entities",
            "UNWIND $nodes AS row MERGE (n:GraphEntity {id:row.id}) SET n += row",
            "nodes",
            (
                {
                    **projection.nodes[key],
                    "id": identity(generation, key),
                    "_logical_id": key,
                    "_publication_id": generation,
                    "_owner_capture_id": projection.event["id"],
                    "_link_publication": True,
                    "_reverse_host": reverse_host(projection.nodes[key]["url"]),
                }
                for key in sorted(derived)
            ),
        )

    def validate_staging(self, generation, links):
        from itertools import batched

        for batch in batched(sorted(links), 500):
            expected = [identity(generation, key) for key in batch]
            rows = self.store.read(
                "UNWIND $ids AS id MATCH ()-[r:RELATES {id:id}]->() "
                "MATCH (e:GraphEvidence {id:r.evidence_id}) RETURN DISTINCT r.id AS id",
                ids=expected,
            )
            if {row["id"] for row in rows} != set(expected):
                raise PublicationConflict("Staged inferred relationships or evidence are incomplete")

    def stage(self, session, capture, generation, projection, links):
        self.stage_dependencies(session, capture, generation, links)

        def records():
            for link in links.values():
                record = {
                    key: value
                    for key, value in link.items()
                    if key not in {"_source_local", "_target_local", "_proof_local"}
                }
                record.update(
                    id=identity(generation, link["id"]),
                    _logical_id=link["id"],
                    _publication_id=generation,
                    _build_capture_id=capture["id"],
                    _link_publication=True,
                )
                yield record

        write_batches(
            session,
            capture["id"],
            "inferred-links",
            "UNWIND $edges AS r MATCH (a:GraphEntity {id:r._source_storage_id}), "
            "(b:GraphEntity {id:r._target_storage_id}) MERGE (a)-[e:RELATES {id:r.id}]->(b) SET e += r",
            "edges",
            records(),
        )
