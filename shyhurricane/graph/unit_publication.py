"""Explicit detail expansion owns its entities without replacing the capture's summary."""

import json
import logging
from urllib.parse import urlsplit

from neo4j import unit_of_work

from shyhurricane.graph.config import graph_timeouts
from shyhurricane.graph.model import identity
from shyhurricane.graph.publication import GraphPublisher, PublicationConflict, activation_metadata


class UnitPublisher(GraphPublisher):
    def __init__(self, store, unit_id):
        super().__init__(store)
        self.unit_id = unit_id

    def publish(self, projection):
        from shyhurricane.graph.links import LinkPlanner

        links = projection.planned_links
        if links is None:
            links = LinkPlanner(self.store, projection).plan()
        capture = {
            "id": projection.event["id"],
            "url": projection.url,
            "host": urlsplit(projection.url).hostname,
            "resource_key": f"{projection.event['data']['method'].upper()} {projection.url}",
            "observed_at": projection.event["observed_at"],
            "timestamp_inferred": projection.event["timestamp_inferred"],
            "backfill": projection.event["backfill"],
            "gaps": projection.gaps,
            "context_urls": sorted({item["url"] for item in projection.contexts}),
            "analysis_details": json.dumps(projection.analysis, sort_keys=True),
            "analysis_unit_id": self.unit_id,
        }

        def semantic(records):
            return {
                key: {name: value for name, value in record.items() if name != "_unit_id"}
                for key, record in records.items()
            }

        digest = identity(
            "unit-publication",
            self.unit_id,
            semantic(projection.nodes),
            semantic(projection.edges),
            semantic(links),
            projection.gaps,
            projection.analysis,
        )
        with self.store.connect().session(database="neo4j") as session:
            generation, complete = self.begin(session, capture, digest)
            if complete:
                return False
            try:
                self.publish_staged(session, capture, generation, projection, links)
            except Exception:
                try:
                    self.abandon(session, generation)
                except Exception:
                    logging.getLogger(__name__).warning("Analysis staging retirement deferred", exc_info=True)
                raise
        return True

    def publish_staged(self, session, capture, generation, projection, links):
        from shyhurricane.graph.link_publication import LinkPublisher

        for node in projection.nodes.values():
            node.update(_unit_id=self.unit_id)
        for edge in projection.edges.values():
            edge.update(_unit_id=self.unit_id)
        for link in links.values():
            link.update(_unit_id=self.unit_id)
        self.stage(session, capture, generation, projection, links)
        self.validate_dependencies(links)
        LinkPublisher.validate_staging(self, generation, {**projection.edges, **links})
        self.activate(session, capture, generation)

    def abandon(self, session, generation):
        super().abandon(session, generation)
        session.run(
            "MATCH (u:GraphAnalysisUnit {id:$unit}) WHERE u.staging_publication_id=$generation "
            "SET u.staging_publication_id=null",
            unit=self.unit_id,
            generation=generation,
        ).consume()

    def begin(self, session, capture, digest):
        @unit_of_work(timeout=graph_timeouts().control)
        def begin(tx):
            tx.run(
                "MERGE (c:GraphCapture {id:$capture.id}) ON CREATE SET c += $capture,"
                "c.complete=true,c.unit_only=true,c.budget_limited=true,"
                "c.gaps=['Only expanded analysis units are available for this capture']",
                capture=activation_metadata(capture),
            ).consume()
            row = tx.run(
                "MERGE (u:GraphAnalysisUnit {id:$id}) SET u.capture_id=$capture "
                "WITH u OPTIONAL MATCH (p:GraphPublication {id:u.active_publication_id}) "
                "RETURN u.active_publication_id AS active,u.staging_publication_id AS staging,p.digest AS digest",
                id=self.unit_id,
                capture=capture["id"],
            ).single()
            if row["digest"] == digest:
                return row["active"], True
            generation = identity("unit-generation", self.unit_id, digest, row["active"])
            if row.get("staging") and row["staging"] != generation:
                tx.run(
                    "MATCH (p:GraphPublication {id:$id}) WHERE p.published_at IS NULL "
                    "SET p:GraphCleanupPending,p.state='abandoned',p.retired_at=timestamp()/1000.0",
                    id=row["staging"],
                ).consume()
            tx.run(
                "MERGE (p:GraphPublication {id:$generation}) ON CREATE SET p += $metadata,"
                "p.digest=$digest,p.state='staging',p.expected_active=$expected "
                "WITH p MATCH (u:GraphAnalysisUnit {id:$unit}) SET u.staging_publication_id=p.id",
                generation=generation,
                metadata={**activation_metadata(capture), "id": generation, "capture_id": capture["id"]},
                digest=digest,
                expected=row["active"],
                unit=self.unit_id,
            ).consume()
            return generation, False

        return session.execute_write(begin)

    def activate(self, session, capture, generation):
        @unit_of_work(timeout=graph_timeouts().control)
        def activate(tx):
            row = tx.run(
                "MATCH (u:GraphAnalysisUnit {id:$unit}),(p:GraphPublication {id:$generation}) "
                "WHERE u.staging_publication_id=p.id "
                "AND coalesce(u.active_publication_id,'')=coalesce(p.expected_active,'') "
                "MERGE (revision:GraphState {id:'publication_revision'}) "
                "SET revision.value=coalesce(revision.value,0)+1 "
                "WITH u,p,revision OPTIONAL MATCH (old:GraphPublication {id:u.active_publication_id}) "
                "SET u.active_publication_id=p.id,u.staging_publication_id=null,"
                "p.state='published',p.published_at=timestamp()/1000.0,p.published_revision=revision.value "
                "FOREACH (previous IN CASE WHEN old IS NULL THEN [] ELSE [old] END | "
                "SET previous:GraphCleanupPending,previous.state='retired',"
                "previous.retired_revision=revision.value,previous.retired_at=timestamp()/1000.0) RETURN p.id AS id",
                unit=self.unit_id,
                generation=generation,
            ).single()
            if row is None:
                raise PublicationConflict("Analysis unit changed during expansion")

        session.execute_write(activate)
