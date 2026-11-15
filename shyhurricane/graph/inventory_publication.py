"""Generation lifecycle for the fresh Neo4j inventory layout."""

from neo4j import Query, unit_of_work

from shyhurricane.graph.config import graph_timeouts
from shyhurricane.graph.inventory_scope import url_properties
from shyhurricane.graph.model import identity


class InventoryConflict(RuntimeError):
    """A generation no longer owns the unit's staging slot."""


class InventoryIncomplete(RuntimeError):
    """Publication is missing one or more durable batches."""


def initialize(session):
    """Install the inventory schema, explicitly rejecting an earlier populated graph."""
    timeout = graph_timeouts().schema
    def run(statement):
        return session.run(Query(statement, timeout=timeout))

    marker = run("MATCH (s:GraphState {id:'inventory_schema'}) RETURN s.version AS version").single()
    if marker and marker["version"] != 1:
        raise ValueError("Unsupported inventory schema; use a fresh graph store")
    if not marker:
        populated = run(
            "MATCH (n) WHERE n:GraphCapture OR n:GraphEntity OR n:GraphPublication "
            "OR n:GraphInventoryFact RETURN n.id AS id LIMIT 1"
        ).single()
        if populated:
            raise ValueError("Inventory initialization requires a fresh graph store")
    run("CREATE CONSTRAINT graphstate_id IF NOT EXISTS FOR (n:GraphState) REQUIRE n.id IS UNIQUE").consume()
    for label in ("GraphInventoryFact", "GraphInventoryBatch", "GraphInventoryGeneration",
                  "GraphInventoryUnit", "GraphInventoryContext", "GraphInventoryReadPin", "GraphInventoryCapture",
                  "GraphInventoryStatus", "GraphInventoryScope", "GraphInventoryMembership"):
        run(f"CREATE CONSTRAINT {label.lower()}_id IF NOT EXISTS FOR (n:{label}) REQUIRE n.id IS UNIQUE").consume()
    run("CREATE CONSTRAINT inventory_batch_slot IF NOT EXISTS FOR (n:GraphInventoryBatch) "
        "REQUIRE n.slot_id IS UNIQUE").consume()
    for fields in (("generation", "manifest_id"), ("generation", "kind", "manifest_id"),
                   ("generation", "role", "manifest_id"), ("generation", "url", "manifest_id")):
        name = "inventory_fact_" + "_".join(fields)
        run(f"CREATE INDEX {name} IF NOT EXISTS FOR (n:GraphInventoryFact) "
            f"ON ({','.join('n.' + field for field in fields)})").consume()
    for label, fields in (
        ("GraphInventoryFact", ("generation",)),
        ("GraphInventoryScope", ("generation",)),
        ("GraphInventoryScope", ("reverse_host",)),
        ("GraphInventoryScope", ("url",)),
        ("GraphInventoryScope", ("kind", "reverse_host")),
        ("GraphInventoryMembership", ("reverse_host",)),
        ("GraphInventoryMembership", ("generation",)),
        ("GraphInventoryMembership", ("kind", "reverse_host")),
        ("GraphInventoryBatch", ("generation", "sequence")),
        ("GraphInventoryBatch", ("generation",)),
        ("GraphInventoryContext", ("generation",)),
        ("GraphInventoryStatus", ("generation",)),
        ("GraphInventoryStatus", ("generation", "published_revision")),
        ("GraphInventoryCapture", ("url", "method", "observed_at")),
        ("GraphInventoryGeneration", ("url", "method", "observed_at")),
        ("GraphInventoryGeneration", ("reverse_host",)),
        ("GraphInventoryContext", ("reverse_host",)),
        ("GraphInventoryGeneration", ("unit_id", "published_revision")),
        ("GraphInventoryGeneration", ("state", "retired_at", "id")),
        ("GraphInventoryGeneration", ("state", "id")),
        ("GraphInventoryContext", ("generation", "capture_id")),
        ("GraphInventoryContext", ("url", "generation")),
        ("GraphInventoryContext", ("reverse_host", "generation")),
        ("GraphInventoryCapture", ("reverse_host", "id")),
        ("GraphInventoryReadPin", ("expires",)),
    ):
        run(f"CREATE INDEX {label.lower()}_{'_'.join(fields)} IF NOT EXISTS FOR (n:{label}) "
            f"ON ({','.join('n.' + field for field in fields)})").consume()
    run("MERGE (s:GraphState {id:'inventory_schema'}) ON CREATE SET s.version=1").consume()
    run("MERGE (s:GraphState {id:'publication_revision'}) ON CREATE SET s.value=0").consume()


class InventoryPublisher:
    def __init__(self, session):
        self.session = session

    def register_captures(self, captures):
        records = [{**capture, **url_properties(capture["url"])} for capture in captures]
        if not 1 <= len(records) <= 500:
            raise ValueError("Capture registration requires a bounded batch")

        @unit_of_work(timeout=graph_timeouts().control)
        def register(tx):
            revision = tx.run(
                "MATCH (s:GraphState {id:'publication_revision'}) SET s.value=s.value+1 RETURN s.value AS revision"
            ).single()["revision"]
            tx.run(
                "UNWIND $rows AS row MERGE (c:GraphInventoryCapture {id:row.id}) "
                "ON CREATE SET c += row,c.registered_revision=$revision",
                rows=records, revision=revision,
            ).consume()
            return revision
        return self.session.execute_write(register)

    def register_capture(self, capture):
        capture = {**capture, **url_properties(capture.get("url", ""))}

        @unit_of_work(timeout=graph_timeouts().control)
        def register(tx):
            tx.run(
                "MATCH (s:GraphState {id:'publication_revision'}) SET s.catalog_lock=coalesce(s.catalog_lock,0)+1"
            ).consume()
            previous = tx.run(
                "MATCH (c:GraphInventoryCapture {id:$id}) RETURN c.registered_revision AS revision",
                id=capture["id"],
            ).single()
            if previous:
                return previous["revision"]
            revision = tx.run(
                "MATCH (s:GraphState {id:'publication_revision'}) SET s.value=s.value+1 RETURN s.value AS revision"
            ).single()["revision"]
            tx.run(
                "CREATE (c:GraphInventoryCapture) SET c += $capture,c.registered_revision=$revision",
                capture=capture, revision=revision,
            ).consume()
            return revision
        return self.session.execute_write(register)

    def begin(self, unit, generation, capture):
        """Reserve a deterministic generation without retiring the active inventory."""
        capture = {**capture, **url_properties(capture.get("url", ""))}

        @unit_of_work(timeout=graph_timeouts().control)
        def begin(tx):
            row = tx.run(
                "MERGE (u:GraphInventoryUnit {id:$unit}) "
                "SET u.lock=coalesce(u.lock,0)+1 "
                "WITH u OPTIONAL MATCH (g:GraphInventoryGeneration {id:$generation}) "
                "RETURN u.staging AS staging,g.state AS state,g.unit_id AS owner",
                unit=unit, generation=generation,
            ).single()
            if row["owner"] is not None and row["owner"] != unit:
                raise InventoryConflict("Inventory generation belongs to another unit")
            if row["state"] in ("active", "retired"):
                return row["state"]
            if row["staging"] not in (None, generation):
                raise InventoryConflict("Another inventory generation is staging")
            tx.run(
                "MATCH (u:GraphInventoryUnit {id:$unit}) SET u.staging=$generation "
                "MERGE (g:GraphInventoryGeneration {id:$generation}) "
                "ON CREATE SET g.unit_id=$unit,g.capture_id=$capture.id,g.url=$capture.url,"
                "g.observed_at=$capture.observed_at,g.method=$capture.method,g.state='staging',"
                "g.host=$capture.host,g.reverse_host=$capture.reverse_host,g.scheme=$capture.scheme,"
                "g.port=$capture.port,g.path=$capture.path,"
                "g.discovery='pending',g.flow='pending',g.created_at=timestamp()/1000.0",
                unit=unit, generation=generation, capture=capture,
            ).consume()
            return "staging"
        return self.session.execute_write(begin)

    def activate(self, unit, generation, *, batches, facts, discovery="complete", flow="pending"):
        if batches < 0 or facts < 0:
            raise ValueError("Invalid inventory generation counts")
        allowed = {"pending", "partial", "complete", "failed", "blocked"}
        if discovery not in allowed or flow not in allowed:
            raise ValueError("Invalid inventory coverage")

        @unit_of_work(timeout=graph_timeouts().control)
        def activate(tx):
            row = tx.run(
                "MATCH (u:GraphInventoryUnit {id:$unit}) SET u.lock=coalesce(u.lock,0)+1 "
                "WITH u MATCH (g:GraphInventoryGeneration {id:$generation}) "
                "RETURN u.active AS active,u.staging AS staging,g.unit_id AS owner,"
                "g.published_revision AS revision,g.state AS state",
                unit=unit, generation=generation,
            ).single()
            if row is None or row["owner"] != unit:
                raise InventoryConflict("Inventory generation is unavailable")
            if row["active"] == generation:
                return row["revision"]
            if row["staging"] != generation or row["state"] != "staging":
                raise InventoryConflict("Inventory staging slot changed")
            summary = tx.run(
                "MATCH (b:GraphInventoryBatch {generation:$generation}) "
                "RETURN count(b) AS batches,count(DISTINCT b.sequence) AS sequences,"
                "coalesce(min(b.sequence),0) AS first,coalesce(max(b.sequence),-1) AS last",
                generation=generation,
            ).single()
            count = tx.run(
                "MATCH (f:GraphInventoryFact {generation:$generation}) RETURN count(f) AS facts",
                generation=generation,
            ).single()["facts"]
            if (summary["batches"] != batches or summary["sequences"] != batches
                    or summary["first"] != 0 or summary["last"] != batches - 1 or count != facts):
                raise InventoryIncomplete("Inventory generation is missing committed batches or facts")
            revision = tx.run(
                "MATCH (s:GraphState {id:'publication_revision'}) SET s.value=s.value+1 "
                "RETURN s.value AS revision"
            ).single()["revision"]
            tx.run(
                "MATCH (u:GraphInventoryUnit {id:$unit}),(g:GraphInventoryGeneration {id:$generation}) "
                "OPTIONAL MATCH (old:GraphInventoryGeneration {id:u.active}) "
                "SET old.state='retired',old.retired_revision=$revision,old.retired_at=timestamp()/1000.0 "
                "SET g.state='active',g.published_revision=$revision,g.discovery=$discovery,g.flow=$flow,"
                "g.published_at=timestamp()/1000.0,u.active=$generation,u.staging=null",
                unit=unit, generation=generation, revision=revision, discovery=discovery, flow=flow,
            ).consume()
            return revision
        return self.session.execute_write(activate)

    def pin(self, token, revision, expires):
        if revision < 0:
            raise ValueError("Invalid inventory revision")
        key = identity("inventory-read-pin-v4", token)
        @unit_of_work(timeout=graph_timeouts().control)
        def pin(tx):
            tx.run(
                "MATCH (s:GraphState {id:'publication_revision'}) SET s.pin_lock=coalesce(s.pin_lock,0)+1"
            ).consume()
            unavailable = tx.run(
                "MATCH (g:GraphInventoryGeneration) WHERE g.state IN ['cleaning','cleaned'] AND "
                + visible_inventory("g", "$revision") + " RETURN g.id AS id LIMIT 1", revision=revision,
            ).single()
            if unavailable:
                raise InventoryConflict("Inventory revision has expired")
            tx.run(
                "MERGE (p:GraphInventoryReadPin {id:$id}) "
                "ON CREATE SET p.revision=$revision,p.expires=$expires",
                id=key, revision=revision, expires=expires,
            ).consume()
        self.session.execute_write(pin)
        return key


def visible_inventory(alias="g", revision="$revision"):
    """Only internally supplied aliases may be interpolated in Cypher."""
    return (
        f"{alias}.published_revision<={revision} AND "
        f"({alias}.retired_revision IS NULL OR {alias}.retired_revision>{revision})"
    )
