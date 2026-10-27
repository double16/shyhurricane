"""Fresh immutable artifact storage with constant-time accounting triggers."""

VERSION = 2


def initialize(connection):
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if version == VERSION:
        return
    if version or connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' LIMIT 1").fetchone():
        raise ValueError("Unsupported graph storage version; use a fresh assessment directory")
    connection.execute("PRAGMA auto_vacuum=INCREMENTAL")
    connection.executescript(
        "BEGIN IMMEDIATE;"
        "CREATE TABLE graph_storage_totals (id INTEGER PRIMARY KEY CHECK(id=1),"
        "logical INTEGER NOT NULL DEFAULT 0,stored INTEGER NOT NULL DEFAULT 0,"
        "retained INTEGER NOT NULL DEFAULT 0,cached INTEGER NOT NULL DEFAULT 0,"
        "pending INTEGER NOT NULL DEFAULT 0,retiring INTEGER NOT NULL DEFAULT 0,"
        "last_progress REAL,next_kind INTEGER NOT NULL DEFAULT 0);"
        "INSERT INTO graph_storage_totals(id) VALUES (1);"
        "CREATE TABLE graph_blobs (digest TEXT PRIMARY KEY,codec TEXT NOT NULL,version INTEGER NOT NULL,"
        "size INTEGER NOT NULL,payload BLOB NOT NULL);"
        "CREATE TABLE graph_blob_usage (digest TEXT PRIMARY KEY,size INTEGER NOT NULL,stored INTEGER NOT NULL,"
        "node_refs INTEGER NOT NULL DEFAULT 0 CHECK(node_refs>=0),"
        "retained_refs INTEGER NOT NULL DEFAULT 0 CHECK(retained_refs>=0),"
        "cached_refs INTEGER NOT NULL DEFAULT 0 CHECK(cached_refs>=0));"
        "CREATE INDEX graph_blob_unused ON graph_blob_usage(node_refs,digest);"
        "CREATE TABLE graph_nodes (id TEXT PRIMARY KEY,kind TEXT NOT NULL,digest TEXT NOT NULL,"
        "created REAL NOT NULL,owners INTEGER NOT NULL DEFAULT 0 CHECK(owners>=0),"
        "caches INTEGER NOT NULL DEFAULT 0 CHECK(caches>=0),"
        "incoming INTEGER NOT NULL DEFAULT 0 CHECK(incoming>=0),"
        "retained_parents INTEGER NOT NULL DEFAULT 0 CHECK(retained_parents>=0),"
        "cached_parents INTEGER NOT NULL DEFAULT 0 CHECK(cached_parents>=0),"
        "retained INTEGER NOT NULL DEFAULT 0,cached INTEGER NOT NULL DEFAULT 0,"
        "retiring INTEGER NOT NULL DEFAULT 0);"
        "CREATE INDEX graph_node_unused ON graph_nodes(owners,caches,incoming,retiring,created,id);"
        "CREATE INDEX graph_node_retiring ON graph_nodes(retiring,id);"
        "CREATE INDEX graph_node_digest ON graph_nodes(digest);"
        "CREATE TABLE graph_edges (parent TEXT NOT NULL,child TEXT NOT NULL,"
        "retained INTEGER NOT NULL DEFAULT 0,cached INTEGER NOT NULL DEFAULT 0,"
        "PRIMARY KEY(parent,child)) WITHOUT ROWID;"
        "CREATE INDEX graph_edge_child ON graph_edges(child);"
        "CREATE TABLE graph_object_owners (owner TEXT PRIMARY KEY,ref TEXT NOT NULL);"
        "CREATE INDEX graph_owner_ref ON graph_object_owners(ref);"
        "CREATE TABLE graph_cache (key TEXT PRIMARY KEY,ref TEXT NOT NULL,accessed REAL NOT NULL);"
        "CREATE INDEX graph_cache_lru ON graph_cache(accessed,key);"
        "CREATE INDEX graph_cache_ref ON graph_cache(ref);"
        "CREATE TABLE graph_storage_work (parent TEXT PRIMARY KEY,after_child TEXT NOT NULL DEFAULT '');"
        "CREATE VIEW graph_objects AS SELECT n.id AS ref,n.digest,n.created,"
        "(n.caches>0) AS cache,coalesce((SELECT min(accessed) FROM graph_cache WHERE ref=n.id),n.created) AS accessed "
        "FROM graph_nodes n WHERE kind='artifact' AND retiring=0;"
        "CREATE VIEW graph_object_links AS SELECT parent,child FROM graph_edges WHERE child LIKE 'a:%';"
        "CREATE VIEW graph_blob_links AS SELECT substr(parent,3) AS parent,substr(child,3) AS child "
        "FROM graph_edges WHERE parent LIKE 'a:%' AND child LIKE 't:%';"
        "CREATE TRIGGER blob_insert AFTER INSERT ON graph_blobs BEGIN "
        "INSERT INTO graph_blob_usage(digest,size,stored) VALUES (NEW.digest,NEW.size,length(NEW.payload)); END;"
        "CREATE TRIGGER usage_insert AFTER INSERT ON graph_blob_usage BEGIN "
        "UPDATE graph_storage_totals SET logical=logical+NEW.size,stored=stored+NEW.stored WHERE id=1; END;"
        "CREATE TRIGGER blob_delete AFTER DELETE ON graph_blobs BEGIN "
        "DELETE FROM graph_blob_usage WHERE digest=OLD.digest; END;"
        "CREATE TRIGGER usage_delete AFTER DELETE ON graph_blob_usage BEGIN "
        "UPDATE graph_storage_totals SET logical=logical-OLD.size,stored=stored-OLD.stored,"
        "retained=retained-(OLD.retained_refs>0)*OLD.stored,"
        "cached=cached-(OLD.retained_refs=0 AND OLD.cached_refs>0)*OLD.stored WHERE id=1; END;"
        "CREATE TRIGGER blob_class AFTER UPDATE OF retained_refs,cached_refs ON graph_blob_usage BEGIN "
        "UPDATE graph_storage_totals SET retained=retained+"
        "((NEW.retained_refs>0)-(OLD.retained_refs>0))*NEW.stored,cached=cached+"
        "((NEW.retained_refs=0 AND NEW.cached_refs>0)-(OLD.retained_refs=0 AND OLD.cached_refs>0))"
        "*NEW.stored WHERE id=1; END;"
        "CREATE TRIGGER node_insert AFTER INSERT ON graph_nodes BEGIN "
        "UPDATE graph_blob_usage SET node_refs=node_refs+1 WHERE digest=NEW.digest; END;"
        "CREATE TRIGGER node_delete AFTER DELETE ON graph_nodes BEGIN "
        "DELETE FROM graph_storage_work WHERE parent=OLD.id;"
        "UPDATE graph_blob_usage SET node_refs=node_refs-1,retained_refs=retained_refs-OLD.retained,"
        "cached_refs=cached_refs-OLD.cached WHERE digest=OLD.digest;"
        "UPDATE graph_storage_totals SET retiring=retiring-OLD.retiring WHERE id=1; END;"
        "CREATE TRIGGER node_counts AFTER UPDATE OF owners,caches,retained_parents,cached_parents ON graph_nodes BEGIN "
        "UPDATE graph_nodes SET retained=(owners>0 OR retained_parents>0),"
        "cached=(caches>0 OR cached_parents>0) WHERE id=NEW.id; END;"
        "CREATE TRIGGER node_class AFTER UPDATE OF retained,cached ON graph_nodes "
        "WHEN NEW.retained<>OLD.retained OR NEW.cached<>OLD.cached BEGIN "
        "UPDATE graph_blob_usage SET retained_refs=retained_refs+NEW.retained-OLD.retained,"
        "cached_refs=cached_refs+NEW.cached-OLD.cached WHERE digest=NEW.digest;"
        "INSERT INTO graph_storage_work(parent) SELECT NEW.id WHERE EXISTS "
        "(SELECT 1 FROM graph_edges WHERE parent=NEW.id) "
        "ON CONFLICT(parent) DO UPDATE SET after_child=''; END;"
        "CREATE TRIGGER node_retiring AFTER UPDATE OF retiring ON graph_nodes BEGIN "
        "UPDATE graph_storage_totals SET retiring=retiring+NEW.retiring-OLD.retiring WHERE id=1; END;"
        "CREATE TRIGGER work_insert AFTER INSERT ON graph_storage_work BEGIN "
        "UPDATE graph_storage_totals SET pending=pending+1 WHERE id=1; END;"
        "CREATE TRIGGER work_delete AFTER DELETE ON graph_storage_work BEGIN "
        "UPDATE graph_storage_totals SET pending=pending-1 WHERE id=1; END;"
        "CREATE TRIGGER edge_insert AFTER INSERT ON graph_edges BEGIN "
        "UPDATE graph_nodes SET incoming=incoming+1 WHERE id=NEW.child;"
        "INSERT INTO graph_storage_work(parent) SELECT NEW.parent FROM graph_nodes "
        "WHERE id=NEW.parent AND (retained OR cached) "
        "ON CONFLICT(parent) DO UPDATE SET after_child=''; END;"
        "CREATE TRIGGER edge_apply AFTER UPDATE OF retained,cached ON graph_edges BEGIN "
        "UPDATE graph_nodes SET retained_parents=retained_parents+NEW.retained-OLD.retained,"
        "cached_parents=cached_parents+NEW.cached-OLD.cached WHERE id=NEW.child; END;"
        "CREATE TRIGGER edge_delete AFTER DELETE ON graph_edges BEGIN "
        "UPDATE graph_nodes SET created=CASE WHEN kind='text' AND incoming=1 THEN 0 ELSE created END,"
        "incoming=incoming-1,retained_parents=retained_parents-OLD.retained,"
        "cached_parents=cached_parents-OLD.cached WHERE id=OLD.child; END;"
        + _root_triggers()
        + f"PRAGMA user_version={VERSION};COMMIT;"
    )


def _root_triggers():
    sql = ""
    for table, column in (("graph_object_owners", "owners"), ("graph_cache", "caches")):
        # These are direct roots. Graph propagation is queued, never recursively executed here.
        sql += (
            f"CREATE TRIGGER {table}_validate BEFORE INSERT ON {table} BEGIN "
            "SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM graph_nodes WHERE id=NEW.ref AND retiring=0) "
            "THEN RAISE(ABORT,'Unknown artifact reference') END; END;"
            f"CREATE TRIGGER {table}_insert AFTER INSERT ON {table} BEGIN "
            f"UPDATE graph_nodes SET {column}={column}+1 WHERE id=NEW.ref; END;"
            f"CREATE TRIGGER {table}_delete AFTER DELETE ON {table} BEGIN "
            f"UPDATE graph_nodes SET {column}={column}-1 WHERE id=OLD.ref; END;"
            f"CREATE TRIGGER {table}_update AFTER UPDATE OF ref ON {table} WHEN OLD.ref<>NEW.ref BEGIN "
            "SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM graph_nodes WHERE id=NEW.ref AND retiring=0) "
            "THEN RAISE(ABORT,'Unknown artifact reference') END;"
            f"UPDATE graph_nodes SET {column}={column}-1 WHERE id=OLD.ref;"
            f"UPDATE graph_nodes SET {column}={column}+1 WHERE id=NEW.ref; END;"
        )

    return sql


def validate(connection):
    if connection.execute("PRAGMA user_version").fetchone()[0] != VERSION:
        raise ValueError("Unsupported graph storage version; use a fresh assessment directory")
