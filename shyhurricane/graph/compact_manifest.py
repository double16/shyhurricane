"""Normalized manifest storage; views expose stable public identifiers to graph queries."""

from shyhurricane.graph.blob_store import owner_triggers


def initialize(connection):
    connection.executescript(
        "CREATE TABLE IF NOT EXISTS graph_terms (key INTEGER PRIMARY KEY,value TEXT NOT NULL UNIQUE);"
        "CREATE TABLE IF NOT EXISTS graph_facts (seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,"
        "unit INTEGER NOT NULL,capture INTEGER NOT NULL,kind_key INTEGER NOT NULL,url_key INTEGER NOT NULL,"
        "host_key INTEGER NOT NULL,role_key INTEGER NOT NULL,data TEXT NOT NULL,method TEXT NOT NULL,"
        "captured INTEGER NOT NULL);"
        "CREATE INDEX IF NOT EXISTS graph_manifest_scope ON graph_facts(host_key,kind_key,id);"
        "CREATE INDEX IF NOT EXISTS graph_manifest_kind ON graph_facts(kind_key,id);"
        "CREATE INDEX IF NOT EXISTS graph_manifest_url ON graph_facts(url_key,id);"
        "CREATE INDEX IF NOT EXISTS graph_manifest_unit ON graph_facts(unit,id);"
        "CREATE VIEW IF NOT EXISTS graph_manifest_facts AS SELECT f.seq AS rowid,f.id,u.value AS unit_id,"
        "c.value AS capture_id,k.value AS kind,url.value AS url,h.value AS host,r.value AS role,"
        "f.data,f.method,f.captured FROM graph_facts f "
        "JOIN graph_terms u ON u.key=f.unit JOIN graph_terms c ON c.key=f.capture "
        "JOIN graph_terms k ON k.key=f.kind_key JOIN graph_terms url ON url.key=f.url_key "
        "JOIN graph_terms h ON h.key=f.host_key JOIN graph_terms r ON r.key=f.role_key;"
        "CREATE TABLE IF NOT EXISTS graph_context_documents (key INTEGER PRIMARY KEY,"
        "context INTEGER NOT NULL,url_key INTEGER NOT NULL,host_key INTEGER NOT NULL,data TEXT NOT NULL UNIQUE);"
        "CREATE INDEX IF NOT EXISTS graph_context_identity ON graph_context_documents(context);"
        "CREATE TABLE IF NOT EXISTS graph_context_members (seq INTEGER PRIMARY KEY AUTOINCREMENT,"
        "unit INTEGER NOT NULL,document INTEGER NOT NULL,UNIQUE(unit,document));"
        "CREATE VIEW IF NOT EXISTS graph_unit_contexts AS SELECT m.seq AS rowid,u.value AS unit_id,"
        "c.value AS context_id,url.value AS url,h.value AS host,d.data FROM graph_context_members m "
        "JOIN graph_context_documents d ON d.key=m.document JOIN graph_terms u ON u.key=m.unit "
        "JOIN graph_terms c ON c.key=d.context JOIN graph_terms url ON url.key=d.url_key "
        "JOIN graph_terms h ON h.key=d.host_key;"
        "CREATE TABLE IF NOT EXISTS graph_fact_contexts (seq INTEGER PRIMARY KEY AUTOINCREMENT,"
        "fact INTEGER NOT NULL,context INTEGER NOT NULL,UNIQUE(fact,context));"
        "CREATE VIEW IF NOT EXISTS graph_manifest_contexts AS SELECT m.seq AS rowid,"
        "f.id AS fact_id,c.value AS context_id FROM graph_fact_contexts m "
        "JOIN graph_facts f ON f.seq=m.fact JOIN graph_terms c ON c.key=m.context;"
        "CREATE TABLE IF NOT EXISTS graph_parents (seq INTEGER PRIMARY KEY AUTOINCREMENT,"
        "unit INTEGER NOT NULL UNIQUE,parent INTEGER NOT NULL);"
        "CREATE INDEX IF NOT EXISTS graph_unit_parent ON graph_parents(parent);"
        "CREATE VIEW IF NOT EXISTS graph_unit_parents AS SELECT p.seq AS rowid,"
        "u.value AS unit_id,v.value AS parent_id FROM graph_parents p "
        "JOIN graph_terms u ON u.key=p.unit JOIN graph_terms v ON v.key=p.parent;"
    )
    owner_triggers(connection, "graph_facts", "data", "seq")
    owner_triggers(connection, "graph_context_documents", "data", "key")
    owner_triggers(connection, "graph_manifest_units", "artifact", "id")


def term(connection, value):
    connection.execute("INSERT OR IGNORE INTO graph_terms(value) VALUES (?)", (value,))
    return connection.execute("SELECT key FROM graph_terms WHERE value=?", (value,)).fetchone()[0]
