"""Normalized manifest storage; views expose stable public identifiers to graph queries."""

from shyhurricane.graph.blob_store import owner_triggers


def initialize(connection):
    connection.executescript(
        "CREATE TABLE IF NOT EXISTS graph_terms (key INTEGER PRIMARY KEY,value TEXT NOT NULL UNIQUE);"
        "CREATE TABLE IF NOT EXISTS graph_context_documents (key INTEGER PRIMARY KEY,"
        "context INTEGER NOT NULL,url_key INTEGER NOT NULL,host_key INTEGER NOT NULL,data TEXT NOT NULL UNIQUE);"
        "CREATE INDEX IF NOT EXISTS graph_context_identity ON graph_context_documents(context);"
        "CREATE TABLE IF NOT EXISTS graph_context_members (seq INTEGER PRIMARY KEY AUTOINCREMENT,"
        "unit INTEGER NOT NULL,document INTEGER NOT NULL,UNIQUE(unit,document));"
        "CREATE INDEX IF NOT EXISTS graph_context_work ON graph_context_members(unit,seq);"
        "CREATE VIEW IF NOT EXISTS graph_unit_contexts AS SELECT m.seq AS rowid,u.value AS unit_id,"
        "c.value AS context_id,url.value AS url,h.value AS host,d.data FROM graph_context_members m "
        "JOIN graph_context_documents d ON d.key=m.document JOIN graph_terms u ON u.key=m.unit "
        "JOIN graph_terms c ON c.key=d.context JOIN graph_terms url ON url.key=d.url_key "
        "JOIN graph_terms h ON h.key=d.host_key;"
        "CREATE TABLE IF NOT EXISTS graph_parents (seq INTEGER PRIMARY KEY AUTOINCREMENT,"
        "unit INTEGER NOT NULL UNIQUE,parent INTEGER NOT NULL);"
        "CREATE INDEX IF NOT EXISTS graph_unit_parent ON graph_parents(parent);"
        "CREATE VIEW IF NOT EXISTS graph_unit_parents AS SELECT p.seq AS rowid,"
        "u.value AS unit_id,v.value AS parent_id FROM graph_parents p "
        "JOIN graph_terms u ON u.key=p.unit JOIN graph_terms v ON v.key=p.parent;"
    )
    owner_triggers(connection, "graph_context_documents", "data", "key")
    owner_triggers(connection, "graph_manifest_units", "artifact", "id")


def term(connection, value):
    connection.execute("INSERT OR IGNORE INTO graph_terms(value) VALUES (?)", (value,))
    return connection.execute("SELECT key FROM graph_terms WHERE value=?", (value,)).fetchone()[0]
