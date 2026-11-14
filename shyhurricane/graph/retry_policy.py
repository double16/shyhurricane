"""Classify Neo4j failures consistently across graph processing paths."""

import sqlite3

from neo4j.exceptions import Neo4jError, ServiceUnavailable, SessionExpired


def transient_neo4j_error(error):
    """Retain connection, transient-server, transaction-timeout, and read-only failures."""
    if isinstance(error, sqlite3.Error):
        return (getattr(error, "sqlite_errorcode", 0) & 255) in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)
    if isinstance(error, (ServiceUnavailable, SessionExpired)):
        return True
    if not isinstance(error, Neo4jError):
        return False
    code = error.code or ""
    return error.is_retryable() or "TransactionTimedOut" in code or "ReadOnly" in code
