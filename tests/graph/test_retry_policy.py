"""Only retryable Neo4j failures use automatic graph redelivery."""

import pytest
from neo4j.exceptions import CypherSyntaxError, Neo4jError, ServiceUnavailable, SessionExpired, TransientError

from shyhurricane.graph.retry_policy import transient_neo4j_error


@pytest.mark.parametrize("error,expected", [
    (ServiceUnavailable("down"), True),
    (SessionExpired("session"), True),
    (TransientError("temporary"), True),
    (CypherSyntaxError("syntax"), False),
    (ValueError("input"), False),
    (Neo4jError("unknown"), False),
    (Neo4jError._hydrate_neo4j(code="Neo.ClientError.Transaction.TransactionTimedOut", message="deadline"), True),
    (Neo4jError._hydrate_neo4j(code="Neo.ClientError.General.ForbiddenOnReadOnlyDatabase", message="read only"), True),
    (Neo4jError._hydrate_neo4j(code="Neo.ClientError.Security.Unauthorized", message="invalid credentials"), False),
])
def test_transient_neo4j_error(error, expected):
    assert transient_neo4j_error(error) is expected
