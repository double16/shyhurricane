"""Resource inventory, progressive validation and incomplete-result contracts."""

from copy import deepcopy

import pytest
from neo4j.exceptions import Neo4jError
from test_indexed_queries import IndexedStore

from shyhurricane.graph import inventory
from shyhurricane.graph.budget import QueryBudget
from shyhurricane.graph.extract import extract
from shyhurricane.graph.lookup import reverse_host
from shyhurricane.graph.query import GraphQuery


class InventoryStore(IndexedStore):
    def __init__(self, graph):
        super().__init__(graph)
        self.hidden = set()
        self.fail_stage = None
        self.fail_call = 1
        self.stage_calls = {}
        self.error = TimeoutError("slow read")
        self.lookup_ready = True
        self.index_state = "ONLINE"

    def read(self, statement, **parameters):
        if not statement.startswith("/* inventory:"):
            if "traversal:lookup-state" in statement and not self.lookup_ready:
                self.calls.append((statement, parameters))
                return [{"ready": False}]
            return super().read(statement, **parameters)
        self.calls.append((statement, parameters))
        stage = statement.split("*/", 1)[0].split(":", 1)[1].strip()
        self.stage_calls[stage] = self.stage_calls.get(stage, 0) + 1
        if stage == self.fail_stage and self.stage_calls[stage] == self.fail_call:
            raise self.error
        if stage == "indexes":
            return [{"state": self.index_state}] if self.index_state else []
        if stage == "candidates":
            field = "_reverse_host" if "kind,_reverse_host,id" in statement else "url"
            exact = f"n.{field} = $value" in statement
            records = []
            for node in self.graph.nodes.values():
                value = node["url"] if field == "url" else reverse_host(node["url"])
                if node["kind"] != "resource":
                    continue
                if not (value == parameters["value"] if exact else value.startswith(parameters["value"])):
                    continue
                if (value, node["id"]) <= (parameters["after_value"], parameters["after"]):
                    continue
                records.append({"id": node["id"], "logical_id": node.get("_logical_id", node["id"]),
                                "url": node["url"], "cursor": value})
            return sorted(records, key=lambda row: (row["cursor"], row["id"]))[:parameters["limit"]]
        if stage == "validate":
            return [{"seed": self.graph.nodes[key]} for key in parameters["ids"]
                    if key not in self.hidden and self.matches(self.graph.nodes[key], parameters)]
        assert stage == "capture-status"
        return [{"id": resource["id"], "captured": any(
            self.graph.nodes[edge["source"]].get("_logical_id", edge["source"]) == resource["id"]
            and edge["kind"] == "HOSTED_AT" and edge["classification"] == "observed"
            for edge in self.graph.edges.values()
        )} for resource in parameters["resources"]]


@pytest.fixture
def store(event):
    graph = extract(event(body='<form action="/save" method="post"><input name="name"></form>'
                               '<script src="/app.js"></script>'))
    return InventoryStore(graph)


def test_inventory_defaults_and_focused_followups(store):
    result = GraphQuery(store).endpoints("example.com", historical=True, as_of=42)
    assert result["results"] and not result["retrieval_truncated"]
    assert {node["capture_status"] for node in result["results"]} == {"captured", "referenced"}
    for row in result["results"]:
        assert set(row) == {"id", "url", "method", "capture_status", "follow_up"}
        assert row["follow_up"] == [{"tool": "find_application_endpoints", "arguments": {
            "scope": "example.com", "url": row["url"], "method": row["method"],
            "historical": True, "as_of": 42, "detail": "summary",
        }}]
    assert "uncomputed, not zero" in result["instructions"]
    assert not any("traversal:context" in query or "hydrate" in query for query, _ in store.calls)
    for query, parameters in store.calls:
        assert parameters["timeout"] <= 5
        if "inventory:candidates" in query:
            assert "EXISTS" not in query and "LIMIT $limit" in query
        if "inventory:validate" in query:
            assert len(parameters["ids"]) <= inventory.VALIDATION_SIZE
            assert parameters["revision"] == 0 and parameters["historical"] is True
            assert parameters["as_of"] == 42 and "published_revision" in query


@pytest.mark.parametrize("scope,url,method,expected", [
    ("example.com", None, "POST", ["https://example.com/save"]),
    ("example.com", None, "delete", []),
    ("example.com:8443", None, None, []),
    ("https://example.com/page", None, None, ["https://example.com/page"]),
    ("example.com", "https://example.com/page", "get", ["https://example.com/page"]),
    ("example.com", "https://other.test/page", None, []),
    ("example.com", "https://example.com/missing", None, []),
    ("unrelated.test", None, None, []),
])
def test_inventory_scope_and_filters(store, scope, url, method, expected):
    result = GraphQuery(store).endpoints(scope, url=url, method=method)
    assert sorted(node["url"] for node in result["results"]) == expected


def test_inventory_excludes_context_only_external_urls_and_hidden_nodes(store):
    resource = next(node for node in store.graph.nodes.values() if node["kind"] == "resource")
    resource["url"] = "https://cdn.other.test/app.js"
    resource["context_urls"] = ["https://example.com/page"]
    store.hidden.update(key for key, node in store.graph.nodes.items() if node["kind"] == "resource")
    assert GraphQuery(store).endpoints("example.com")["results"] == []
    assert not any("GraphContext" in query for query, _ in store.calls)


@pytest.mark.parametrize("stage,completed", [("candidates", False), ("validate", False), ("capture-status", True)])
def test_timeouts_preserve_validated_records(store, stage, completed):
    store.fail_stage = stage
    result = GraphQuery(store).endpoints("example.com")
    assert bool(result["results"]) is completed
    reason = "classification_limit" if stage == "capture-status" else "time_limit"
    assert result["retrieval_truncated"] and reason in result["truncation_reasons"]
    assert all(row["capture_status"] == "unknown" for row in result["results"])


def test_later_candidate_timeout_preserves_completed_page(store, monkeypatch):
    monkeypatch.setattr(inventory, "PAGE_SIZE", 1)
    store.fail_stage, store.fail_call = "candidates", 2
    result = GraphQuery(store).endpoints("example.com")
    assert len(result["results"]) == 1
    assert result["results"][0]["capture_status"] != "unknown"
    assert "time_limit" in result["truncation_reasons"]


@pytest.mark.parametrize("code,reason", [
    ("Neo.ClientError.Transaction.TransactionTimedOut", "time_limit"),
    ("Neo.TransientError.General.MemoryPoolOutOfMemoryError", "memory_limit"),
])
def test_inventory_database_limits(store, code, reason):
    store.fail_stage = "validate"
    store.error = Neo4jError._hydrate_neo4j(code=code, message="bounded read")
    result = GraphQuery(store).endpoints("example.com")
    assert reason in result["truncation_reasons"]
    assert result["results"] == []


def test_unrelated_database_errors_propagate(store):
    store.fail_stage = "candidates"
    store.error = Neo4jError._hydrate_neo4j(code="Neo.ClientError.Statement.SyntaxError", message="syntax")
    with pytest.raises(Neo4jError):
        GraphQuery(store).endpoints("example.com")


@pytest.mark.parametrize("cap,reason", [("RESULT_LIMIT", "result_limit"), ("SCAN_LIMIT", "scan_limit")])
def test_inventory_caps(store, monkeypatch, cap, reason):
    monkeypatch.setattr(inventory, cap, 1)
    result = GraphQuery(store).endpoints("example.com")
    assert len(result["results"]) == 1
    assert reason in result["truncation_reasons"]


def test_lookup_pending_does_not_fall_back_to_expensive_snapshot(store):
    store.lookup_ready = False
    result = GraphQuery(store).endpoints("example.com")
    assert result["results"] == []
    assert result["truncation_reasons"] == ["lookup_unavailable"]
    assert not any("inventory:" in query for query, _ in store.calls)


@pytest.mark.parametrize("state", [None, "POPULATING"])
def test_inventory_waits_for_resource_index_without_broad_fallback(store, state):
    store.index_state = state
    result = GraphQuery(store).endpoints("example.com")
    assert result["results"] == []
    assert result["truncation_reasons"] == ["lookup_unavailable"]
    assert "candidates" not in store.stage_calls


def test_inventory_uses_shared_30_second_budget(store):
    budget = QueryBudget(seconds=120)
    GraphQuery(store, budget=budget).endpoints("example.com")
    assert budget.deadline == budget.started + 30
    budget.deadline = budget.started - 1
    result = GraphQuery(store, budget=budget).endpoints("example.com")
    assert "time_limit" in result["truncation_reasons"]


def test_duplicate_versions_share_id_and_captured_status(store):
    captured = next(edge["source"] for edge in store.graph.edges.values() if edge["kind"] == "HOSTED_AT")
    original = store.graph.nodes[captured]
    duplicate = deepcopy(original)
    duplicate.update(id="version-copy", _logical_id=captured)
    store.graph.nodes[duplicate["id"]] = duplicate
    result = GraphQuery(store).endpoints("example.com")
    rows = [row for row in result["results"] if row["id"] == captured]
    assert len(rows) == 1 and rows[0]["capture_status"] == "captured"


def test_invalid_detail_rejected(store):
    with pytest.raises(ValueError, match="inventory or summary"):
        GraphQuery(store).endpoints("example.com", detail="full")


def test_duplicate_storage_pages_are_not_revalidated(store, monkeypatch):
    monkeypatch.setattr(inventory, "PAGE_SIZE", 1)
    resource = next(node for node in store.graph.nodes.values() if node["kind"] == "resource")
    original = deepcopy(resource)
    store.graph.nodes.clear()
    for index in range(5):
        version = {**original, "id": str(index), "_logical_id": original["id"]}
        store.graph.nodes[version["id"]] = version
    store.graph.edges.clear()
    result = GraphQuery(store).endpoints("example.com")
    assert len(result["results"]) == 1
    assert store.stage_calls["validate"] == store.stage_calls["capture-status"] == 1


def test_duplicate_reference_is_captured_through_another_visible_version(store, monkeypatch):
    monkeypatch.setattr(inventory, "PAGE_SIZE", 1)
    captured = next(edge["source"] for edge in store.graph.edges.values() if edge["kind"] == "HOSTED_AT")
    original = store.graph.nodes[captured]
    duplicate = {**original, "id": "000", "_logical_id": captured}
    store.graph.nodes[duplicate["id"]] = duplicate
    result = GraphQuery(store).endpoints("example.com")
    rows = [row for row in result["results"] if row["id"] == captured]
    assert len(rows) == 1 and rows[0]["capture_status"] == "captured"


def test_optional_classification_timeout_does_not_stop_resource_selection(store, monkeypatch):
    monkeypatch.setattr(inventory, "PAGE_SIZE", 1)
    store.fail_stage = "capture-status"
    result = GraphQuery(store).endpoints("example.com")
    assert len(result["results"]) >= 3
    assert store.stage_calls["capture-status"] == 1
    assert "classification_limit" in result["truncation_reasons"]
    assert all(row["capture_status"] == "unknown" for row in result["results"])
