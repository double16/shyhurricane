"""Bounded native inventory hydration, status overlays, and continuation validation."""

from unittest.mock import MagicMock

import pytest

from shyhurricane.graph import inventory_reader
from shyhurricane.graph.inventory_reader import InventoryReader
from shyhurricane.graph.inventory_scope import inventory_filters, scope_parameters, url_properties


def fact(key="one", kind="symbol", **values):
    return {"manifest_id": key, "generation": "generation", "unit_id": "unit", "capture_id": "capture",
            "oversized": False, "logical_id": key, "kind": kind, "url": "https://example.com/", "method": "GET",
            "shard": key, "position": 0, "discovery": "complete", "flow": "partial", "artifact": "a:ir",
            "error": "", "materialization": "deferred", "captured": False, "status": None, **values}


def reader(rows=(), payloads=None, states=()):
    calls = []
    states = {row["generation"]: row["state"] for row in states}
    rows = [{**row, "status": states.get(row.get("generation"))} for row in rows]

    def read(statement, **parameters):
        calls.append((statement, parameters))
        if "CREATE (p:GraphInventoryReadPin" in statement:
            return [{"revision": 7}]
        if "RETURN p.id AS id" in statement:
            return [{"id": "pin"}]
        return rows

    shards = MagicMock()
    payloads = payloads or {row["shard"]: [{"id": row["logical_id"], "manifest_id": row["manifest_id"],
                                         "kind": row["kind"], "url": row["url"], "_context_ids": ["private"]}]
                            for row in rows if "shard" in row}
    shards.read_record.side_effect = lambda reference, position, **kwargs: payloads[reference][position]
    return InventoryReader(read, shards), calls


def test_watermark_snapshot_and_expiry():
    obj, calls = reader()
    pin = obj.watermark()
    assert pin["revision"] == 7 and pin["pin"] and pin["expires"] > 0
    assert calls[0][1]["access_mode"] == "WRITE"
    assert obj.snapshot(pin) == pin
    assert obj.snapshot(None)["revision"] == 7
    with pytest.raises(ValueError, match="no generation pin"):
        obj.snapshot({"revision": 7})
    obj.read = lambda *args, **kwargs: []
    with pytest.raises(ValueError, match="expired"):
        obj.snapshot(pin)
    with pytest.raises(ValueError, match="revision state"):
        obj.watermark()


def test_filters_paging_and_shared_shard_cache():
    rows = [fact("one"), fact("two", shard="one", position=1), fact("three")]
    payloads = {"one": [{"manifest_id": key, "id": key, "kind": "symbol"} for key in ("one", "two")]}
    obj, calls = reader(rows, payloads)
    result, cursor = obj.page("example.com", kinds=["symbol"], exclude_kinds=["resource"], role="source",
                              url="https://example.com/", method="post", capture_id="capture", unit_id="unit", limit=2)
    assert [row["id"] for row in result] == ["one", "two"] and cursor == "two"
    assert obj.shards.read_record.call_count == 2
    sql, parameters = next(call for call in calls if "RETURN f.manifest_id" in call[0])
    assert "f.unit_id=$unit_id" in sql and "NOT f.kind IN $excluded" in sql
    assert parameters["method"] == "POST" and parameters["limit"] == 3
    for limit in (0, 1001):
        with pytest.raises(ValueError):
            obj.page("example.com", limit=limit)


def test_resource_and_analysis_status_and_oversized_stub():
    obj, _ = reader([fact("resource", "resource", oversized=True, captured=True), fact("unit", "analysis_unit")],
                    states=[{"generation": "generation", "state": {"discovery": "failed", "flow": "failed",
                             "materialization": "failed", "error": "publication failed"}}])
    result, cursor = obj.page("example.com")
    assert cursor is None
    assert result[0]["oversized"] and result[0]["capture_status"] == "captured"
    assert result[0]["follow_up"]["arguments"]["url"] == "https://example.com/"
    assert result[1]["discovery"] == result[1]["materialization"] == "failed"
    assert result[1]["expandable"] and result[1]["error"] == "publication failed"
    assert "_context_ids" not in result[1]
    obj, calls = reader([fact("resource", "resource")])
    assert obj.page("example.com", kind="resource", context_url="https://example.com/")[0][0]["capture_status"] == "referenced"
    sql = next(sql for sql, _ in calls if "RETURN f.manifest_id" in sql)
    assert "UNION" not in sql


@pytest.mark.parametrize("change,match", [({"position": -1}, "position"), ({"position": 4}, "position"),
                                        ({"manifest_id": "mismatch"}, "identity")])
def test_corrupt_positions_and_identity_are_errors(change, match):
    obj, _ = reader([fact(**change)], {"one": [{"manifest_id": "one", "kind": "symbol"}]})
    if "position" in change:
        obj.shards.read_record.side_effect = ValueError("Invalid shard position")
    with pytest.raises(ValueError, match=match):
        obj.page("example.com")


def test_hydration_deadline_retains_only_completed_rows():
    obj, _ = reader([fact("one"), fact("two")])
    obj.check = MagicMock(side_effect=[None, TimeoutError("deadline")])
    result, cursor = obj.page("example.com")
    assert [row["id"] for row in result] == ["one"] and cursor == "one"
    obj.check = MagicMock(side_effect=TimeoutError("deadline"))
    with pytest.raises(TimeoutError):
        obj.page("example.com")


def test_byte_limits_and_empty_pages(monkeypatch):
    obj, _ = reader([fact("one"), fact("two")])
    monkeypatch.setattr(inventory_reader, "PAGE_BYTES", 150)
    result, cursor = obj.page("example.com")
    assert [row["id"] for row in result] == ["one"] and cursor == "one"
    monkeypatch.setattr(inventory_reader, "PAGE_BYTES", 1)
    assert obj.page("example.com")[0][0]["oversized"]
    obj, _ = reader()
    assert obj.page("example.com") == ([], None)


@pytest.mark.parametrize("status", ["failed", "blocked", "pending", "partial", "complete"])
def test_coverage_precedence_and_lookup(status):
    obj, _ = reader([{"unit_id": "one", "discovery": status, "flow": "complete"},
                     {"unit_id": "two", "discovery": "complete", "flow": "complete"}])
    assert obj.coverage(scope="example.com") == {"discovery": status, "flow": "complete", "units": 2}
    assert obj.coverage("capture")["units"] == 2
    assert obj.lookup_unit("example.com", "unit", "capture")["unit_id"] == "one"
    obj, _ = reader()
    assert obj.coverage()["discovery"] == "pending"
    assert obj.lookup_unit("example.com", "unit", "capture") is None


def test_scope_and_optional_filters():
    assert url_properties("https://app.example.com:8443/path")["port"] == 8443
    assert url_properties("http://example.com")["path"] == "/"
    assert scope_parameters("https://example.com/p")["scope_path"] == "/p"
    assert scope_parameters("example.com")["scope_subdomains"]
    assert scope_parameters("[2001:db8::1]:8443")["scope_host"] == "2001:db8::1"
    assert inventory_filters(kind="field", method=" post ")["method"] == "POST"
    assert inventory_filters(role="  ", url="", method="\t")["role"] is None
    with pytest.raises(ValueError):
        scope_parameters("ftp://example.com")
