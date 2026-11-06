"""Validate the shared query expansion contract without replacing model responses."""
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from shyhurricane.structured_generation import QueryExpansion, query_expansion_schema


@pytest.mark.parametrize("value", [{"queries": {"x": "y"}}, {"queries": [1]}, {"queries": [], "extra": 1}])
def test_invalid_shape(value):
    with pytest.raises(ValidationError):
        QueryExpansion.model_validate(value)


def test_multiline():
    assert QueryExpansion.model_validate_json('{"queries":["a\\nb"]}').queries == ["a\nb"]


def test_static_assets():
    for path in Path("shyhurricane/assets/query").glob("*.yaml"):
        result = QueryExpansion.model_validate(yaml.safe_load(path.read_text()))
        assert result.queries, path
        assert all(query.strip() for query in result.queries), path


def test_empty_expansion_is_valid():
    assert QueryExpansion.model_validate_json('{"queries": []}').queries == []


def test_invalid_json_is_rejected():
    with pytest.raises(ValidationError):
        QueryExpansion.model_validate_json("not JSON")


@pytest.mark.parametrize("length", [255, 256])
def test_pattern_length_boundary_accepted(length):
    pattern = "x" * length
    assert QueryExpansion.model_validate({"queries": [pattern]}).queries == [pattern]


def test_overlong_pattern_rejected():
    with pytest.raises(ValidationError):
        QueryExpansion.model_validate({"queries": ["x" * 257]})


def test_schema_exposes_pattern_length_limit():
    schema = QueryExpansion.model_json_schema()
    assert schema["properties"]["queries"]["items"]["maxLength"] == 256


@pytest.mark.parametrize("limit", [0, 1, 3, 10])
def test_generation_count_boundary(limit):
    schema = query_expansion_schema(limit)
    assert schema.model_validate({"queries": ["x"] * limit}).queries == ["x"] * limit
    assert schema.model_validate({"queries": []}).queries == []
    with pytest.raises(ValidationError):
        schema.model_validate({"queries": ["x"] * (limit + 1)})
    properties = schema.model_json_schema()["properties"]["queries"]
    assert properties["maxItems"] == limit
    assert properties["items"]["maxLength"] == 256


def test_bounded_count_keeps_pattern_length_validation():
    with pytest.raises(ValidationError):
        query_expansion_schema(3).model_validate({"queries": ["x" * 257]})
