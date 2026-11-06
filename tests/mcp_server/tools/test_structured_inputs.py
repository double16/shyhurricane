import json
from typing import get_type_hints

import pytest
from pydantic import TypeAdapter, ValidationError

from shyhurricane.mcp_server.tools.application_graph import find_application_elements, find_application_relationships
from shyhurricane.mcp_server.tools.findings import save_finding
from shyhurricane.mcp_server.tools.register_http_headers import register_http_headers


@pytest.mark.parametrize("tool,field,value,expected", [
    (register_http_headers, "http_headers", {"X-Test": "yes"}, {"X-Test": "yes"}),
    (find_application_elements, "kinds", [" resource "], ["resource"]),
    (find_application_relationships, "kinds", [" FLOWS_TO "], ["FLOWS_TO"]),
    (save_finding, "metadata", {"severity": "high"}, {"severity": "high"}),
])
def test_structured_inputs(tool, field, value, expected):
    adapter = TypeAdapter(get_type_hints(tool, include_extras=True)[field])
    schema = adapter.json_schema()
    assert schema.get("type") != "string"
    assert all(branch.get("type") != "string" for branch in schema.get("anyOf", []))
    for supplied in [value, json.dumps(value)]:
        result = adapter.validate_python(supplied)
        if field == "metadata":
            result = result.model_dump(exclude_none=True)
        assert result == expected
    for invalid in ["{", '"text"', "42", '[1]', '{"severity":"bad"}' if field == "metadata" else "false"]:
        with pytest.raises(ValidationError):
            adapter.validate_python(invalid)
