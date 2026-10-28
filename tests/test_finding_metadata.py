"""Producer metadata stays optional, typed, and distinct from verification."""

import pytest
from pydantic import ValidationError

from shyhurricane.finding_metadata import (
    FindingMetadata,
    categories,
    merge_metadata,
    metadata_dict,
    scanner_metadata,
)


def test_optional_metadata_and_normalization():
    assert metadata_dict() == {}
    assert metadata_dict(FindingMetadata()) == {}
    assert metadata_dict({"code_location": {"start_column": 5, "end_column": 2}})
    assert categories({}) == ["unknown"]
    assert metadata_dict({"cwe_ids": None, "affected_method": None, "content_sha256": None}) == {}
    value = metadata_dict(
        {
            "affected_method": " post ",
            "cwe_ids": ["CWE-79", "CWE-79"],
            "content_sha256": "A" * 64,
            "code_location": {"start_line": 2, "end_line": 3},
        }
    )
    assert value["affected_method"] == "POST"
    assert value["content_sha256"] == "a" * 64
    assert value["cwe_ids"] == ["CWE-79"]
    assert categories(value) == ["xss"]
    assert categories({"vulnerability_types": ["authentication"], "cwe_ids": ["CWE-79", "CWE-99999"]}) == [
        "authentication",
        "xss",
    ]


@pytest.mark.parametrize(
    "value",
    [
        {"severity": "urgent"},
        {"confidence": "confirmed"},
        {"verification_status": "certain"},
        {"observed_at": float("inf")},
        {"observed_at": -1},
        {"affected_method": "GET /"},
        {"content_sha256": "invalid"},
        {"cwe_ids": ["79"]},
        {"cwe_ids": ["CWE-0"]},
        {"parameter": {"location": "xml"}},
        {"code_location": {"start_line": True}},
        {"code_location": {"start_line": 0}},
        {"code_location": {"start_line": 3, "end_line": 2}},
        {"code_location": {"start_line": 2, "end_line": 2, "start_column": 5, "end_column": 2}},
        {"code_location": {"start_line": 2, "start_column": 5, "end_column": 2}},
        {"unexpected": 1},
        {"vulnerability_types": ["prose"]},
    ],
)
def test_invalid_metadata(value):
    with pytest.raises(ValidationError):
        metadata_dict(value)


def test_missing_nested_fields_can_be_filled_without_mutating_original():
    saved = {"parameter": {"name": "q"}, "confidence": "unknown"}
    merged, conflicts = merge_metadata(
        saved, {"parameter": {"name": "q", "location": "query"}, "confidence": "high", "severity": None}
    )
    assert merged == {"parameter": {"name": "q", "location": "query"}, "confidence": "high"}
    assert saved["parameter"] == {"name": "q"}
    assert conflicts == []
    merged, conflicts = merge_metadata(merged, {"parameter": {"name": "different"}})
    assert merged["parameter"]["name"] == "q"
    assert conflicts == [{"field": "parameter.name", "retained": "q", "submitted": "different"}]
    assert merge_metadata(merged, {"parameter": {"name": "different"}}, conflicts)[1] == conflicts


@pytest.mark.parametrize(
    "source,label,expected",
    [
        ("opengrep", "ERROR", "high"),
        ("opengrep", "WARNING", "medium"),
        ("opengrep", "INFO", "informational"),
        ("nuclei", "critical", "critical"),
        ("nuclei", "unexpected", "unknown"),
        ("nuclei", "warning", "unknown"),
    ],
)
def test_scanner_mapping(source, label, expected):
    result = scanner_metadata(source, "rule", label, cwes=["CWE-79: XSS", "none"])
    assert result["severity"] == expected
    assert result["native_severity"] == label
    assert result["verification_status"] == "unverified"
    assert result["cwe_ids"] == ["CWE-79"]
