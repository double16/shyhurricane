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


@pytest.mark.parametrize("rule,expected", [
    ("2097920", "xss"), ("2097408", "xss"), ("2097936", "xss"), ("2097928", "injection"),
])
def test_burp_rule_categories_have_explicit_provenance(rule, expected):
    from shyhurricane.finding_metadata import category_basis
    metadata = {"source": "burp", "rule_id": rule}
    assert categories(metadata) == [expected]
    assert category_basis(metadata) == [
        {"category": expected, "basis": "scanner_rule", "source": "burp", "value": rule}
    ]
    assert categories({**metadata, "source": "zap"}) == ["unknown"]
    assert categories({**metadata, "cwe_ids": ["CWE-918"]}) == ["ssrf"]
    assert categories({**metadata, "vulnerability_types": ["configuration"]}) == ["configuration"]
    assert categories({"source": "burp", "rule_id": "9999999"}) == ["unknown"]


def test_every_allowlisted_rule_is_source_specific():
    from shyhurricane.finding_metadata import SCANNER_CATEGORIES
    for (source, rule), category in SCANNER_CATEGORIES.items():
        assert categories({"source": source, "rule_id": rule}) == [category]
        assert categories({"source": "custom", "rule_id": rule}) == ["unknown"]


@pytest.mark.parametrize("rule,category", [
    ("1049600", "injection"), ("2097664", "injection"), ("2097942", "injection"),
    ("5243392", "configuration"), ("5243008", "dependency"),
])
def test_additional_reviewed_burp_rules(rule, category):
    from shyhurricane.finding_metadata import categories
    assert categories({"source": "burp", "rule_id": rule}) == [category]
    assert categories({"source": "zap", "rule_id": rule}) == ["unknown"]
    assert categories({"source": "burp", "rule_id": rule, "vulnerability_types": ["xss"]}) == ["xss"]


@pytest.mark.parametrize("cwe,expected", [
    ("CWE-80", "xss"), ("CWE-90", "injection"), ("CWE-502", "injection"),
    ("CWE-22", "access_control"), ("CWE-352", "access_control"),
    ("CWE-307", "authentication"), ("CWE-1004", "configuration"),
    ("CWE-532", "exposure"), ("CWE-327", "cryptography"), ("CWE-1395", "dependency"),
])
def test_expanded_web_cwe_categories(cwe, expected):
    from shyhurricane.finding_metadata import category_basis
    assert category_basis({"cwe_ids": [cwe]}) == [
        {"category": expected, "basis": "cwe", "value": cwe}
    ]


@pytest.mark.parametrize("cwe", ["CWE-119", "CWE-400", "CWE-1344", "CWE-937", "CWE-99999"])
def test_unclassified_weaknesses_and_views(cwe):
    assert categories({"cwe_ids": [cwe]}) == ["unknown"]


def test_catalog_categories_are_valid():
    from shyhurricane.finding_metadata import CWE_TYPES, SCANNER_CATEGORIES, VULNERABILITY_TYPES
    assert set(CWE_TYPES.values()) <= set(VULNERABILITY_TYPES) - {"unknown"}
    assert set(SCANNER_CATEGORIES.values()) <= set(VULNERABILITY_TYPES) - {"unknown"}
    for cwe, expected in CWE_TYPES.items():
        assert categories({"cwe_ids": [cwe]}) == [expected]
