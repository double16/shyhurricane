"""Optional producer evidence shared by finding ingestion and deterministic correlation."""

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

VULNERABILITY_TYPES = (
    "xss",
    "access_control",
    "authentication",
    "injection",
    "ssrf",
    "configuration",
    "exposure",
    "cryptography",
    "dependency",
    "unknown",
)
CWE_TYPES = {
    "CWE-79": "xss",
    "CWE-89": "injection",
    "CWE-78": "injection",
    "CWE-94": "injection",
    "CWE-918": "ssrf",
    "CWE-639": "access_control",
    "CWE-862": "access_control",
    "CWE-863": "access_control",
    "CWE-287": "authentication",
    "CWE-384": "authentication",
    "CWE-200": "exposure",
    "CWE-798": "exposure",
    "CWE-942": "configuration",
}


class EvidenceModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class FindingParameter(EvidenceModel):
    name: str | None = None
    location: Literal["query", "body", "path", "header", "cookie", "fragment", "unknown"] | None = None


class CodeLocation(EvidenceModel):
    source_path: str | None = None
    start_line: StrictInt | None = Field(None, ge=1)
    end_line: StrictInt | None = Field(None, ge=1)
    start_column: StrictInt | None = Field(None, ge=1)
    end_column: StrictInt | None = Field(None, ge=1)
    coordinate_space: Literal["delivered", "recovered", "unknown"] | None = None

    @model_validator(mode="after")
    def ordered(self):
        if self.start_line and self.end_line and self.end_line < self.start_line:
            raise ValueError("end_line must not precede start_line")
        if (
            self.start_line
            and self.end_line in (None, self.start_line)
            and self.start_column
            and self.end_column
            and self.end_column < self.start_column
        ):
            raise ValueError("end_column must not precede start_column")
        return self


class FindingMetadata(EvidenceModel):
    source: str | None = None
    source_finding_id: str | None = None
    rule_id: str | None = None
    severity: Literal["informational", "low", "medium", "high", "critical", "unknown"] | None = None
    confidence: Literal["low", "medium", "high", "unknown"] | None = None
    native_severity: str | None = None
    native_confidence: str | None = None
    verification_status: Literal["confirmed", "suspected", "unverified", "false_positive"] | None = None
    cwe_ids: list[str] | None = None
    vulnerability_types: (
        list[
            Literal[
                "xss",
                "access_control",
                "authentication",
                "injection",
                "ssrf",
                "configuration",
                "exposure",
                "cryptography",
                "dependency",
                "unknown",
            ]
        ]
        | None
    ) = None
    affected_method: str | None = None
    parameter: FindingParameter | None = None
    code_location: CodeLocation | None = None
    capture_id: str | None = None
    content_sha256: str | None = None
    observed_at: float | None = Field(None, ge=0, allow_inf_nan=False)

    @field_validator("cwe_ids")
    @classmethod
    def cwes(cls, values):
        if values is None:
            return values
        if any(not re.fullmatch(r"CWE-[1-9][0-9]*", value) for value in values):
            raise ValueError("use canonical CWE identifiers, such as CWE-79")
        return sorted(set(values))

    @field_validator("affected_method")
    @classmethod
    def method(cls, value):
        if value is not None:
            value = value.upper()
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Z-]+", value):
                raise ValueError("affected_method must be an HTTP token")
        return value

    @field_validator("content_sha256")
    @classmethod
    def digest(cls, value):
        if value is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            raise ValueError("content_sha256 must be a SHA-256 hex digest")
        return value.lower() if value else value


def metadata_dict(value=None):
    """Validate at every producer boundary; omit unavailable fields on the wire."""
    model = value if isinstance(value, FindingMetadata) else FindingMetadata.model_validate(value or {})
    return model.model_dump(exclude_none=True)


def merge_metadata(saved, incoming, conflicts=None):
    """Fill missing leaf values, retaining provenance instead of silently overwriting conflicts."""
    result = dict(saved)
    conflicts = list(conflicts or [])

    def merge(destination, addition, prefix=""):
        for key, value in addition.items():
            path = f"{prefix}.{key}" if prefix else key
            if value in (None, "", [], {}) or value == "unknown":
                continue
            previous = destination.get(key)
            if previous in (None, "", [], {}, "unknown"):
                destination[key] = value
            elif isinstance(value, dict) and isinstance(previous, dict):
                nested = dict(previous)
                merge(nested, value, path)
                destination[key] = nested
            elif previous != value:
                conflict = {"field": path, "retained": previous, "submitted": value}
                if conflict not in conflicts:
                    conflicts.append(conflict)

    merge(result, incoming)
    return result, conflicts


def categories(metadata):
    """Only producer-supplied categories and explicit CWE mappings drive rules."""
    return sorted(
        set(metadata.get("vulnerability_types") or [])
        | {CWE_TYPES[cwe] for cwe in metadata.get("cwe_ids", []) if cwe in CWE_TYPES}
    ) or ["unknown"]


def scanner_metadata(source, rule_id, severity, *, cwes=()):
    """Normalize known scanner severities without equating confidence with verification."""
    mapping = {
        "info": "informational",
        "informational": "informational",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    }
    if source == "opengrep":
        mapping.update(error="high", warning="medium")
    valid_cwes = sorted({match.group() for value in cwes for match in re.finditer(r"CWE-[1-9][0-9]*", str(value))})
    return metadata_dict(
        {
            "source": source,
            "rule_id": str(rule_id),
            "native_severity": str(severity),
            "severity": mapping.get(str(severity).lower(), "unknown"),
            "cwe_ids": valid_cwes,
            "verification_status": "unverified",
        }
    )
