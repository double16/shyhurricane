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
    "CWE-611": "injection",
    "CWE-113": "injection",
    "CWE-915": "injection",
    "CWE-1321": "injection",
    "CWE-614": "configuration",
    "CWE-1104": "dependency",
    "CWE-918": "ssrf",
    "CWE-639": "access_control",
    "CWE-862": "access_control",
    "CWE-863": "access_control",
    "CWE-287": "authentication",
    "CWE-384": "authentication",
    "CWE-200": "exposure",
    "CWE-798": "exposure",
    "CWE-942": "configuration",
    # Web-relevant xss weaknesses.
    "CWE-80": "xss",
    "CWE-81": "xss",
    "CWE-83": "xss",
    "CWE-84": "xss",
    "CWE-85": "xss",
    "CWE-86": "xss",
    "CWE-87": "xss",
    # Web-relevant injection weaknesses.
    "CWE-74": "injection",
    "CWE-77": "injection",
    "CWE-88": "injection",
    "CWE-90": "injection",
    "CWE-91": "injection",
    "CWE-93": "injection",
    "CWE-95": "injection",
    "CWE-96": "injection",
    "CWE-97": "injection",
    "CWE-98": "injection",
    "CWE-99": "injection",
    "CWE-1336": "injection",
    "CWE-502": "injection",
    "CWE-643": "injection",
    "CWE-652": "injection",
    "CWE-917": "injection",
    # Web-relevant access_control weaknesses.
    "CWE-22": "access_control",
    "CWE-23": "access_control",
    "CWE-36": "access_control",
    "CWE-284": "access_control",
    "CWE-285": "access_control",
    "CWE-352": "access_control",
    "CWE-425": "access_control",
    "CWE-441": "access_control",
    "CWE-565": "access_control",
    "CWE-732": "access_control",
    "CWE-749": "access_control",
    "CWE-922": "exposure",
    "CWE-1275": "configuration",
    # Web-relevant authentication weaknesses.
    "CWE-256": "authentication",
    "CWE-259": "authentication",
    "CWE-288": "authentication",
    "CWE-289": "authentication",
    "CWE-290": "authentication",
    "CWE-294": "authentication",
    "CWE-295": "authentication",
    "CWE-297": "authentication",
    "CWE-306": "authentication",
    "CWE-307": "authentication",
    "CWE-308": "authentication",
    "CWE-309": "authentication",
    "CWE-346": "authentication",
    "CWE-347": "authentication",
    "CWE-521": "authentication",
    "CWE-613": "authentication",
    "CWE-620": "authentication",
    "CWE-640": "authentication",
    "CWE-645": "authentication",
    "CWE-646": "authentication",
    "CWE-647": "authentication",
    # Web-relevant configuration weaknesses.
    "CWE-15": "configuration",
    "CWE-209": "configuration",
    "CWE-444": "configuration",
    "CWE-548": "configuration",
    "CWE-602": "configuration",
    "CWE-615": "configuration",
    "CWE-693": "configuration",
    "CWE-1004": "configuration",
    "CWE-1021": "configuration",
    # Web-relevant exposure weaknesses.
    "CWE-201": "exposure",
    "CWE-203": "exposure",
    "CWE-204": "exposure",
    "CWE-215": "exposure",
    "CWE-359": "exposure",
    "CWE-497": "exposure",
    "CWE-498": "exposure",
    "CWE-532": "exposure",
    "CWE-538": "exposure",
    "CWE-539": "exposure",
    "CWE-540": "exposure",
    "CWE-541": "exposure",
    "CWE-598": "exposure",
    # Web-relevant cryptography weaknesses.
    "CWE-261": "cryptography",
    "CWE-311": "cryptography",
    "CWE-312": "cryptography",
    "CWE-319": "cryptography",
    "CWE-321": "cryptography",
    "CWE-322": "cryptography",
    "CWE-323": "cryptography",
    "CWE-324": "cryptography",
    "CWE-325": "cryptography",
    "CWE-326": "cryptography",
    "CWE-327": "cryptography",
    "CWE-328": "cryptography",
    "CWE-329": "cryptography",
    "CWE-330": "cryptography",
    "CWE-331": "cryptography",
    "CWE-334": "cryptography",
    "CWE-335": "cryptography",
    "CWE-336": "cryptography",
    "CWE-337": "cryptography",
    "CWE-338": "cryptography",
    "CWE-522": "cryptography",
    "CWE-759": "cryptography",
    "CWE-760": "cryptography",
    "CWE-916": "cryptography",
    # Web-relevant dependency weaknesses.
    "CWE-829": "dependency",
    "CWE-830": "dependency",
    "CWE-1395": "dependency",
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


# Burp issue type indexes; documented sources are in docs/investigation-targets.md.
# Source: PortSwigger scanner issue definitions; indexes are decimal typeIndex values.
SCANNER_CATEGORIES = {
    ("burp", "1049600"): "injection",
    ("burp", "2097664"): "injection",
    ("burp", "2097942"): "injection",
    ("burp", "5243392"): "configuration",
    ("burp", "5243008"): "dependency",
    ("burp", "2097920"): "xss",
    ("burp", "2097408"): "xss",
    ("burp", "2097936"): "xss",
    ("burp", "2097928"): "injection",
    ("burp", "2097938"): "xss",
    ("burp", "1048832"): "injection",
    ("burp", "1049088"): "injection",
    ("burp", "1049104"): "injection",
    ("burp", "1052800"): "injection",
    ("burp", "3146256"): "ssrf",
    ("burp", "5244416"): "configuration",
    ("burp", "16777984"): "configuration",
    ("burp", "1049344"): "access_control",  # file-path-traversal
    ("burp", "1049856"): "injection",  # ldap-injection
    ("burp", "1050112"): "injection",  # xpath-injection
    ("burp", "1050368"): "injection",  # xml-injection
    ("burp", "1051648"): "injection",  # php-code-injection
    ("burp", "1051904"): "injection",  # server-side-javascript-code-injection
    ("burp", "1052160"): "injection",  # perl-code-injection
    ("burp", "1052416"): "injection",  # ruby-code-injection
    ("burp", "1052432"): "injection",  # python-code-injection
    ("burp", "1052448"): "injection",  # expression-language-injection
    ("burp", "1052672"): "injection",  # unidentified-code-injection
    ("burp", "1052928"): "injection",  # ssi-injection
    ("burp", "2097937"): "xss",  # cross-site-scripting-reflected-dom-based
    ("burp", "4195328"): "exposure",  # password-returned-in-url-query-string
    ("burp", "16777472"): "cryptography",  # tls-certificate
}


def category_basis(metadata):
    """Return deterministic classification provenance without interpreting prose."""
    basis = [
        {"category": value, "basis": "producer"}
        for value in metadata.get("vulnerability_types", [])
        if value != "unknown"
    ]
    basis.extend(
        {"category": CWE_TYPES[cwe], "basis": "cwe", "value": cwe}
        for cwe in metadata.get("cwe_ids", [])
        if cwe in CWE_TYPES
    )
    key = (metadata.get("source"), metadata.get("rule_id"))
    if not basis and key in SCANNER_CATEGORIES:
        basis.append({"category": SCANNER_CATEGORIES[key], "basis": "scanner_rule", "source": key[0], "value": key[1]})
    return basis


def categories(metadata):
    """Classify explicit metadata, falling back to known scanner rule identities."""
    return sorted({item["category"] for item in category_basis(metadata)}) or ["unknown"]


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
