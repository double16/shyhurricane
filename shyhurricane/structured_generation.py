"""Validated JSON generation with process-local provider capability discovery."""

import json
import logging
from threading import RLock
from time import monotonic
from typing import Annotated, Literal, get_args

from haystack import component
from pydantic import BaseModel, ConfigDict, Field, create_model

logger = logging.getLogger(__name__)
_UNSUPPORTED = set()
_LOCK = RLock()


class TitleDescription(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)


VulnerabilityType = Literal[
    "XSS",
    "CSRF",
    "SSRF",
    "SSTI",
    "IDOR",
    "XXE",
    "SQL Injection",
    "Command Injection",
    "LDAP Injection",
    "XPath Injection",
    "NoSQL Injection",
    "Code Injection",
    "Template Injection",
    "Weak Authentication",
    "Secrets Disclosure",
    "Broken Access Control",
    "Sensitive Data Exposure",
    "Security Misconfiguration",
    "Unpatched Software",
    "Business Logic Flaw",
    "Clickjacking",
    "Open Redirect",
    "Directory Traversal",
    "Insecure Deserialization",
    "Rate Limiting Issues",
    "Broken Session Management",
    "Information Disclosure",
    "Unvalidated Redirects and Forwards",
    "Cryptographic Misuse",
    "Insecure Design",
    "Software Supply Chain Failures",
    "Software or Data Integrity Failures",
    "Security Logging and Alerting Failures",
    "Mishandling of Exceptional Conditions",
    "Authentication Bypass",
    "Privilege Escalation",
    "Session Fixation",
    "Account Enumeration",
    "Account Takeover",
    "Insecure Password Recovery",
    "Password Brute Force",
    "Credential Stuffing",
    "JWT Misconfiguration",
    "OAuth Misconfiguration",
    "Insecure Cookie Settings",
    "CORS Misconfiguration",
    "CSP Misconfiguration",
    "TLS Misconfiguration",
    "HTTP Request Smuggling",
    "HTTP Response Splitting",
    "CRLF Injection",
    "Host Header Injection",
    "HTTP Parameter Pollution",
    "HTML Injection",
    "CSS Injection",
    "SSI Injection",
    "XML Injection",
    "Prototype Pollution",
    "DOM Clobbering",
    "Insecure PostMessage",
    "WebSocket Security Misconfiguration",
    "Web Cache Poisoning",
    "Web Cache Deception",
    "Insecure File Upload",
    "Local File Inclusion",
    "Remote File Inclusion",
    "Arbitrary File Read",
    "Arbitrary File Write",
    "Mass Assignment",
    "GraphQL Misconfiguration",
    "Race Condition",
    "Denial of Service",
    "Regular Expression Denial of Service",
    "Subdomain Takeover",
    "DNS Rebinding",
    "Dependency Confusion",
    "Broken Object Level Authorization",
    "Broken Function Level Authorization",
    "Unrestricted Resource Consumption",
]
SUPPORTED_VULNERABILITY_TYPES = get_args(VulnerabilityType)


class Vulnerabilities(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    vuln_types: list[VulnerabilityType]


class WebsiteContext(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    target: list[str]
    content: list[Literal["html", "forms", "xml", "javascript", "css", "json", "network"]]
    tech: list[str]
    methods: list[str]
    response_codes: list[int]


@component
class StructuredGenerator:
    def __init__(self, factory, schema, key):
        self.factory = factory
        self.schema = schema
        self.key = key
        self.generator = None
        self.structured = None

    def warm_up(self):
        if self.generator is None or (self.structured and self.key in _UNSUPPORTED):
            self.close()
            self.structured = self.key not in _UNSUPPORTED
            self.generator = self.factory(self.structured)
        self.generator.warm_up()

    def close(self):
        if self.generator is not None and hasattr(self.generator, "close"):
            self.generator.close()

    @component.output_types(replies=list[str])
    def run(self, prompt: str):
        started = monotonic()
        prompt += "\nReturn only JSON matching this schema: " + json.dumps(self.schema.model_json_schema())
        with _LOCK:
            self.warm_up()
            try:
                result = self.generator.run(prompt=prompt)
            except Exception as error:
                message = str(error).lower()
                unsupported = any(term in message for term in ("response_format", "json_schema", "structured output", "format"))
                unsupported = unsupported and any(term in message for term in ("not supported", "unsupported"))
                if not unsupported or self.key in _UNSUPPORTED:
                    logger.warning("Structured generation failed task=%s provider/model=%s elapsed=%.3f input_chars=%s",
                                   self.schema.__name__, self.key, monotonic() - started, len(prompt))
                    raise
                _UNSUPPORTED.add(self.key)
                logger.warning("Structured output unavailable provider/model=%s; using validated JSON", self.key)
                self.close()
                self.structured = False
                self.generator = self.factory(False)
                self.generator.warm_up()
                result = self.generator.run(prompt=prompt)
        try:
            if not result.get("replies"):
                raise ValueError("Empty structured response")
            validated = [self.schema.model_validate_json(reply) for reply in result["replies"]]
            if self.schema is Vulnerabilities:
                logger.debug("Classification complete count=%s elapsed=%.3f",
                             sum(len(reply.vuln_types) for reply in validated), monotonic() - started)
            return {"replies": [reply.model_dump_json() for reply in validated]}
        except ValueError:
            logger.warning("Invalid structured response task=%s provider/model=%s elapsed=%.3f input_chars=%s",
                           self.schema.__name__, self.key, monotonic() - started, len(prompt))
            raise


class QueryExpansion(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    queries: list[Annotated[str, Field(max_length=256)]]


def query_expansion_schema(number: int):
    """Constrain generated patterns while retaining the shared asset validation schema."""
    return create_model(
        "BoundedQueryExpansion",
        __base__=QueryExpansion,
        queries=(list[Annotated[str, Field(max_length=256)]], Field(max_length=number)),
    )
