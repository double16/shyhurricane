"""Fallback parsing for structured MCP arguments."""

import json


def parse_json_string(value):
    """Decode accidental JSON strings before validating the intended structured type."""
    return json.loads(value) if isinstance(value, str) else value
