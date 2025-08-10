import re
from typing import List

from base64 import b64encode, b64decode
from urllib.parse import quote, unquote
import html


def _nop(in_str: str) -> str:
    return in_str


def _urlencode_all(in_str: str) -> str:
    hex_string = in_str.encode().hex()
    url_encoded = ""
    for i in range(0, len(hex_string), 2):
        url_encoded += "%" + hex_string[i:i + 2]
    return url_encoded.upper()


def _escape_unicode(in_str: str, escape_str: str) -> str:
    escaped = []
    for ch in in_str:
        escaped.append(escape_str)
        escaped.append(ch.encode(encoding="utf-16be").hex().upper())
    return "".join(escaped)


def _unescaped_unicode(escaped_str: str) -> str:
    replaced = escaped_str.replace(r'\\u', '').replace(r'%u', '').replace(r'U+', '')
    return bytes.fromhex(replaced).decode(encoding="utf-16be")


_operations = {
    "base64_encode": lambda t: b64encode(t.encode()).decode(),
    "base64_decode": lambda t: b64decode(t).decode(),
    "to_hex": lambda t: t.encode().hex(),
    "from_hex": lambda t: bytes.fromhex(t).decode(),
    "to_charcode": lambda t: t.encode(encoding="utf-16be").hex(),
    "from_charcode": lambda t: bytes.fromhex(t).decode(encoding="utf-16be"),
    "url_encode": lambda t: quote(t, safe=''),
    "url_encode_all": _urlencode_all,
    "url_decode": lambda t: unquote(t.upper()),
    "to_htmlentity": html.escape,
    "from_htmlentity": html.unescape,
    "escape_unicode_backslash": lambda t: _escape_unicode(t, "\\u"),
    "escape_unicode_percent": lambda t: _escape_unicode(t, "%u"),
    "escape_unicode_u_plus": lambda t: _escape_unicode(t, "U+"),
    "unescape_unicode": _unescaped_unicode,
    "to_uppercase": str.upper,
    "to_lowercase": str.lower,
}


def do_encode_decode(in_str: str, operations: List[str]) -> str:
    if in_str is None:
        return ""
    for op in operations:
        try:
            op_f = _operations.get(op)
            in_str = op_f(in_str)
        except KeyError:
            raise ValueError("Operation %s is invalid: valid operations are %s", op, ", ".join(_operations.keys()))

    return in_str
