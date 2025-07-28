import logging
import re
from collections import OrderedDict
import tinycss2

logger = logging.getLogger(__name__)

HASH_RE = re.compile(r"\b[0-9a-f]{32,64}\b", re.I)
TS_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b")


def _normalize_number(val: str) -> str:
    # 0px -> 0  |  1.0 -> 1
    if val.lower().endswith("px") and val[:-2] == "0":
        return "0"
    try:
        f = float(val)
        if f.is_integer():
            return str(int(f))
    except Exception:
        pass
    return val


def _normalize_color(val: str) -> str:
    if val.startswith("#"):
        v = val.lower()
        if len(v) == 7 and v[1] == v[2] and v[3] == v[4] and v[5] == v[6]:
            return f"#{v[1]}{v[3]}{v[5]}"
        return v
    return val


def _clean_url(val: str) -> str:
    # url("path/file.css?v=123#hash") -> url("path/file.css")
    inside = val.strip().strip("url(").strip(")").strip(" '\"")
    inside = re.sub(r"[?#].*$", "", inside)
    return f"url({inside})"


def _normalize_selector(sel: str) -> str:
    # simple whitespace collapse around combinators
    sel = re.sub(r"\s*([>+~])\s*", r"\1", sel)
    sel = re.sub(r"\s+", " ", sel).strip()
    return sel


def _normalize_decls(decls):
    props = OrderedDict()
    for d in decls:
        if d.type != "declaration" or d.name is None:
            continue
        name = d.name.lower().strip()
        value = tinycss2.serialize(d.value).strip()

        # normalize tokens
        value = _normalize_number(value)
        value = _normalize_color(value)
        if value.lower().startswith("url("):
            value = _clean_url(value)

        # keep last occurrence wins (CSS cascade)
        props[name] = value
    # sort props alphabetically for determinism
    return OrderedDict(sorted(props.items()))


def normalize_css(css: str) -> str:
    # 1. Parse
    rules = tinycss2.parse_stylesheet(css, skip_whitespace=True, skip_comments=True)

    out_rules = []

    for rule in rules:
        if rule.type == "error":
            continue

        if rule.type == "at-rule":
            # @media, @font-face, etc. — keep params, normalize block if exists
            prelude = tinycss2.serialize(rule.prelude).strip()
            if rule.content:
                decls = tinycss2.parse_declaration_list(rule.content, skip_comments=True, skip_whitespace=True)
                decls_norm = _normalize_decls(decls)
                block = "".join(f"{k}:{v};" for k, v in decls_norm.items())
                out_rules.append(f"@{rule.lower_at_keyword} {prelude}{{{block}}}")
            else:
                out_rules.append(f"@{rule.lower_at_keyword} {prelude};")
            continue

        if rule.type == "qualified-rule":
            # selectors
            sel_raw = tinycss2.serialize(rule.prelude)
            selectors = [s.strip() for s in sel_raw.split(",")]
            selectors = [_normalize_selector(s) for s in selectors]
            selectors.sort()
            sel_norm = ",".join(selectors)

            # declarations
            decls = tinycss2.parse_declaration_list(rule.content, skip_comments=True, skip_whitespace=True)
            decls_norm = _normalize_decls(decls)
            block = "".join(f"{k}:{v};" for k, v in decls_norm.items())
            out_rules.append(f"{sel_norm}{{{block}}}")

    normalized = "".join(out_rules)

    # 2. Replace dynamic tokens
    normalized = HASH_RE.sub("<HASH>", normalized)
    normalized = TS_RE.sub("<TIMESTAMP>", normalized)

    return normalized.strip()
