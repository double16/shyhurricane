"""
Nuclei JSON → Markdown
"""

import json
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple


#
# parsing utils
#

def load_findings(raw: str) -> List[Dict[str, Any]]:
    raw = raw.strip()
    if not raw:
        return []
    # Try object/array
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
    except json.JSONDecodeError:
        pass
    # Try NDJSON
    out: List[Dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                out.append(obj)
        except json.JSONDecodeError:
            continue
    return out


def split_http_message(msg: str) -> Tuple[str, str]:
    parts = msg.split("\r\n\r\n", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    parts = msg.split("\n\n", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return msg, ""


def parse_headers(header_text: str) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for line in header_text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return headers


def is_probably_text(content_type: Optional[str]) -> bool:
    if not content_type:
        return True
    ct = content_type.lower()
    return any([
        ct.startswith("text/"),
        "json" in ct,
        "xml" in ct,
        "yaml" in ct,
        "html" in ct,
        "javascript" in ct,
        "x-www-form-urlencoded" in ct,
    ])


def clip(text: str, max_chars: int) -> str:
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n...[truncated]"


def bullets(items: Iterable[str]) -> str:
    return "\n".join(f"- {line}" for line in items if line)


def md_code_block(content: str, lang: str = "") -> str:
    fence = "```" if "```" not in content else "~~~"
    return f"{fence}{lang}\n{content.rstrip()}\n{fence}\n"


def md_kv(label: str, value: Optional[str]) -> str:
    return f"**{label}:** {value}" if value else f"**{label}:** -"


#
# field helpers
#

def norm(d: Dict[str, Any], *path: str) -> Any:
    cur: Any = d
    for p in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


def to_title(d: Dict[str, Any]) -> str:
    name = str(norm(d, "info", "name") or d.get("template-id") or "Finding")
    target = d.get("url") or d.get("matched-at") or d.get("host") or ""
    return f"{name} on {target}" if target else name


def severity_of(d: Dict[str, Any]) -> str:
    sev = str(norm(d, "info", "severity") or "").strip()
    return sev.capitalize() if sev else "Info"


def classification_lines(d: Dict[str, Any]) -> List[str]:
    c = norm(d, "info", "classification") or {}
    if not isinstance(c, dict):
        return []
    out: List[str] = []
    cve = c.get("cve-id")
    if cve:
        if isinstance(cve, list):
            for x in cve:
                out.append(f"CVE: {x} – https://nvd.nist.gov/vuln/detail/{x}")
        else:
            out.append(f"CVE: {cve} – https://nvd.nist.gov/vuln/detail/{cve}")

    def cwe_url(x: str) -> str:
        m = re.search(r"(\d+)", str(x))
        return f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html" if m else ""

    cwe = c.get("cwe-id")
    if cwe:
        if isinstance(cwe, list):
            for x in cwe:
                url = cwe_url(x)
                out.append(f"CWE: {x}" + (f" – {url}" if url else ""))
        else:
            url = cwe_url(str(cwe))
            out.append(f"CWE: {cwe}" + (f" – {url}" if url else ""))
    score = c.get("cvss-score")
    metrics = c.get("cvss-metrics")
    if score:
        out.append(f"CVSS: {score}" + (f" ({metrics})" if metrics else ""))
    epss = c.get("epss-score")
    epss_p = c.get("epss-percentile")
    if epss is not None:
        if isinstance(cve, str):
            out.append(f"EPSS: {epss} (p{epss_p}) – https://epss.cyentia.com/score/cve/{cve}")
        else:
            out.append(f"EPSS: {epss}" + (f" (p{epss_p})" if epss_p else ""))
    if c.get("cisa-known-exploited") in (True, "true", "True"):
        out.append("CISA KEV: Known exploited – https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
    cpe = c.get("cpe")
    if cpe:
        for x in (cpe if isinstance(cpe, list) else [cpe]):
            out.append(f"CPE: {x}")
    refs = c.get("references") or []
    if isinstance(refs, list):
        out.extend(str(r) for r in refs)
    return out


def intel_query_lines(info: Dict[str, Any]) -> List[str]:
    md = info.get("metadata") or {}
    if not isinstance(md, dict):
        return []
    keys = [
        "shodan-query", "fofa-query", "zoomeye-query", "quake-query", "hunter-query",
        "publicwww-query", "google-query", "github-query", "censys-query",
    ]
    out: List[str] = []
    for k in keys:
        v = md.get(k)
        if v:
            out.append(f"{k.replace('-', ' ').title()}: `{v}`")
    return out


def issue_summary(d: Dict[str, Any]) -> str:
    info = d.get("info") or {}
    desc = (info.get("description") or "").strip() or "Finding reported by Nuclei."
    extracted = d.get("extracted-results") or []
    matched_name = d.get("matcher-name")
    details = []
    if matched_name:
        details.append(f"Matcher: `{matched_name}`")
    if extracted and isinstance(extracted, list):
        joined = ", ".join(x.strip() for x in extracted if isinstance(x, str))
        if joined:
            details.append(f"Extracted: {joined}")
    add = ("\n\n" + bullets(details)) if details else ""
    return f"{desc}{add}"


def discovery_method(d: Dict[str, Any]) -> str:
    info = d.get("info") or {}
    parts = [
        "Tool: Nuclei",
        f"Template: {info.get('name')} ({d.get('template-id', 'unknown')})" if info.get(
            "name") else f"Template: {d.get('template-id', 'unknown')}",
    ]
    if d.get("template-url"):
        parts.append(f"Template URL: {d['template-url']}")
    if info.get("author"):
        authors = ", ".join(info["author"]) if isinstance(info["author"], list) else str(info["author"])
        parts.append(f"Author(s): {authors}")
    if info.get("tags"):
        parts.append("Tags: " + ", ".join(info["tags"]))
    if d.get("matched-at"):
        parts.append(f"Matched at: {d['matched-at']}")
    if d.get("url"):
        parts.append(f"URL: {d['url']}")
    host = d.get("host")
    ip = d.get("ip")
    port = d.get("port")
    scheme = d.get("scheme")
    hi = " / ".join(filter(None, [str(scheme or ""), str(host or ""), str(port or "")])).strip(" /")
    if hi or ip:
        parts.append(f"Host: {hi} | IP: {ip or '-'}")
    if d.get("timestamp"):
        parts.append(f"Timestamp: {d['timestamp']}")
    if d.get("matcher-status") is not None:
        parts.append(f"Matcher status: {d['matcher-status']}")
    parts.extend(classification_lines(d))
    iq = intel_query_lines(info)
    if iq:
        parts.append("Intel:")
        parts.extend([f"  - {x}" for x in iq])
    return bullets(parts)


def reproduction_steps(d: Dict[str, Any]) -> str:
    t = (d.get("type") or "").lower()
    url = d.get("matched-at") or d.get("url") or ""
    curl = d.get("curl-command")
    host = d.get("host")
    port = d.get("port") or ""
    hostport = f"{host}:{port}" if host and port else (host or "")

    lines: List[str] = []
    if t in ("http", "headless"):
        if url:
            lines.append(f"1. Open `{url}` in a browser.")
        if curl:
            lines.append("2. Or run the curl command in PoC.")
        else:
            lines.append("2. Send an HTTP request as shown in PoC.")
        lines.append("3. Verify response status and expected markers/fields.")
        return "\n".join(lines)

    if t == "dns":
        if host:
            lines.append(f"1. Query the record with `dig {host} any` or `nslookup {host}`.")
        lines.append("2. Confirm the record(s) match expected indicators from the template.")
        return "\n".join(lines)

    if t in ("tcp", "udp", "network"):
        if hostport:
            proto = "udp" if t == "udp" else "tcp"
            lines.append(f"1. Connect using `nc -v {host} {port}` ({proto}).")
            lines.append("2. Send payloads per template; observe banner or response.")
        else:
            lines.append("1. Connect to the target service; observe banner/response as per template.")
        return "\n".join(lines)

    if t in ("ssl", "tls"):
        if hostport and host:
            lines.append(f"1. `openssl s_client -connect {hostport} -servername {host}`")
            lines.append("2. Inspect certificate/handshake details as per template.")
        else:
            lines.append("1. Use `openssl s_client` to inspect the TLS endpoint per template.")
        return "\n".join(lines)

    if url:
        lines.append(f"1. Interact with `{url}` per template instructions.")
    elif hostport:
        lines.append(f"1. Test the service at `{hostport}` per template instructions.")
    else:
        lines.append("1. Trigger the check using the same inputs as Nuclei.")
    lines.append("2. Validate the observed indicator(s) match the finding.")
    return "\n".join(lines)


def poc_block(d: Dict[str, Any], max_chars: int, show_binary: bool) -> str:
    blocks: List[str] = []
    curl = d.get("curl-command")
    if curl:
        blocks.append("### curl")
        blocks.append(md_code_block(curl, "bash"))
    req = d.get("request")
    if req:
        blocks.append("### Request")
        blocks.append(md_code_block(clip(str(req), max_chars), "http"))
    resp = d.get("response")
    if resp:
        hdrs, body = split_http_message(resp)
        blocks.append("### Response headers")
        blocks.append(md_code_block(clip(hdrs, max_chars), "http"))
        ctype = parse_headers(hdrs).get("content-type")
        if body.strip():
            if is_probably_text(ctype) or show_binary:
                lang = "json" if ctype and "json" in ctype.lower() else "text"
                blocks.append("### Response body")
                blocks.append(md_code_block(clip(body, max_chars), lang))
            else:
                blocks.append("### Response body")
                blocks.append("> (binary content suppressed)")
    extracted = d.get("extracted-results")
    if extracted:
        txt = "\n".join(str(x) for x in extracted if isinstance(x, (str, int, float)))
        if txt.strip():
            blocks.append("### Extracted")
            blocks.append(md_code_block(clip(txt, max_chars), "text"))
    return "\n".join(blocks).rstrip() + ("\n" if blocks else "")


def remediation(d: Dict[str, Any]) -> str:
    info = d.get("info") or {}
    for key in ("remediation", "solution", "fix"):
        val = info.get(key)
        if isinstance(val, str) and val.strip():
            return bullets([line.strip() for line in val.splitlines() if line.strip()])
    sev = (info.get("severity") or "").lower()
    t = (d.get("type") or "").lower()
    items: List[str] = []
    if t in ("http", "headless"):
        items.append("Validate/sanitize inputs & outputs; enforce least privilege.")
        items.append("Apply vendor patches and harden service configuration.")
        items.append("Monitor for anomalous requests; consider WAF rules if applicable.")
    elif t in ("ssl", "tls"):
        items.append("Use a modern TLS config; deploy valid, complete certificate chains.")
        items.append("Enable HSTS where appropriate; remove weak/legacy options.")
    elif t == "dns":
        items.append("Harden DNS; avoid sensitive disclosures; use DNSSEC if applicable.")
    else:
        items.append("Patch/upgrade affected components per vendor guidance.")
        items.append("Restrict exposure; enforce authN/authZ & network controls.")
    if sev in ("high", "critical"):
        items.insert(0, "Prioritize remediation due to potential high impact.")
    return bullets(items)


def references(d: Dict[str, Any]) -> str:
    info = d.get("info") or {}
    refs: List[str] = []
    if d.get("template-url"):
        refs.append(str(d["template-url"]))
    for r in info.get("reference") or []:
        refs.append(str(r))
    refs.extend(classification_lines(d))
    out: List[str] = []
    seen = set()
    for r in refs:
        if r not in seen and r.strip():
            out.append(r)
            seen.add(r)
    return bullets(out) if out else "- (none)"


#
# targets & title
#

def _default_port_for_scheme(scheme: Optional[str]) -> Optional[str]:
    if not scheme:
        return None
    s = scheme.lower()
    return {"http": "80", "https": "443"}.get(s)


def _hostport(host: Optional[str], port: Optional[str]) -> Optional[str]:
    if not host:
        return None
    h = str(host).strip()
    p = str(port).strip() if port is not None else ""
    return f"{h}:{p}" if p and f":{p}" not in h else h


def extract_targets(d: Dict[str, Any]) -> List[str]:
    """
    Return a stable, de-duplicated list of targets consisting of:
    - URLs (matched-at, url, scheme://host[:port])
    - host[:port]
    - ip[:port]
    """
    seen = set()
    ordered: List[str] = []

    def add(x: Optional[str]):
        if not x:
            return
        xx = str(x).strip()
        if not xx:
            return
        if xx not in seen:
            seen.add(xx)
            ordered.append(xx)

    # 1) Strong signals first: explicit URLs
    add(d.get("matched-at"))
    add(d.get("url"))
    if ordered:
        return ordered

    # 2) Construct URL from pieces
    host = d.get("host")
    ip = d.get("ip")
    port = str(d.get("port")) if d.get("port") is not None else ""
    scheme = d.get("scheme")
    default_port = _default_port_for_scheme(scheme)
    if host:
        if scheme:
            # include URL with port only if it's not default
            if port and port != default_port and f":{port}" not in host:
                add(f"{scheme}://{host}:{port}")
            else:
                add(f"{scheme}://{host}")
        # host forms
        add(_hostport(host, port))
        add(str(host))
    # 3) IP forms
    if ip:
        add(_hostport(ip, port))
        add(str(ip))

    if ordered:
        return ordered

    # 4) Try extracting Host header from request (fallback)
    req = d.get("request")
    if isinstance(req, str) and "Host:" in req:
        hdrs, _ = split_http_message(req)
        h = parse_headers(hdrs).get("host")
        if h:
            # Preserve any port in Host header
            add(h)
            # Also scheme URL if we know the scheme
            if scheme:
                if ":" in h:
                    add(f"{scheme}://{h}")
                else:
                    if port and port != default_port and f":{port}" not in h:
                        add(f"{scheme}://{h}:{port}")
                    else:
                        add(f"{scheme}://{h}")

    return ordered


#
# rendering
#

def header_block(d: Dict[str, Any]) -> str:
    title = to_title(d)
    severity = severity_of(d)
    target = d.get("url") or d.get("matched-at") or d.get("host") or "-"
    template_id = d.get("template-id") or "-"
    template_ver = (norm(d, "info", "version") or norm(d, "info", "template-version") or "")
    tver = f" ({template_ver})" if template_ver else ""
    ts = d.get("timestamp")
    ts_human = ""
    if ts:
        try:
            ts_human = datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S %Z")
        except Exception:
            ts_human = ts
    lines = [
        f"# {title}",
        "",
        md_kv("Severity", severity) + "  ",
        md_kv("Target", str(target)) + "  ",
        md_kv("Template", f"{template_id}{tver}") + "  ",
        md_kv("Type", str(d.get("type") or "-")) + "  ",
        md_kv("Timestamp", ts_human or "-") + "  ",
    ]
    return "\n".join(lines).rstrip()


def finding_to_markdown(d: Dict[str, Any], max_chars: int, show_binary: bool) -> str:
    parts = [header_block(d), ""]
    sections = [
        ("## Issue summary", issue_summary(d)),
        ("## Discovery method", discovery_method(d)),
        ("## Reproduction steps", reproduction_steps(d)),
        ("## PoC", poc_block(d, max_chars=max_chars, show_binary=show_binary).rstrip()),
        ("## Fix", remediation(d)),
        ("## References", references(d)),
    ]
    for heading, body in sections:
        if body and str(body).strip():
            parts.append(heading)
            parts.append("")
            parts.append(str(body).rstrip())
            parts.append("")
    tpath = d.get("template-path")
    if tpath:
        parts.append(f"<sub>Template path: `{tpath}`</sub>")
        parts.append("")
    return "\n".join(parts).rstrip() + "\n"


#
# conversion functions
#

def nuclei_finding_to_markdown(
        finding: Dict[str, Any],
        max_chars: int = 1024,
        show_binary: bool = False
) -> Dict[str, Any]:
    """
    Convert a Nuclei finding JSON document to:
      - title: str
      - targets: List[str]
      - markdown: str
    """
    title = to_title(finding)
    targets = extract_targets(finding)
    md = finding_to_markdown(finding, max_chars=max_chars, show_binary=show_binary)
    return {"title": title, "targets": targets, "markdown": md}


def is_nuclei_finding(d: Dict[str, Any]) -> bool:
    return all(filter(lambda e: e in d, ["template-id", "info"])) and any(
        filter(lambda e: e in d, ["url", "matched-at", "host"]))
