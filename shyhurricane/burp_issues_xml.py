"""Convert Burp issue exports into finding and HTTP indexing submissions."""

import base64
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urljoin

from lxml import etree

from shyhurricane.http_burp_xml import _http_text, _parse_item
from shyhurricane.utils import parse_to_iso8601, urlparse_ext


def issue_records(issue, timestamp):
    """Return extension-compatible findings followed by complete HTTP exchanges."""
    if any(isinstance(node, etree._Entity) for node in issue.iter()):
        raise ValueError("Unsupported XML entity")

    def text(name):
        return (issue.findtext(name) or "").strip()

    name, host = text("name"), text("host")
    target = urljoin(host.rstrip("/") + "/", text("path"))
    if urlparse_ext(target).scheme not in ("http", "https"):
        raise ValueError("Expected HTTP(S) issue URL")
    if not name:
        raise ValueError("Missing issue name")
    title = f"{name} at {target}"
    metadata = {"source": "burp", "verification_status": "unverified"}
    for field, tag in (("rule_id", "type"), ("source_finding_id", "serialNumber")):
        if text(tag):
            metadata[field] = text(tag)
    for field, mapping in (
        ("severity", {"high": "high", "medium": "medium", "low": "low",
                      "information": "informational", "informational": "informational"}),
        ("confidence", {"certain": "high", "firm": "medium", "tentative": "low"}),
    ):
        if text(field):
            metadata[f"native_{field}"] = text(field)
            metadata[field] = mapping.get(text(field).lower(), "unknown")
    classifications = text("vulnerabilityClassifications")
    cwes = sorted({value.upper() for value in re.findall(r"CWE-[1-9][0-9]*", classifications, re.I)})
    cwes = sorted(set(cwes) | {f"CWE-{value}" for value in re.findall(
        r"https?://cwe\.mitre\.org/data/definitions/([1-9][0-9]*)\.html", classifications, re.I
    )})
    if cwes:
        metadata["cwe_ids"] = [value.upper() for value in cwes]
    markdown = (f"# {title}\n\n**Summary**\nSeverity: {text('severity')}\n"
                f"Confidence: {text('confidence')}\nURL: `{target}`\n\n"
                f"{text('issueBackground')}\n{text('issueDetail')}\n\n**Reproduction Steps**\n")
    requests, exchanges = [], []
    for pair in issue.findall("requestresponse"):
        decoded = {}
        for part in ("request", "response"):
            try:
                decoded[part] = _http_text(pair, part)
            except ValueError as error:
                print(f"[✘] Skipping issue {part}: {error}", file=sys.stderr)
                continue
        request = decoded.get("request", "")
        first = request.splitlines()[0].split() if request else []
        if len(first) >= 3 and first[2].startswith("HTTP/"):
            url = urljoin(host.rstrip("/") + "/", first[1])
            try:
                if urlparse_ext(url).scheme not in ("http", "https"):
                    raise ValueError("Expected HTTP(S) evidence URL")
                if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", first[0]):
                    raise ValueError("Invalid request method")
            except ValueError as error:
                print(f"[✘] Skipping issue request: {error}", file=sys.stderr)
                continue
            requests.append((url, first[0]))
            body = re.split(r"\r?\n\r?\n", request, maxsplit=1)
            markdown += f"{first[0]} {url}\n" + (body[1][:1024] if len(body) > 1 else "") + "\n\n"
            response = decoded.get("response", "")
            if response:
                body = re.split(r"\r?\n\r?\n", response, maxsplit=1)
                markdown += response.splitlines()[0].partition(" ")[2] + "\n"
                markdown += (body[1][:1024] if len(body) > 1 else "") + "\n\n"
                item = etree.Element("item")
                for tag, value in (("url", url), ("time", timestamp), *decoded.items()):
                    element = etree.SubElement(item, tag)
                    if tag in ("request", "response"):
                        element.set("base64", "true")
                        element.text = base64.b64encode(value.encode("utf-8")).decode("ascii")
                    else:
                        element.text = value
                try:
                    exchanges.append(_parse_item(item))
                except (ValueError, KeyError, TypeError) as error:
                    print(f"[✘] Skipping issue exchange: {error}", file=sys.stderr)
    markdown += f"\n**Solution**\n{text('remediationDetail')}\n{text('remediationBackground')}\n"
    for tag in ("location", "references", "vulnerabilityClassifications", "issueDetailItems",
                "collaboratorEvent", "infiltratorEvent", "staticAnalysis", "dynamicAnalysis", "prototypePollution"):
        for node in issue.findall(tag):
            markdown += f"\n**{tag}**\n" + "\n".join(node.itertext()) + "\n"
    for url, method in requests or [(target, None)]:
        yield "finding", {"target": url, "title": title, "markdown": markdown,
                          "metadata": {**metadata, **({"affected_method": method.upper()} if method else {})}}
    for exchange in exchanges:
        yield "exchange", exchange


def burp_xml_records(source):
    """Dispatch either Burp XML root while retaining bounded streaming memory."""
    root = None
    number = 0
    for event, node in etree.iterparse(source, events=("start", "end"), resolve_entities=False,
                                       load_dtd=False, no_network=True):
        if root is None:
            root = node
            if root.tag not in ("items", "issues"):
                raise ValueError("Expected Burp XML root <items> or <issues>")
        if event != "end" or node.getparent() is not root:
            continue
        number += 1
        try:
            if root.tag == "items" and node.tag == "item":
                yield "exchange", _parse_item(node)
            elif root.tag == "issues" and node.tag == "issue":
                try:
                    timestamp, _ = parse_to_iso8601(root.get("exportTime", ""))
                except (ValueError, KeyError):
                    timestamp = datetime.now(timezone.utc).isoformat()
                yield from issue_records(node, timestamp)
        except (ValueError, KeyError, TypeError) as error:
            print(f"[✘] Skipping XML {node.tag} {number}: {error}", file=sys.stderr)
        finally:
            node.clear()
            while node.getprevious() is not None:
                del root[0]
