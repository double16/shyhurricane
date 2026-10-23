"""Passive SVG markup extraction shared by standalone and inline documents."""

import re

from lxml import etree

from shyhurricane.graph.model import identity, web_url

SVG_MIMES = {"image/svg+xml", "image/svg"}
JAVASCRIPT_TYPES = {"", "module", "text/javascript", "application/javascript"}


def is_svg(mime):
    return mime.lower().split(";", 1)[0].strip() in SVG_MIMES


def svg_root(body):
    parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)
    return etree.fromstring(body.encode("utf-8"), parser=parser)


def extract_svg(root, graph, page, reference, scripts, base, *, inline=False, prefix="svg"):
    """Extract declared relationships and script text without resolving XML entities."""
    bases = {}
    retained = []
    elements = [root, *root.find_all(True)] if inline else root.iter()
    for index, tag in enumerate(elements):
        if index >= 10000:
            graph.gaps.append("SVG element budget reached")
            break
        if not inline and not isinstance(tag.tag, str):
            continue
        retained.append(tag)
        name = tag.name if inline else etree.QName(tag).localname
        attrs = tag.attrs if inline else tag.attrib
        parent = tag.parent if inline else tag.getparent()
        inherited = bases.get(id(parent), base)
        declared_base = attrs.get("xml:base") if inline else attrs.get("{http://www.w3.org/XML/1998/namespace}base")
        current_base = (web_url(declared_base, inherited) if declared_base else None) or inherited
        bases[id(tag)] = current_base
        locator = f"{prefix}:{index}:{name}"
        element = graph.node(
            "element", identity(graph.event["id"], locator), name=attrs.get("id") or name,
            html_id=attrs.get("id"), html_tag=name, capture_id=graph.event["id"],
        )
        graph.fact(page, element, "CONTAINS", "svg.element", location=locator)
        href = attrs.get("href", attrs.get("xlink:href" if inline else "{http://www.w3.org/1999/xlink}href"))
        if href:
            if href.strip().lower().startswith("javascript:"):
                scripts.append((f"{locator}:href", href.strip().split(":", 1)[1]))
            elif name == "a" or not href.strip().startswith("#"):
                kind = "NAVIGATES_TO" if name == "a" else (
                    "LOADS" if name in {"script", "image", "use"} else "RESOURCE_LINK"
                )
                reference(href, kind, "svg.href", base=current_base, location=locator)
        if name == "script" and not href and attrs.get("type", "").lower() in JAVASCRIPT_TYPES:
            text = tag.get_text() if inline else "".join(tag.itertext())
            if text.strip():
                scripts.append((locator, text))
        for attr, value in attrs.items():
            if attr.startswith("on") and isinstance(value, str):
                scripts.append((f"{locator}:{attr}", value))
        styles = [attrs.get("style", "")]
        if name == "style":
            styles.append(tag.get_text() if inline else "".join(tag.itertext()))
        # Presentation attributes such as fill and filter also accept CSS url(...).
        styles.extend(attrs.get(attr, "") for attr in (
            "fill", "stroke", "filter", "clip-path", "mask", "marker", "marker-start", "marker-mid", "marker-end",
            "cursor",
        ))
        for style in styles:
            for match in re.finditer(r"(?:url\(|@import\s+)[\"']?([^\"')\s;]+)", style):
                if not match[1].startswith("#"):
                    reference(match[1], "LOADS", "svg.css", base=current_base, location=locator)
