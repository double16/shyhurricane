"""Streaming markup inventory and a bounded semantic projection, without a whole-document DOM."""

from html import escape
from html.parser import HTMLParser

CHUNK_BYTES = 1024 * 1024
SEMANTIC_TAGS = {
    "a",
    "area",
    "base",
    "form",
    "input",
    "textarea",
    "select",
    "option",
    "button",
    "script",
    "link",
    "meta",
    "svg",
    "use",
    "image",
    "style",
    "fieldset",
    "legend",
}
VOID_TAGS = {
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "param",
    "source",
    "track",
    "wbr",
}


class MarkupScanner(HTMLParser):
    def __init__(self, emit, *, maximum=10000, offset=0, locators=None):
        super().__init__(convert_charrefs=True)
        self.emit = emit
        self.maximum = maximum
        self.selection_offset = offset
        self.seen = 0
        self.locators = locators
        self.base = None
        self.forms = {}
        self.requested_forms = set()
        self.rendered_forms = set()
        self.retained = 0
        self.output = []
        self.stack = []
        self.form = None
        self.text_tag = None
        self.deferred = 0
        self.deferred_script = None

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        important = tag in SEMANTIC_TAGS or any(
            key in {"id", "name", "src", "href", "xlink:href", "style", "xml:base"} or key.startswith("on")
            for key in values
        )
        locator = f"markup:{self.seen}:{tag}"
        retained = important and self.seen >= self.selection_offset and self.retained < self.maximum
        if tag == "base" and self.base is None:
            self.base = (tag, attrs, locator)
        if retained and not self.retained and self.selection_offset:
            ancestors = [(entry[0], entry[3], entry[4]) for entry in self.stack]
            if self.base and self.base[2] != locator:
                ancestors.insert(0, self.base)
            for name, attributes, position in ancestors:
                self.open_tag(name, attributes, position)
            self.stack = [
                (name, True, form, attributes, position) for name, _, form, attributes, position in self.stack
            ]
        if important and tag not in VOID_TAGS:
            self.stack.append((tag, retained, self.form, attrs, locator))
        if tag == "form":
            self.form = values.get("id") or values.get("name") or locator
            if values.get("id"):
                self.forms.setdefault(values["id"], (attrs, locator))
        if retained and values.get("form"):
            self.requested_forms.add(values["form"])
        if important:
            self.seen += 1
            self.emit(
                {
                    "tag": tag,
                    "attributes": values,
                    "form": self.form,
                    "locator": locator,
                    "line": self.getpos()[0],
                    "column": self.getpos()[1],
                }
            )
            if retained:
                self.retained += 1
                self.open_tag(tag, attrs, locator)
            else:
                self.deferred += 1
        if tag in {"script", "style", "textarea", "option"}:
            self.text_tag = tag
        if tag == "script" and important and not retained and not values.get("src"):
            self.deferred_script = {
                "tag": tag,
                "attributes": values,
                "form": self.form,
                "line": self.getpos()[0],
                "column": self.getpos()[1],
                "locator": locator,
                "source": [],
            }

    def finish(self):
        for name in sorted(self.requested_forms - self.rendered_forms):
            if name in self.forms:
                attrs, locator = self.forms[name]
                self.open_tag("form", attrs, locator)
                self.output.append("</form>")

    def open_tag(self, tag, attrs, locator):
        if tag == "form" and dict(attrs).get("id"):
            self.rendered_forms.add(dict(attrs)["id"])
        attributes = " ".join(f'{key}="{escape(value or "", quote=True)}"' for key, value in attrs)
        self.output.append(f"<{tag} {attributes}>")
        if self.locators is not None:
            self.locators.append(locator)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag == "script" and self.deferred_script is not None:
            record = self.deferred_script
            record["source"] = "".join(record["source"])
            self.emit(record)
            self.deferred_script = None
        # HTML void elements have no closing event; do not retain an ever-growing stack for them.
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                _, _, form, _, _ = self.stack[index]
                self.output.extend(f"</{entry[0]}>" for entry in reversed(self.stack[index:]) if entry[1])
                del self.stack[index:]
                self.form = form
                break
        if tag == self.text_tag:
            self.text_tag = None

    def handle_data(self, data):
        if self.deferred_script is not None:
            self.deferred_script["source"].append(data)
            return
        if self.text_tag and self.stack and self.stack[-1][1]:
            self.output.append(data if self.text_tag in {"script", "style"} else escape(data))


def scan_markup(body, emit=lambda record: None, *, maximum=10000, offset=0, locators=None):
    scanner = MarkupScanner(emit, maximum=maximum, offset=offset, locators=locators)
    for offset in range(0, len(body), CHUNK_BYTES):
        scanner.feed(body[offset : offset + CHUNK_BYTES])
    scanner.close()
    scanner.finish()
    return "".join(scanner.output), scanner.deferred


def scan_svg(body, emit=lambda record: None, *, maximum=10000, offset=0, locators=None):
    """Pull XML in bounded chunks, clearing parsed nodes after each end event."""
    from lxml import etree

    parser = etree.XMLPullParser(events=("start", "end"), resolve_entities=False, load_dtd=False, no_network=True)
    output, stack, positions = [], [], []
    retained = deferred = seen = 0
    for chunk_offset in range(0, len(body), CHUNK_BYTES):
        parser.feed(body[chunk_offset : chunk_offset + CHUNK_BYTES].encode())
        for event, node in parser.read_events():
            if not isinstance(node.tag, str):
                continue
            name = etree.QName(node).localname
            if event == "start":
                attrs = {}
                for key, value in node.attrib.items():
                    qualified = etree.QName(key)
                    key = (
                        "xml:"
                        if qualified.namespace == "http://www.w3.org/XML/1998/namespace"
                        else "xlink:"
                        if qualified.namespace == "http://www.w3.org/1999/xlink"
                        else ""
                    ) + qualified.localname
                    attrs[key] = value
                important = name in SEMANTIC_TAGS or any(
                    key in {"id", "href", "xlink:href", "xml:base", "style", "fill", "stroke", "filter"}
                    or key.startswith("on")
                    for key in attrs
                )
                locator = f"markup:{seen}:{name}"
                keep = important and seen >= offset and retained < maximum
                stack.append(keep)
                positions.append(locator)
                if keep and not retained and offset:
                    ancestors = list(reversed(list(node.iterancestors())))
                    for index, ancestor in enumerate(ancestors):
                        output.append(svg_open(ancestor))
                        stack[index] = True
                        if locators is not None:
                            locators.append(positions[index])
                if important:
                    seen += 1
                    emit(
                        {
                            "tag": name,
                            "attributes": attrs,
                            "form": None,
                            "locator": locator,
                            "line": node.sourceline or 1,
                            "column": 0,
                        }
                    )
                    if keep:
                        retained += 1
                        output.append(svg_open(node))
                        if locators is not None:
                            locators.append(locator)
                    else:
                        deferred += 1
            else:
                keep = stack.pop()
                source_locator = positions.pop()
                if not keep and name == "script" and node.text:
                    emit(
                        {
                            "tag": name,
                            "attributes": dict(node.attrib),
                            "form": None,
                            "line": node.sourceline or 1,
                            "column": 0,
                            "locator": source_locator,
                            "source": node.text,
                        }
                    )
                if keep:
                    if name in {"script", "style", "text"} and node.text:
                        output.append(escape(node.text))
                    output.append(f"</{name}>")
                node.clear()
                parent = node.getparent()
                if parent is not None:
                    while node.getprevious() is not None:
                        del parent[0]
    parser.close()
    return "".join(output), deferred


def svg_open(node):
    from lxml import etree

    name = etree.QName(node).localname
    attrs = {}
    for key, value in node.attrib.items():
        qualified = etree.QName(key)
        prefix = (
            "xml:"
            if qualified.namespace == "http://www.w3.org/XML/1998/namespace"
            else "xlink:"
            if qualified.namespace == "http://www.w3.org/1999/xlink"
            else ""
        )
        attrs[prefix + qualified.localname] = value
    if name == "svg":
        attrs.update(xmlns="http://www.w3.org/2000/svg")
        attrs["xmlns:xlink"] = "http://www.w3.org/1999/xlink"
    encoded = " ".join(f'{key}="{escape(value, quote=True)}"' for key, value in attrs.items())
    return f"<{name} {encoded}>"
