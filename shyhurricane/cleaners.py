import json
import logging

from lxml import etree
import re, html
from bs4 import BeautifulSoup, Doctype
from collections import OrderedDict
import json5

logger = logging.getLogger(__name__)


def normalize_xml(xml: str) -> str:
    parser = etree.XMLParser(remove_blank_text=True, resolve_entities=False, recover=True)
    tree = etree.fromstring(xml, parser)
    return etree.tostring(tree, pretty_print=True, encoding="utf-8", xml_declaration=True)


DYNAMIC_ATTRS = {"nonce", "data-reactroot", "data-hydration-id"}
DYNAMIC_PATTERNS = [
    re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b"),  # timestamps
    re.compile(r"\b[0-9a-f]{32,64}\b"),  # md5/sha hashes
]


def normalize_html(raw: str) -> str:
    soup = BeautifulSoup(raw, "html5lib")

    # # remove comments
    # for c in soup.find_all(string=lambda s: isinstance(s, type(soup.comment))):
    #     c.extract()
    #

    for el in soup.contents:
        if isinstance(el, Doctype):
            el.extract()

    for tag in soup.find_all(True):
        tag.name = tag.name.lower()

        # sort & clean attributes
        if tag.attrs:
            clean = {}
            for k, v in tag.attrs.items():
                k = k.lower()
                if k in DYNAMIC_ATTRS:
                    continue
                clean[k] = v
            tag.attrs = OrderedDict(sorted(clean.items()))

    # collapse whitespace in text nodes
    for t in soup.find_all(string=True):
        if isinstance(t, str):
            t.replace_with(re.sub(r"\s+", " ", t))

    text = soup.decode(formatter="minimal")
    text = html.unescape(text)

    # scrub dynamic literals
    for pat in DYNAMIC_PATTERNS:
        text = pat.sub("<NUMERIC_TOKEN>", text)

    return text.strip()


def normalize_json(raw: str) -> str:
    data = json5.loads(raw)  # parse lenient JSON5
    # Normalize for embedding (stable order + tight separators)
    return json.dumps(data, sort_keys=True, separators=(",", ":"))
