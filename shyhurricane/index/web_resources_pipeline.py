import datetime
import hashlib
import json
import logging
import subprocess
import sys
from math import floor
from typing import List, Optional, Dict, Any, Tuple

from bs4 import SoupStrainer
from haystack import component, Document, Pipeline
from haystack.components.embedders import SentenceTransformersDocumentEmbedder
from haystack.components.joiners import ListJoiner
from haystack.components.preprocessors import DocumentSplitter, DocumentCleaner
from haystack.components.routers import ConditionalRouter
from haystack.document_stores.types import DuplicatePolicy
from haystack_integrations.document_stores.chroma import ChromaDocumentStore

from shyhurricane.clean_css import normalize_css
from shyhurricane.cleaners import normalize_html, normalize_xml, normalize_json
from shyhurricane.doc_type_model_map import map_mime_to_type, doc_type_to_model, \
    get_chroma_collection_name_by_doc_type_token_length
from shyhurricane.generator_config import GeneratorConfig
from shyhurricane.retrieval_pipeline import create_chrome_document_store
from shyhurricane.utils import IngestableRequestResponse, urlparse_ext, BeautifulSoupExtractor, extract_domain, \
    parse_to_iso8601, remove_unencodable, is_katana_jsonl, is_har_json, is_http_raw, unix_command_image

logger = logging.getLogger(__name__)

# Change this when previously indexed data becomes obsolete
WEB_RESOURCE_VERSION = 1


def is_binary(content: str, mime_type: str) -> bool:
    """
    Detect if the content is binary based on the raw MIME type and content.
    """
    mime_category = mime_type.split("/")[0]
    if mime_category == "text" or mime_category == "application/javascript":
        return False
    if mime_category in [
        "video",
        "audio",
        "font",
        "binary",
    ]:
        return True
    if mime_category == "image":
        return mime_type not in ["image/svg+xml", "image/svg"]
    if mime_type in [
        "application/octet-stream",
        "application/pdf",
        "application/x-pdf",
        "application/zip",
        "application/x-zip-compressed",
        "application/x-protobuf",
        "application/font-woff",
        "application/font-woff2",
        "application/vnd.ms-fontobject",
    ]:
        return True
    if mime_type.endswith("+json") or mime_type.endswith("+xml"):
        return False
    if not content.strip():
        return False
    try:
        sample = content.encode("utf-8", errors="ignore")[:1024]
        if not sample:
            return False
        high = sum(b > 127 for b in sample)
        low = sum(b <= 127 for b in sample)
        return high > 0.15 * max(low, 1)
    except Exception:
        return False


def _deobfuscate_javascript(content: str) -> str:
    if not content:
        return content

    docker_command = ["docker", "run", "--rm", "-i", unix_command_image(), 'timeout', '--preserve-status',
                      '--kill-after=1m', '90s', '/usr/share/wakaru/wakaru.cjs']
    logger.info(f"Deobfuscating javascript with command {' '.join(docker_command)}")
    proc = subprocess.Popen(docker_command, universal_newlines=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)
    result = ""
    try:
        proc.stdin.write(content)
        proc.stdin.close()
        while proc.poll() is None:
            line_out = proc.stdout.readline()
            if line_out:
                result += line_out
        # read any buffered output
        while True:
            line_out = proc.stdout.readline()
            if not line_out:
                break
            result += line_out
    except EOFError:
        pass

    return_code = proc.wait()
    if return_code != 0 or not result.strip():
        logger.warning("Deobfuscating javascript failed with exit code %d", return_code)
        return content
    else:
        logger.info("Deobfuscating javascript completed, from %d bytes to %d bytes", len(content), len(result))
        return result


@component
class KatanaDocument:
    def __init__(self):
        self._empty_response = {"request_responses": []}

    @component.output_types(request_responses=List[IngestableRequestResponse])
    def run(self, text: str | dict):
        if isinstance(text, dict):
            entry = text
        else:
            entry = json.loads(str(text))
            # TODO: Handle JSONDecodeError
        if "request" not in entry:
            logger.warning("Missing request")
            return self._empty_response
        if "response" not in entry:
            logger.warning("Missing response")
            return self._empty_response
        if "status_code" not in entry["response"]:
            logger.info("No status_code, usually indicates out of scope")
            return self._empty_response
        if "endpoint" not in entry["request"]:
            logger.info("No endpoint")
            return self._empty_response

        url = entry["request"]["endpoint"]
        try:
            urlparse_ext(url)
        except Exception:
            logger.warning(f"Malformed URL: {url}")
            return self._empty_response

        timestamp = entry["timestamp"]  # 2025-06-28T22:52:07.882000
        response_body: Optional[str] = entry.get("response", {}).get("body", None)
        status_code = entry["response"].get("status_code", 200)
        http_method = entry["request"].get("method", "").upper()
        request_headers = self._title_case_header(entry["request"].get("headers", {}))
        request_headers.pop("raw", None)
        response_headers = self._title_case_header(entry["response"].get("headers", {}))
        response_headers.pop("raw", None)
        response_rtt: Optional[float] = entry.get("response", {}).get("rtt", None)
        technologies = entry["response"].get("technologies", [])
        if not isinstance(technologies, list):
            technologies = [str(technologies)]
        forms = entry.get("response", {}).get("forms", None)

        request_response = IngestableRequestResponse(
            url=url,
            timestamp=timestamp,
            method=http_method,
            request_headers=request_headers,
            request_body=response_body,
            response_code=status_code,
            response_headers=response_headers,
            response_body=response_body,
            response_rtt=response_rtt,
            technologies=technologies,
            forms=forms,
        )
        return {"request_responses": [request_response]}

    def _title_case_header(self, katana_headers: Dict[str, str]) -> Dict[str, str]:
        result = dict()
        for k, v in katana_headers.items():
            result[k.replace('_', '-').title()] = v
            pass
        return result


@component
class HttpRawDocument:
    def __init__(self):
        self._empty_response = {"request_responses": []}

    @component.output_types(request_responses=List[IngestableRequestResponse])
    def run(self, text: str):
        return self._empty_response


@component
class HarDocument:
    def __init__(self):
        self._empty_response = {"request_responses": []}

    @component.output_types(request_responses=List[IngestableRequestResponse])
    def run(self, text: str):
        return self._empty_response


class SuffixIdSplitter(DocumentSplitter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _split_document(self, doc) -> List[Document]:
        parts = super()._split_document(doc)
        for i, p in enumerate(parts):
            p.id = f"{doc.id}_{i}"
            if "_split_overlap" in p.meta:
                split_overlap = p.meta["_split_overlap"]
                if not isinstance(split_overlap, str) and not isinstance(split_overlap, int):
                    p.meta["_split_overlap"] = json.dumps(split_overlap)
        return parts


def _quantize_timestamp(timestamp: str):
    """
    quantize timestamp to avoid too many duplicate results
    """
    # one document per URL per day
    return timestamp[0:11]


def _build_splitters(embedders: Dict[str, SentenceTransformersDocumentEmbedder]):
    splitters: Dict[str, SuffixIdSplitter] = dict()
    for doc_type_model in doc_type_to_model.values():
        embedder = embedders[doc_type_model.doc_type]
        for token_length in (doc_type_model.token_lengths or [sys.maxsize]):
            max_model_length = embedder.embedding_backend.model.max_seq_length
            # treat "infinite" as 512
            if max_model_length > 1_000_000:
                max_model_length = 512
            target_token_length = min(token_length, max_model_length)
            split_len = int(floor(target_token_length * 0.93) / 2)
            overlap = int(floor(target_token_length * 0.06))
            logger.info(
                f"Splitting document {doc_type_model.doc_type} by {split_len} words, overlap {overlap} (target {token_length} tokens, model has {max_model_length} tokens)")
            splitter = SuffixIdSplitter(
                split_by="word",
                split_length=split_len,
                split_overlap=overlap,
            )
            splitter.warm_up()
            splitters[doc_type_model.get_chroma_collection(token_length)] = splitter
    return splitters


@component
class RequestResponseToDocument:
    def __init__(self, embedders: Dict[str, Any]):
        self.embedders = embedders
        self._soup_extractor = BeautifulSoupExtractor()
        self._title_soup_strainer = SoupStrainer(['title', 'meta'])

    @component.output_types(documents=List[Document])
    def run(self, request_responses: List[IngestableRequestResponse]):
        docs = []
        for rr in (request_responses or []):
            docs.extend(self._to_documents(rr))
        return {"documents": docs}

    def _embed_single(self, doc: Document) -> Document:
        doc_type = doc.meta["type"]
        embedder = self.embedders.get(doc_type, self.embedders["default"])
        embedded_docs = embedder.run(documents=[Document(content=doc.content[0:4096])])["documents"]
        doc.embedding = embedded_docs[0].embedding
        return doc

    def _to_documents(self, request_response: IngestableRequestResponse) -> List[Document]:
        url = request_response.url
        try:
            url_parsed = urlparse_ext(url)
            host = url_parsed.hostname.lower()
            port = url_parsed.port
            netloc = f"{host}:{port}"
            domain = extract_domain(host)
        except Exception:
            logger.warning(f"Malformed URL: {url}")
            return []

        try:
            timestamp, timestamp_float = parse_to_iso8601(request_response.timestamp)
        except ValueError:
            timestamp_float = datetime.datetime.now().timestamp()
            timestamp = datetime.datetime.now().isoformat()

        timestamp_for_id = _quantize_timestamp(timestamp)
        request_headers = request_response.request_headers
        response_body = remove_unencodable(request_response.response_body)
        response_headers = request_response.response_headers
        raw_mime = response_headers.get("Content-Type", "").lower().split(";")[0].strip()
        technologies_str = json.dumps(request_response.technologies or [], indent=None, separators=(',', ':'),
                                      sort_keys=True)

        title: Optional[str] = None
        description: Optional[str] = None
        if response_body and raw_mime == "text/html":
            title, description = self._soup_extractor.extract(response_body)

        base_meta = {
            "version": WEB_RESOURCE_VERSION,
            "url": url,
            "netloc": netloc,
            "host": host,
            "port": port,
            "domain": domain,
            "timestamp": timestamp,
            "timestamp_float": timestamp_float,
            "content_type": raw_mime,
            "status_code": request_response.response_code,
            "http_method": request_response.method,
            "technologies": technologies_str,
        }
        if title:
            base_meta["title"] = title
        if description:
            base_meta["description"] = description
        if request_response.response_rtt is not None:
            base_meta["response_rtt"] = request_response.response_rtt

        documents = []

        # ─ Content Document (if body is present)
        if response_body and not is_binary(response_body, raw_mime):
            doc = Document(
                content=response_body,
                meta=base_meta | {
                    "type": "content",
                    "token_length": doc_type_to_model.get("content").get_primary_token_length(),
                    "request_headers": json.dumps(request_headers),
                    "response_headers": json.dumps(response_headers),
                },
                id=hashlib.sha256(f"{url}:content:{timestamp_for_id}".encode()).hexdigest()
            )
            documents.append(self._embed_single(doc))

        # ─ Network Document (always)
        sorted_request_headers = "\n".join(
            f"{k}: {v}" for k, v in sorted(request_headers.items())
        )
        sorted_response_headers = "\n".join(
            f"{k}: {v}" for k, v in sorted(response_headers.items())
        )
        net_text = (
                "--- HTTP Request Headers ---\n" +
                sorted_request_headers +
                "\n--- HTTP Response Headers ---\n" +
                sorted_response_headers
        )

        net_doc = Document(
            content=net_text,
            meta=base_meta | {
                "type": "network",
                "token_length": doc_type_to_model.get("network").get_primary_token_length(),
                "description": "HTTP request and response headers",
                "content_type": "text/plain"
            },
            id=hashlib.sha256(f"{url}:network:{timestamp_for_id}".encode()).hexdigest()
        )
        documents.append(self._embed_single(net_doc))

        # ─ HTML forms
        if request_response.forms:
            sorted_forms = sorted(request_response.forms,
                                  key=lambda f: f.get("method", "GET") + "." + f.get("action", ""))
            forms_doc = Document(
                content=json.dumps(sorted_forms, indent=None, separators=(',', ':'), sort_keys=True),
                meta=base_meta | {
                    "type": "forms",
                    "token_length": doc_type_to_model.get("forms").get_primary_token_length(),
                    "description": "HTTP form information in JSON format",
                    "content_type": "text/json"
                },
                id=hashlib.sha256(f"{url}:forms:{timestamp_for_id}".encode()).hexdigest()
            )
            documents.append(self._embed_single(forms_doc))

        return documents


@component
class FilterExistingDocuments:
    def __init__(self, stores: Dict[str, ChromaDocumentStore]):
        self.stores = stores

    @component.output_types(documents=List[Document])
    def run(self, documents: List[Document]):
        new_documents = []
        for doc in documents:
            url = doc.meta.get("url", "")
            raw_mime = doc.meta.get("content_type", "")
            timestamp = doc.meta.get("timestamp", "")
            if not url or not raw_mime or not timestamp:
                continue

            doc_type = map_mime_to_type(raw_mime)
            token_length = doc.meta.get("token_length", sys.maxsize)
            store = self.stores.get(get_chroma_collection_name_by_doc_type_token_length(doc_type, token_length))
            if store is None:
                continue

            filters = {
                "operator": "AND",
                "conditions": [
                    {"field": "meta.version", "operator": "==", "value": WEB_RESOURCE_VERSION},
                    {"field": "meta.url", "operator": "==", "value": url},
                    {"field": "meta.timestamp", "operator": "==", "value": timestamp}
                ]}
            logger.debug("Checking for existing document: doc_type %s, filters %s", doc_type, filters)
            result = store.filter_documents(filters=filters)
            if len(result) == 0:
                new_documents.append(doc)
            else:
                logger.info("Skipping existing document %s", doc.id)

        return {"documents": new_documents}


@component
class IndexDocTypeDocuments:
    def __init__(
            self,
            embedders: Dict[str, Any],
            doc_cleaner: DocumentCleaner
    ) -> None:
        self.embedders = embedders
        self.doc_cleaner = doc_cleaner
        self.splitters: Dict[str, SuffixIdSplitter] = dict()

    def warm_up(self):
        if not self.splitters:
            self.splitters = _build_splitters(self.embedders)

    @component.output_types(documents=List[Document])
    def run(self, documents: List[Document]):
        results: List[Document] = []

        for doc in documents:
            results.append(doc)  # always update in case the title/description was improved

            if not doc.content:
                continue

            url = doc.meta.get("url", "")
            raw_mime = doc.meta.get("content_type", "")
            timestamp_for_id = _quantize_timestamp(doc.meta.get("timestamp", ""))
            if not url or not raw_mime or not timestamp_for_id:
                logger.info(f"Skipping {doc.id} for missing url, raw_mime, or timestamp_for_id")
                continue

            if is_binary(doc.content, raw_mime):
                logger.info(f"Skipping {url} ({raw_mime}) binary content")
                continue

            # Map MIME to a logical doc type
            doc_type = map_mime_to_type(raw_mime)

            normalized_content = doc.content
            try:
                if doc_type == "javascript":
                    normalized_content = _deobfuscate_javascript(normalized_content)
                elif doc_type == "html":
                    normalized_content = normalize_html(normalized_content)
                elif doc_type == "xml":
                    normalized_content = normalize_xml(normalized_content)
                elif doc_type == "json":
                    normalized_content = normalize_json(normalized_content)
                elif doc_type == "css":
                    normalized_content = normalize_css(normalized_content)
                else:
                    normalized_content = \
                        self.doc_cleaner.run(documents=[Document(content=normalized_content)])["documents"][0].content
            except Exception as e:
                logger.warning(f"Normalizing content failed, continuing with original content: {e}")

            if normalized_content != doc.content:
                if len(normalized_content) < len(doc.content) / 2:
                    logger.warning(
                        f"Normalized content for {doc_type} reduced {len(doc.content)} bytes to {len(normalized_content)} bytes")
                doc.content = normalized_content
                response_headers = json.loads(doc.meta.get("response_headers", "{}"))
                response_headers["Content-Length"] = str(len(normalized_content))
                doc.meta["response_headers"] = json.dumps(response_headers)

            for token_length in (doc_type_to_model.get(doc_type).token_lengths or [sys.maxsize]):
                # create docs per token_length
                new_doc = Document(
                    content=doc.content,
                    meta=doc.meta.copy() | {"type": doc_type, "token_length": token_length},
                    id=hashlib.sha256(f"{url}:{doc_type}:{token_length}:{timestamp_for_id}".encode()).hexdigest()
                )
                collection_name = get_chroma_collection_name_by_doc_type_token_length(doc_type, token_length)
                split_docs = self.splitters[collection_name].run(documents=[new_doc])["documents"]
                embedder = self.embedders.get(doc_type, self.embedders["default"])
                results.extend(embedder.run(documents=split_docs)["documents"])

        return {"documents": results}


@component
class IngestMultiStore:
    def __init__(self, stores: Dict[str, ChromaDocumentStore], should_update=None) -> None:
        self.stores = stores
        self.should_update = should_update

    @staticmethod
    def _update_document(doc: Document, store: ChromaDocumentStore):
        store._ensure_initialized()
        assert store._collection is not None
        data = store._convert_document_to_chroma(doc)
        if data is not None:
            store._collection.update(**data)

    @component.output_types(documents=List[Document])
    def run(self, documents: List[Document]):
        for doc in documents:
            doc_type = "???"
            try:
                doc_type = doc.meta.get("type")
                token_length = doc.meta.get("token_length", sys.maxsize)
                collection_name = get_chroma_collection_name_by_doc_type_token_length(doc_type, token_length)
                store = self.stores.get(collection_name)
                if store is None:
                    logger.error(f"No store for {collection_name}")
                elif self.should_update and self.should_update(doc):
                    self._update_document(doc, store)
                else:
                    store.write_documents([doc], policy=DuplicatePolicy.OVERWRITE)
            except Exception as e:
                logger.warning(f"Document {doc_type} {doc.id} not written to the store: {e}", e)

        return {"documents": documents}


@component
class GenerateTitleAndDescription:
    prompt: str = """
      You are a web site content analyst. You are good at summarizing the content of a web resource, whether it be
      HTML, text, javascript or css, into a short title and 2-3 sentence description. The consumer of the title and
      description is another LLM such as yourself.

      Structure:
      Output the title and description information as a valid JSON object. Only output the JSON. Do not include any other text except the JSON.
      Ensure the JSON values have proper string escaping.

      The title uses the key "title" and the value is a string. It should be between 5 and 30 words long.

      The description uses the key "description" and the value is a string. It should be about 2 or 3 sentences.

      Your Task:
      Query: "%s"
      JSON title and description:
"""

    def __init__(self, generator_config: GeneratorConfig):
        self.generator = generator_config.create_generator()

    @component.output_types(documents=List[Document])
    def run(self, documents: List[Document]):
        cached_title = {}
        cached_description = {}
        for doc in documents:
            if doc.meta.get("status_code", 0) != 200:
                continue
            if doc.meta.get("type") in ["network"]:
                continue
            url = None
            if 'url' in doc.meta:
                url = doc.meta["url"]
                if url in cached_title and "title" not in doc.meta:
                    doc.meta["title"] = cached_title[url]
                if url in cached_description and "description" not in doc.meta:
                    doc.meta["description"] = cached_description[url]
            if doc.content and "title" not in doc.meta or "description" not in doc.meta:
                try:
                    result = self.generator.run(prompt=self.prompt % (doc.content[0:2048])).get("replies", ["{}"])[-1]
                    parsed = json.loads(result)
                    logger.info(f"title_and_desc: {doc.meta.get('type', '')} {result}")
                    if "title" in parsed and "title" not in doc.meta:
                        doc.meta["title"] = str(parsed["title"])
                        if url:
                            cached_title[url] = doc.meta["title"]
                    if "description" in parsed and "description" not in doc.meta:
                        doc.meta["description"] = str(parsed["description"])
                        if url:
                            cached_description[url] = doc.meta["description"]
                except Exception:
                    pass

        return {"documents": documents}


def _build_store_and_embedders(db: str) -> Tuple[
    Dict[str, ChromaDocumentStore], Dict[str, SentenceTransformersDocumentEmbedder]]:
    stores: Dict[str, ChromaDocumentStore] = {}
    embedders = {}
    embedder_cache = {}
    for doc_type_model in doc_type_to_model.values():
        model_name = doc_type_model.model_name
        if model_name in embedder_cache:
            embedder = embedder_cache[model_name]
        else:
            embedder = SentenceTransformersDocumentEmbedder(
                model=model_name,
                batch_size=1,
                normalize_embeddings=True,
                progress_bar=False,
                model_kwargs={
                    "attn_implementation": "eager",
                },
            )
            embedder.warm_up()
            embedder_cache[model_name] = embedder
        embedders[doc_type_model.doc_type] = embedder

        for col in doc_type_model.get_chroma_collections():
            document_store = create_chrome_document_store(
                db=db,
                collection_name=col,
            )
            document_store.count_documents()  # ensure the collection exists
            stores[col] = document_store

    return stores, embedders


def build_ingest_pipeline(db: str) -> Pipeline:
    stores, embedders = _build_store_and_embedders(db)

    pipe = Pipeline()

    input_format_routes = [
        {
            "condition": "{{ text|is_katana_jsonl }}",
            "output": ["{{ text }}"],
            "output_name": ["katana_jsonl"],
            "output_type": [str],
        },
        {
            "condition": "{{ text|is_har_json }}",
            "output": ["{{ text }}"],
            "output_name": ["har_json"],
            "output_type": [str],
        },
        {
            "condition": "{{ text|is_http_raw }}",
            "output": ["{{ text }}"],
            "output_name": ["http_raw_text"],
            "output_type": [str],
        },
        # ConditionalRouter will fail if a path isn't taken
        {
            "condition": "{{ True }}",
            "output": ["{{ text }}"],
            "output_name": ["input_failure"],
            "output_type": [str],
        },
    ]
    custom_filters = {
        "is_katana_jsonl": is_katana_jsonl,
        "is_har_json": is_har_json,
        "is_http_raw": is_http_raw,
    }

    pipe.add_component("input_router", ConditionalRouter(routes=input_format_routes, custom_filters=custom_filters))
    pipe.add_component("katana_document", KatanaDocument())
    pipe.add_component("raw_document", HttpRawDocument())
    pipe.add_component("har_document", HarDocument())

    pipe.add_component("rr_joiner", ListJoiner(List[IngestableRequestResponse]))
    pipe.add_component("request_response_to_document", RequestResponseToDocument(embedders=embedders))

    pipe.add_component("output", IngestMultiStore(stores))

    pipe.connect("input_router.katana_jsonl", "katana_document.text")
    pipe.connect("input_router.http_raw_text", "raw_document.text")
    pipe.connect("input_router.har_json", "har_document.text")

    pipe.connect("katana_document", "rr_joiner")
    pipe.connect("raw_document", "rr_joiner")
    pipe.connect("har_document", "rr_joiner")

    pipe.connect("rr_joiner", "request_response_to_document")
    pipe.connect("request_response_to_document", "output")

    return pipe


def build_doc_type_pipeline(
        db: str,
        generator_config: GeneratorConfig,
) -> Pipeline:
    stores, embedders = _build_store_and_embedders(db)

    doc_cleaner = DocumentCleaner(
        keep_id=True,
        remove_empty_lines=True,
        remove_extra_whitespaces=True,
        unicode_normalization='NFKC',
        # ascii_only=True,
    )

    pipe = Pipeline()

    pipe.add_component("input", FilterExistingDocuments(stores=stores))
    pipe.add_component("gen_title", GenerateTitleAndDescription(generator_config))
    pipe.add_component("gen_doc_type", IndexDocTypeDocuments(embedders=embedders, doc_cleaner=doc_cleaner))
    pipe.add_component("store", IngestMultiStore(stores, should_update=lambda d: d.meta.get("type") == "content"))

    pipe.connect("input", "gen_title")
    pipe.connect("gen_title", "gen_doc_type")
    pipe.connect("gen_doc_type", "store")

    return pipe
