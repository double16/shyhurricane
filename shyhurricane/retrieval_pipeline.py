import json
import logging
import os
from dataclasses import replace
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

import yaml
from haystack import Document, Pipeline, component
from haystack.components.builders import PromptBuilder
from haystack.core.component import Component
from haystack.dataclasses import ChatMessage
from haystack_integrations.components.retrievers.qdrant import QdrantHybridRetriever
from haystack_integrations.document_stores.qdrant import QdrantDocumentStore

from shyhurricane.db import create_qdrant_document_store
from shyhurricane.doc_type_model_map import SPARSE_EMBEDDING_MODEL, doc_type_to_model, get_qdrant_collections
from shyhurricane.generator_config import GeneratorConfig
from shyhurricane.structured_generation import (
    EvidenceClassification,
    QueryExpansion,
    Vulnerabilities,
    WebsiteContext,
    query_expansion_schema,
)
from shyhurricane.utils import documents_sort_unique

logger = logging.getLogger(__name__)


@component
class CombineDocs:
    def __init__(self, collections: Iterable[str]) -> None:
        input_types = {k: List[Document] for k in collections}
        component.set_input_types(self, **input_types)

    @component.output_types(documents=List[Document])
    def run(self, doc_types: Iterable[str], **kwargs):
        merged = []
        for docs in kwargs.values():
            merged.extend(docs)

        # increase score when document is from doc_type
        if doc_types:
            for index, doc in enumerate(merged):
                if doc.meta.get("type", None) in doc_types and doc.score:
                    merged[index] = replace(doc, score=doc.score * 10)
        merged.sort(key=lambda d: (d.score or 0, d.meta.get("timestamp_float", 0)), reverse=True)
        return {"documents": merged}


@component
class TraceDocs:
    """
    Stores queries and documents into a file for debugging.
    """

    def __init__(self, file: str | os.PathLike[str] = "trace_documents.md") -> None:
        self.file = file

    @component.output_types()
    def run(self, query: str, expanded_queries: List[str], documents: List[Document]):
        with open(self.file, "a", encoding="utf-8") as f:
            f.write(f"# Q: {query}\n\n")
            f.write("## Q expanded:\n")
            for eq in expanded_queries:
                f.write(f"- {eq}\n")
            f.write("\n")
            for doc in documents:
                f.write(f"## {doc.meta["url"]}\n")
                f.write(f"Score: {doc.score}\n\n")
                f.write(doc.content[0:1024])
                f.write("\n\n")
            f.write("\n\n---\n\n")
        return {}


@component
class Query:
    @component.output_types(text=str, filters=Dict[str, Any], max_results=int,
                            targets=Iterable[str], doc_types=Iterable[str],
                            progress_callback=Callable[[str], None])
    def run(
            self,
            text: str,
            filters: Optional[Dict[str, Any]] = None,
            targets: Optional[Iterable[str]] = None,
            doc_types: Optional[Iterable[str]] = None,
            max_results: Optional[int] = None,
            progress_callback: Optional[Callable[[str], None]] = None
    ):
        max_results = min(1000, max(1, max_results or 100))
        targets = list(filter(bool, targets or []))
        return {
            "text": text,
            "filters": filters or {},
            "targets": targets or [],
            "doc_types": doc_types or [],
            "max_results": max_results,
            "progress_callback": progress_callback,
        }


vuln_type_prompt = """
Classify the CURRENT QUERY at the end of this message.
Return JSON candidates, each with vuln_type and evidence copied from the CURRENT QUERY.
Read the entire query. Include ALL explicitly named classes and directly supported inferences.
Do not stop after the first candidate. Each candidate needs a supporting exact query substring.
Do not copy evidence from these instructions or examples.
Use the shortest relevant phrase. Preserve punctuation exactly; quote a class name alone
rather than combining separated phrases and removing quotes or operators.
Select each class once, even if multiple phrases support it.
For an explicit list of vulnerability classes, return EVERY named class (including LDAP Injection).
The schema enum defines valid vocabulary, not a checklist.
An empty query or neutral inventory returns {"candidates": []}.
Forms, inputs, parameters, POST, GET, search, checkout, payment and booking ALONE
do not imply SQL Injection, NoSQL Injection, or any other vulnerability.
Authentication or login suggests Weak Authentication.
Authentication bypass/session weaknesses also suggest Broken Access Control and
Security Misconfiguration.
Generic injection requires SQL Injection, NoSQL Injection, Command Injection,
Code Injection and Template Injection, with the same evidence "injection".
Outdated components imply Unpatched Software and Security Misconfiguration.
Supply chain suggests Unpatched Software. Untrusted updates, software integrity and data
integrity suggest Security Misconfiguration and Insecure Deserialization.
DOM sinks innerHTML/document.write imply XSS. eval implies XSS and Code Injection.
postMessage without origin check implies Insecure PostMessage.
CSP implies CSP Misconfiguration and Security Misconfiguration.
IDOR/access control implies IDOR and Broken Access Control.
Vulnerable cookies imply Broken Access Control and Sensitive Data Exposure.
Include no unrelated types.
Checkout, payment, booking and search are inventory words, never evidence for
Broken Access Control, Security Misconfiguration or injection.
A query with login and inventory words needs only Weak Authentication.
Use Broken Access Control/Security Misconfiguration for authentication bypass or
session weaknesses, not for a simple login inventory.
Keep evidence short (prefer one or two words) and return compact JSON.
Do not repeat a vuln_type with different evidence.

Examples (never use these evidence strings unless they occur in the CURRENT QUERY):
Query: IDOR or access control
Response: {"candidates": [
{"vuln_type": "IDOR", "evidence": "IDOR"},
{"vuln_type": "Broken Access Control", "evidence": "access control"}]}
Query: authentication bypass
Response: {"candidates": [
{"vuln_type": "Weak Authentication", "evidence": "authentication bypass"},
{"vuln_type": "Broken Access Control", "evidence": "authentication bypass"},
{"vuln_type": "Security Misconfiguration", "evidence": "authentication bypass"}]}
Query: supply chain software integrity
Response: {"candidates": [
{"vuln_type": "Unpatched Software", "evidence": "supply chain"},
{"vuln_type": "Security Misconfiguration", "evidence": "software integrity"},
{"vuln_type": "Insecure Deserialization", "evidence": "software integrity"}]}
Query: forms inputs parameters POST GET search checkout payment booking
Response: {"candidates": []}
Query: XSS
Response: {"candidates": [{"vuln_type": "XSS", "evidence": "XSS"}]}
Query: SQL injection OR XSS
Response: {"candidates": [
{"vuln_type": "SQL Injection", "evidence": "SQL injection"},
{"vuln_type": "XSS", "evidence": "XSS"}]}
Query: Examine the authentication mechanism
Response: {"candidates": [
{"vuln_type": "Weak Authentication", "evidence": "authentication"}]}
Query: POST form login checkout payment booking search
Response: {"candidates": [
{"vuln_type": "Weak Authentication", "evidence": "login"}]}
Query: forms inputs parameters POST GET search checkout payment booking
Response: {"candidates": []}

CURRENT QUERY:
{{ query }}
END CURRENT QUERY
Return all and only supported candidates with evidence copied from CURRENT QUERY.
"""



query_expander_structure = """
Structure:
Output format:
 - Output a JSON object with a "queries" array of strings.
 - Each pattern must be at most 256 characters, including newlines.
 - Use focused snippets rather than full documents or long lists of fields.
 - Escape newlines and quotes inside strings.
 - Only output the JSON object.
 - Do not include any other text except the list of patterns.
 - Do not include any explanation or commentary.
 - Do not format using markdown or other markup language.
 - Exclude patterns that are only whitespace.
 - If no relevant patterns exist, return {"queries": []}. Never echo the input as a pattern.
 - Return at most {{ number }} patterns in total, regardless of the number of vulnerabilities.
 - Select a high-value, concise set that covers the supplied input across relevant vulnerabilities.
 - Prefer complementary patterns over redundant variations; do not pad the set to meet the count.
 - Avoid duplicating patterns.
"""

query_expander_natural_language = """
You are a cybersecurity search assistant that processes users queries.
You expand a given query into up to {{ number }} queries in total that are similar in meaning, but specific to finding vulnerabilities. The expanded query should not be less specific. Infer vulnerabilities from the query.


""" + query_expander_structure.replace("patterns", "expanded queries") + """

Example output: {"queries": ["example pattern", "another pattern"]}

Your Task:
Query: "{{query}}"
Never include the URL, hostname or IP address in the expanded queries.
Expanded Queries:
"""

query_expander_javascript = """
You are a code pattern generator trained to identify insecure client-side JavaScript practices.


You will receive a single free-text input from the user. It may include:
- One or more vulnerability names (e.g., "XSS", "IDOR", "Open Redirect", etc.)
- Natural language phrases (e.g., "What uses eval or innerHTML?", "Check for anything vulnerable to DOM clobbering or open redirect")
- Informal combinations (e.g., "IDOR or XSS", "maybe eval too", "dangerous access patterns")

Your task:
1. Analyze the input and **infer all relevant client-side vulnerabilities or risky behaviors**.
2. Generate up to {{ number }} insecure client-side JavaScript patterns in total across all inferred items.

Code Pattern Requirements:
- Must be valid client-side JavaScript (ES5/ES6+)
- Must demonstrate insecure behavior
- Must not be tied to a specific app or domain
- Should use realistic client-side APIs (DOM, window/document, localStorage, etc.)
- Do NOT use Node.js or backend features
- Do NOT show secure or mitigated code—only vulnerable patterns
- Escape all code strings properly for JSON.
- Do not include explanations or comments.
- Keep patterns realistic and relevant to the client-side context.

""" + query_expander_structure.replace("expanded queries", "patterns") + """

Example output: {"queries": ["example pattern", "another pattern"]}

Now, given a single unstructured user input string, infer the vulnerabilities and generate {{ number }} insecure client-side JavaScript patterns in total across the input:

{{query}}
"""

query_expander_css = """
You are a static code analysis assistant that receives user queries containing hints about web security vulnerabilities. From the user query, infer one or more common vulnerability types (e.g., XSS, information disclosure, insecure design, etc.) and generate {{ number }} generic CSS code patterns likely to exhibit or relate to those vulnerabilities.


Examples of inferred vulnerability types and sample pattern directions:

|Inferred Vulnerability  | Example Pattern Direction             |
|------------------------|---------------------------------------|
| Information disclosure | .debug { display: block; }            |
| Insecure design        | * { visibility: visible !important; } |
| Authentication         | #admin-login { display: block; }      |

Capabilities:
 - Handle multiple vulnerability types in a single input.
 - Recognize synonyms and related keywords.
 - Detect implications.
 - Recognize both code-level and logic-level vulnerabilities.

""" + query_expander_structure.replace("expanded queries", "patterns") + """
- Each pattern should be a valid CSS snippet (selector + rules), inline style, or injection-prone usage.

Now, given a single unstructured user input string, infer the vulnerabilities and generate {{ number }} insecure CSS patterns in total across the input:

{{query}}
"""

query_expander_html = """
You are a static code analysis assistant that receives user queries containing hints about web security vulnerabilities. From the user query, infer one or more common vulnerability types (e.g., XSS, SQLi, IDOR, insecure deserialization, etc.) and generate {{ number }} generic HTML code patterns likely to exhibit or relate to those vulnerabilities.


Examples of inferred vulnerability types and sample pattern directions:

|Inferred Vulnerability   | Example Pattern Direction                       |
|-------------------------|-------------------------------------------------|
|XSS	                  | <input> reflected into DOM unsanitized          |
|SQLi                     | <form> with suspect SQL-like input names        |
|IDOR                     | Hidden fields with user IDs in forms            |
|SSRF                     | <input> fields accepting URLs or IPs            |
|Misconfiguration         | Comments with stack traces or debug info        |
|Sensitive Data Exposure  | Fields named like “key”, “token”, “.env”        |
|Weak Auth/Session        | Login forms with autocomplete or insecure attrs |
|Insecure Deserialization | JavaScript using JSON.parse(untrusted_input)    |
|Template Injection       | {{user}} in HTML with no escaping               |
|Outdated Components      | Script tags with versioned paths or CDNs        |

Capabilities:
 - Handle multiple vulnerability types in a single input.
 - Recognize synonyms and related keywords.
 - Detect implications, such as “What calls eval()?” infers insecure JS execution.
 - Recognize both code-level and logic-level vulnerabilities.
 - For technology specific patterns, vary the technology used. For example: do not only consider PHP.

""" + query_expander_structure.replace("expanded queries", "patterns") + """
 - Each pattern should be a generic HTML snippet (possibly including inline JavaScript or HTML forms) designed to match vulnerable structures.
 - You must infer the vulnerability types from the input text; assume the input may use synonyms or descriptions instead of standard names.

Now, given a single unstructured user input string, infer the vulnerabilities and generate {{ number }} insecure HTML patterns in total across the input:

{{query}}
"""

query_expander_xml = """
You are a static code and traffic analysis assistant that receives user queries describing potential web application vulnerabilities. From the user query, infer one or more common vulnerability types (e.g., XXE, SSRF, IDOR, insecure deserialization, etc.), and generate {{ number }} generic XML data patterns likely to exhibit or relate to those vulnerabilities. Consider the XML to be data or configuration, not HTML or source code.


Examples of inferred vulnerability types and sample pattern directions:

|Inferred Vulnerability    | Example Pattern Direction                               |
|--------------------------|---------------------------------------------------------|
| XXE / SSRF               | External entity injections                              |
| Insecure Deserialization | Base64 or serialized binary blobs in tags               |
| IDOR / Access Control    | Direct reference to user IDs                            |
| Sensitive Data Exposure  | API keys, passwords, encryption keys in plaintext       |
| XPath Injection          | Dynamic filter strings with unvalidated user input      |
| Insecure Configuration   | Debug flags, default credentials, exposed admin configs |
| Broken Authentication    | Weak password policies or session tokens in XML         |

Capabilities:
 - Infer vulnerabilities from the actual input; the table lists possibilities, not a checklist.
 - Cover only the vulnerabilities requested or implied by the input.
 - Handle multiple vulnerability types in a single input.
 - Recognize synonyms and related keywords.
 - Detect implications.
 - Patterns must be valid XML snippets that would appear in XML.
 - XXE means XML external entity injection. For XXE or external entity requests, prioritize
   DOCTYPE declarations with external ENTITY definitions (SYSTEM or PUBLIC) and entity references.
 - Keep external entity syntax together in a compact snippet; use example.com for example URLs.
 - Do not substitute generic debug settings, API keys, credentials, or user IDs for XXE patterns
   unless those are also requested by the input.
 - Only output the patterns, do not include comments or titles.
 - Ensure patterns are varied and reflect plausible real-world vulnerable constructs.

""" + query_expander_structure.replace("expanded queries", "patterns") + """

Example input: "XXE"
Example output for a one-pattern request:
{"queries": ["<!DOCTYPE root [<!ENTITY xxe SYSTEM 'https://example.com/entity'>]><root>&xxe;</root>"]}

Now, given a single unstructured user input string, infer the vulnerabilities and generate {{ number }} insecure XML data patterns in total across the input:

{{query}}
"""

query_expander_network = """
You are a static code and traffic analysis assistant that receives queries describing potential web application vulnerabilities. From the user query, infer one or more common vulnerability types (e.g., XSS, SQLi, IDOR, SSRF, weak authentication, insecure deserialization, etc.), and generate {{ number }} HTTP header name/value combinations likely to indicate these vulnerabilities.


Capabilities:
 - Handle multiple vulnerability types in a single input.
 - Recognize synonyms and related keywords.
 - Detect implications, such as “How can I run code in the browser?” infers cross-site scripting (XSS).
 - Recognize both code-level and logic-level vulnerabilities.

""" + query_expander_structure.replace("expanded queries", "patterns") + """
 - Each string must be an HTTP header name and header value separated by ": ".
 - Only include HTTP header names and header values, do not include explanation or vulnerability types.
 - Header values may be exact, partial, or suggestive of vulnerability conditions.
 - Ensure outputs span both request and response headers where applicable.

Example output: {"queries": ["Set-Cookie: session=abc", "Content-Security-Policy: unsafe-inline"]}

Now, given a single unstructured user input string, infer the vulnerabilities and generate {{ number }} insecure HTTP headers and values in total across the input:

{{query}}
"""


@component
class VulnTypeParser:

    @component.output_types(vuln_types=Iterable[str])
    def run(self, replies: List[str], query: str = ""):
        vuln_types: Set[str] = set()
        normalized_query = " ".join(query.casefold().split())
        for reply in replies:
            try:
                parsed = json.loads(reply)
                if isinstance(parsed, dict) and "candidates" in parsed:
                    candidates = EvidenceClassification.model_validate(parsed).candidates
                    retained = [c.vuln_type for c in candidates
                                if c.evidence.strip()
                                and " ".join(c.evidence.casefold().split()) in normalized_query]
                    logger.debug("Classification evidence proposed=%s retained=%s rejected=%s",
                                 len(candidates), len(set(retained)), len(candidates) - len(retained))
                    parsed = {"vuln_types": retained}
                if isinstance(parsed, dict):
                    parsed = parsed.get("vuln_types", [])
                validated = Vulnerabilities.model_validate({"vuln_types": parsed})
                vuln_types.update(label.lower().replace(" ", "_") for label in validated.vuln_types)
            except ValueError:
                pass
        logger.info(f"VulnTypeParser: {vuln_types}")
        return {"vuln_types": vuln_types}


@component
class QueryExpander:
    target_placeholders = ["example.com", "{NETLOC}"]
    def __init__(
            self,
            generator_config: GeneratorConfig,
            prompt: Optional[str] = None,
            doc_type: Optional[str] = None,
            number: int = 5,
            include_original_query: bool = True,
            temperature: float = 0.6,
    ):

        self.query_expansion_prompt = prompt
        self.doc_type = doc_type or "nl"
        self.number = number
        self.include_original_query = include_original_query
        if prompt is None:
            self.query_expansion_prompt = query_expander_natural_language
        builder = PromptBuilder(self.query_expansion_prompt, required_variables=["number", "query"])
        self.generator_config = generator_config
        self.temperature = temperature
        self.generation_limit = max(0, number)
        llm = generator_config.create_generator(
            temperature=temperature, response_schema=query_expansion_schema(self.generation_limit),
            max_output_tokens=4096,
        )
        self.pipeline = Pipeline()
        self.pipeline.add_component("builder", builder)
        self.pipeline.add_component("llm", llm)
        self.pipeline.connect("builder", "llm")

    @component.output_types(queries=List[str])
    def run(self, query: str, targets: Iterable[str], vuln_types: Iterable[str]):
        if self.number <= 1:
            return {"queries": [query]}

        expanded_set: Set[str] = set()

        logger.debug(f"vuln_types: {vuln_types}")
        if vuln_types:
            for vuln_type in vuln_types:
                vuln_query_path = os.path.join(os.path.dirname(__file__),
                                               "assets/query/" + vuln_type + "_" + self.doc_type + ".yaml")
                logger.debug(f"checking {vuln_query_path} for static expanded queries")
                if os.path.exists(vuln_query_path):
                    logger.info("Reading expanded queries from %s", vuln_query_path)
                    with open(vuln_query_path, "r") as f:
                        try:
                            expanded_set.update(QueryExpansion.model_validate(yaml.safe_load(f)).queries)
                        except (ValueError, yaml.YAMLError) as error:
                            raise ValueError(f"Invalid query asset: {vuln_query_path}") from error
        logger.debug(f"static expanded queries: {expanded_set}")

        # If there are static queries, make sure the LLM has a chance to add something
        expanded_set_number = max(self.number, len(expanded_set) + 3)

        retry = 2
        while retry > 0 and len(expanded_set) < expanded_set_number:
            retry -= 1
            number_left = expanded_set_number - len(expanded_set)

            if number_left != self.generation_limit:
                self.pipeline.remove_component("llm").close()
                llm = self.generator_config.create_generator(
                    temperature=self.temperature, response_schema=query_expansion_schema(number_left),
                    max_output_tokens=4096,
                )
                self.pipeline.add_component("llm", llm)
                self.pipeline.connect("builder", "llm")
                self.generation_limit = number_left
            run_result = self.pipeline.run({'builder': {'query': query, 'number': number_left}})
            replies: List[str] = run_result.get('llm', {}).get('replies', [])
            if not replies:
                continue
            result = replies[0]
            logger.info(f"Expanded query result:\n{result}")
            if not result:
                continue

            results = {pattern.strip() for pattern in QueryExpansion.model_validate_json(result).queries
                       if pattern.strip() and pattern.strip() != query.strip()}
            expanded_set.update(results)

        expanded_list: List[str] = list(expanded_set)[:expanded_set_number]
        if self.include_original_query:
            expanded_list.insert(0, query)

        # apply targets
        expanded_with_targets = []
        if targets:
            for expanded_query in expanded_list:
                placeholder_found = False
                for placeholder in self.target_placeholders:
                    if placeholder in expanded_query:
                        for target in targets:
                            # set here in case targets is empty
                            placeholder_found = True
                            expanded_with_targets.append(expanded_query.replace(placeholder, target))
                if not placeholder_found:
                    expanded_with_targets.append(expanded_query)
        else:
            expanded_with_targets = expanded_list

        return {"queries": expanded_with_targets}


@component
class MultiQueryChromaRetriever:
    def __init__(self, name: str, embedder: Component, sparse_embedder: Component, retriever: QdrantHybridRetriever,
                 collection: Optional[str] = None):
        self.name = name
        self.collection = collection or name
        self.embedder = embedder
        self.sparse_embedder = sparse_embedder
        self.retriever = retriever

    def warm_up(self):
        if hasattr(self.embedder, "warm_up"):
            self.embedder.warm_up()
        if hasattr(self.sparse_embedder, "warm_up"):
            self.sparse_embedder.warm_up()

    @component.output_types(documents=List[Document])
    def run(self,
            queries: List[str],
            top_k: int,
            filters: Optional[Dict[str, Any]] = None,
            progress_callback: Optional[Callable[[str], None]] = None,
            ):
        top_k = min(1000, max(1, top_k))
        if filters is not None and "predicate_filters" in filters:
            filters = filters["predicate_filters"].get(self.collection)
            if filters is None or not filters.must[0].has_id:
                return {"documents": []}
        results = []
        ids = set()
        for query in queries:
            logger.info(f"Querying {self.name}: {query}")
            try:
                if progress_callback is not None:
                    progress_callback(f"Querying {self.name}: {query}")
                result = self.retriever.run(
                    query_embedding=self.embedder.run(query)["embedding"],
                    query_sparse_embedding=self.sparse_embedder.run(query)["sparse_embedding"],
                    filters=filters,
                    top_k=top_k)
                found_count = 0
                for doc in result['documents']:
                    if doc.id not in ids:
                        found_count += 1
                        results.append(doc)
                        ids.add(doc.id)
                logger.info(f"Query for {self.name}: {query} found {found_count} documents")
            except Exception as e:
                logger.error(f"Exception querying database: {str(e)}, filters={filters}", exc_info=e)

        unique_docs = documents_sort_unique(results)

        return {"documents": unique_docs}


@component
class ChatMessageLogger:
    def __init__(self, label: str):
        self.label = label

    @component.output_types()
    def run(self, messages: List[ChatMessage]):
        if not messages:
            logger.debug(f"{self.label}: No messages received")
            # print(f"{self.label}: No messages received")
        for idx, message in enumerate(messages):
            if message.tool_call_results:
                msg = f"{self.label}: Message {idx}: {message.role}: {"\\n".join(map(lambda r: r.result, message.tool_call_results))}"
            else:
                msg = f"{self.label}: Message {idx}: {message.role}: {message.texts}"
            logger.debug(msg)
            # print(msg.replace("\\n", "\n"))
        return {}


@component
class ChatPromptTemplateBuilder:
    def __init__(self, system_prompt: List[ChatMessage]):
        self.system_prompt = system_prompt

    @component.output_types(messages=List[ChatMessage])
    def run(self, memories: List[ChatMessage], query: List[ChatMessage]):
        messages = []
        messages.extend(self.system_prompt)
        messages.extend(memories)
        messages.extend(query)
        return {"messages": messages}


@component
class ChatMessageFilter:
    @component.output_types(messages=List[ChatMessage])
    def run(self, messages: List[ChatMessage]):
        filtered = []
        for message in messages:
            # ollama chat generator fails if a ChatMessage has no content
            text_contents = message.texts
            tool_calls = message.tool_calls
            tool_call_results = message.tool_call_results
            images = message.images
            if text_contents or tool_calls or tool_call_results or images:
                filtered.append(message)
        return {"messages": filtered}


@component
class ChatMessageToListAdapter:
    @component.output_types(values=List[ChatMessage])
    def run(self, value: ChatMessage):
        return {"values": [value]}


async def build_document_pipeline(db: str, generator_config: GeneratorConfig) -> Tuple[
    Pipeline, Dict[str, MultiQueryChromaRetriever], Dict[str, QdrantDocumentStore]]:
    """
    Builds a pipeline for retrieving documents from the store.
    :return: Pipeline
    """

    pipe = Pipeline()
    comb = CombineDocs([f"{col}_documents" for col in get_qdrant_collections()])
    pipe.add_component("combine", comb)
    pipe.add_component("query", Query())
    pipe.add_component("vuln_type_prompt", PromptBuilder(vuln_type_prompt, required_variables=["query"]))
    pipe.add_component("vuln_type_llm", generator_config.create_generator(temperature=0, response_schema=EvidenceClassification, max_output_tokens=1024))
    pipe.add_component("vuln_type_parser", VulnTypeParser())
    pipe.add_component("query_expander", QueryExpander(generator_config))
    pipe.connect("query.text", "vuln_type_prompt.query")
    pipe.connect("vuln_type_prompt", "vuln_type_llm")
    pipe.connect("vuln_type_llm", "vuln_type_parser")
    pipe.connect("query.text", "vuln_type_parser.query")
    pipe.connect("query.text", "vuln_type_llm.query")
    pipe.connect("query.text", "query_expander.query")
    pipe.connect("query.targets", "query_expander.targets")
    pipe.connect("vuln_type_parser", "query_expander")
    pipe.connect("query.doc_types", "combine.doc_types")

    retrievers: Dict[str, MultiQueryChromaRetriever] = {}
    stores: Dict[str, QdrantDocumentStore] = {}

    sparse_embedder = generator_config.create_sparse_text_embedder(SPARSE_EMBEDDING_MODEL)

    embedder_cache = dict()
    for doc_type_model in doc_type_to_model().values():
        model_name = doc_type_model.model_config

        if model_name in embedder_cache:
            embedder = embedder_cache[model_name]
        else:
            embedder = generator_config.create_text_embedder(doc_type_model.model_config)
            if hasattr(embedder, "warm_up"):
                embedder.warm_up()
            embedder_cache[model_name] = embedder

        custom_query_expander = None
        custom_query_expander_name = None
        if doc_type_model.doc_type == "javascript":
            custom_query_expander = QueryExpander(generator_config, prompt=query_expander_javascript, number=10,
                                                  include_original_query=False, doc_type="javascript")
        elif doc_type_model.doc_type == "css":
            custom_query_expander = QueryExpander(generator_config, prompt=query_expander_css, number=5,
                                                  include_original_query=False, doc_type="css")
        elif doc_type_model.doc_type == "html":
            custom_query_expander = QueryExpander(generator_config, prompt=query_expander_html, number=10,
                                                  include_original_query=False, doc_type="html")
        elif doc_type_model.doc_type == "xml":
            custom_query_expander = QueryExpander(generator_config, prompt=query_expander_xml, number=5,
                                                  include_original_query=False, doc_type="xml")
        elif doc_type_model.doc_type == "network":
            custom_query_expander = QueryExpander(generator_config, prompt=query_expander_network, number=5,
                                                  include_original_query=False, doc_type="network")
        if custom_query_expander is not None:
            custom_query_expander_name = "query_expander_" + doc_type_model.doc_type
            pipe.add_component(custom_query_expander_name, custom_query_expander)
            pipe.connect("query.text", custom_query_expander_name + ".query")
            pipe.connect("query.targets", custom_query_expander_name + ".targets")
            pipe.connect("vuln_type_parser", custom_query_expander_name)

        for col in doc_type_model.get_qdrant_collections():
            store = create_qdrant_document_store(db=db, index=col)
            stores[col] = store
            retriever = QdrantHybridRetriever(document_store=store)
            multiquery_retriever = MultiQueryChromaRetriever(doc_type_model.doc_type, embedder, sparse_embedder,
                                                             retriever, collection=col)
            retrievers[col] = multiquery_retriever

            ret_name = f"ret_{col}"
            pipe.add_component(ret_name, multiquery_retriever)

            # wiring: Query → embedder → retriever → combiner
            pipe.connect("query.max_results", ret_name + ".top_k")
            pipe.connect("query.progress_callback", ret_name + ".progress_callback")
            if custom_query_expander_name is not None:
                pipe.connect(custom_query_expander_name + ".queries", ret_name + ".queries")
            else:
                pipe.connect("query_expander.queries", ret_name + ".queries")
            pipe.connect("query.filters", ret_name + ".filters")
            pipe.connect(ret_name + ".documents", f"combine.{col}_documents")

    # pipe.add_component("trace_docs", TraceDocs())
    # pipe.connect("query.text", "trace_docs.query")
    # pipe.connect("query_expander.queries", "trace_docs.expanded_queries")
    # pipe.connect("combine.documents", "trace_docs.documents")

    return pipe, retrievers, stores


def build_website_context_pipeline(generator_config: GeneratorConfig) -> Pipeline:
    prompt = """
      You are a cybersecurity search assistant that processes users queries for websites.

      You determine the target hostname, IP address(es), site url(s) and ports the user is interested in. If the user specifies
      a scheme do not change it. Never add a scheme the user did not provide. Never suggest targets. Only accept explicit targets given by the user.
      Follow these rules when determining the targets:
       - Multiple sites may be specified, preserve the hostname and IP addresses.
         Example: http://example.com and http://sub1.example.com are two targets, http://example.com and http://sub1.example.com
       - The hostname may include several components in dot-notation.
         Example: web01.internal.example.com is one target, web01.internal.example.com
       - If the user specifies a protocol, keep it.
         Example: http://example.com is exactly one target, http://example.com
         Example: https://example.com is exactly one target, https://example.com
       - A hostname or IP address is permitted without a protocol and without a port, such as target.local
         Example: target.local is one target, target.local
       - A hostname or IP address is permitted without a protocol but with a port, such as target.local:443
         Example: example.com:443 is one target, example.com:443
         Example: example.com:80 is one target, example.com:80

      You also determine optional types of content the user is interested in from the following list:
      "html", "forms", "xml", "javascript", "css", "json", "network". If the query includes things that would be in the HTTP headers such as cookies, the content security policy or response messages include the content type "network".

      You also determine technology stacks the user references, if any.

      You also determine if anything in the query implies a specific set of HTTP response codes. Do not include response codes in the 200-299 range.

      You also determine if anything in the query implies the request was made using a specific set of HTTP methods such as "GET", "POST", "PUT", if any. Only include methods if the user is asking for how the request was made. Usually the user will intend HTTP methods that are in the RFC, but may ask for specific non-standard methods. Be cautious about providing methods so to not be too limiting.
      
      Structure:
      Output the information as a valid JSON object. Only output the JSON. Do not include any other text except the JSON.
      
      The list of web sites uses key "target". The value of "target" is a valid JSON list. It is a list of url(s), hostnames, and/or IP addresses.

      The list of content types uses key "content". The value of "content" is a valid JSON list. Only use the aforementioned list of content types.

      The list of technology uses key "tech". The value of "tech" is a valid JSON list. Prefer using the format of "name/version".

      The list of HTTP methods uses key "methods". The value of "methods" is a valid JSON list of upper case alphanumeric strings.

      The list of HTTP response codes uses key "response_codes". The value of "response_codes" is a valid JSON list of integers.

      Examples:
        1. Example Query 1: "Examine http://target.local for vulns"  
           Example Result: {"target": ["http://target.local"], "content": [], "tech": [], "methods": [], "response_codes": []}

        2. Example Query 2: "Examine http://target.local and http://sub1.target.local for vulns"
           Example Result: {"target": ["http://target.local", "http://sub1.target.local"], "content": [], "tech": [], "methods": [], "response_codes": []}

        3. Example Query 3: "Examine 10.10.10.10:8000 for risky javascript functions"  
           Example Result: {"target": ["10.10.10.10:8000"], "content": ["html", "javascript"], "tech": [], "methods": [], "response_codes": []}

        4. Example Query 4: "Examine nobody.net for vulnerable versions of WordPress"  
           Example Result: {"target": ["nobody.net"], "content": ["network", "html", "javascript"], "tech": ["WordPress"], "methods": [], "response_codes": []}

        5. Example Query 5: "Examine authentication failures on schooldaze.edu for username disclosure"
           Example Result: {"target": ["schooldaze.edu"], "content": ["html", "javascript"], "tech": [""], "methods": [], "response_codes": [403]}

        6. Example Query 6: "Examine posted forms on 192.168.1.1:8090 for XSS vulns."
           Example Result: {"target": ["192.168.1.1:8090"], "content": ["html", "javascript"], "tech": [""], "methods": ["POST"], "response_codes": []}

        7. Example Query 7: "Find forbidden pages on https://schooldaze.edu"   
           Example Result: {"target": ["https://schooldaze.edu"], "content": ["network"], "tech": [""], "methods": [], "response_codes": [403]}

        8. Example Query 7: "Find bad requests on https://schooldaze.edu"   
           Example Result: {"target": ["https://schooldaze.edu"], "content": ["network"], "tech": [""], "methods": [], "response_codes": [400]}

      Your Task:
      Query: "{{query}}"
      JSON targets, optional content, optional tech:
      """
    builder = PromptBuilder(prompt, required_variables=["query"])
    llm = generator_config.create_generator(temperature=0.1, response_schema=WebsiteContext, max_output_tokens=1024)
    pipeline = Pipeline()
    pipeline.add_component("builder", builder)
    pipeline.add_component("llm", llm)
    pipeline.connect("builder", "llm")
    return pipeline
