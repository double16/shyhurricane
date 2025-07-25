# doc_type_model_map.py
DEFAULT_EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L12-v2"
# CODE_EMBEDDING_MODEL = "microsoft/codebert-base" # 512 tokens
# CODE_EMBEDDING_MODEL = "nomic-ai/nomic-embed-code" # 7B, very large
CODE_EMBEDDING_MODEL = "jinaai/jina-embeddings-v2-base-code"

# Mapping of document types (collections) to embedding model names
doc_type_to_model = {
    "html": CODE_EMBEDDING_MODEL,
    "xml": CODE_EMBEDDING_MODEL,
    "javascript": CODE_EMBEDDING_MODEL,
    "json": CODE_EMBEDDING_MODEL,
    "css": CODE_EMBEDDING_MODEL,
    "network": DEFAULT_EMBEDDING_MODEL,
    "forms": CODE_EMBEDDING_MODEL,
    "nmap": CODE_EMBEDDING_MODEL,  # store raw nmap xml
    "portscan": CODE_EMBEDDING_MODEL,  # store json port scan model
    "finding": DEFAULT_EMBEDDING_MODEL,  # store markdown formatted findings
    "default": DEFAULT_EMBEDDING_MODEL,
    "content": DEFAULT_EMBEDDING_MODEL,  # stores response content verbatim
}


def get_model_for_doc_type(doc_type: str) -> str:
    return doc_type_to_model.get(doc_type, DEFAULT_EMBEDDING_MODEL)


def get_all_required_models(collections: list[str]) -> set[str]:
    return {doc_type_to_model[c] for c in collections if c in doc_type_to_model}


# ─── MIME to Logical Type Map ─────────────────────────────────────────
MIME_TYPE_ALIASES = {
    "text/html": "html",
    "application/xml": "xml",
    "image/svg+xml": "xml",
    "text/css": "css",
    "application/javascript": "javascript",
    "application/x-javascript": "javascript",
    "text/javascript": "javascript",
    "application/json": "json",
    "text/json": "json",
}


def map_mime_to_type(mime: str) -> str:
    if not mime:
        return "default"
    if mime.endswith("+json"):
        return "json"
    if mime.endswith("+xml"):
        return "xml"
    return MIME_TYPE_ALIASES.get(mime, "default")
