# doc_type_model_map.py

# Mapping of document types (collections) to embedding model names
doc_type_to_model = {
    "html": "intfloat/e5-base-v2",
    "xml": "intfloat/e5-base-v2",
    "javascript": "microsoft/codebert-base",
    "json": "microsoft/codebert-base",
    "css": "microsoft/codebert-base",
    "network": "sentence-transformers/paraphrase-mpnet-base-v2",
    "forms": "microsoft/codebert-base",
    "default": "sentence-transformers/all-MiniLM-L6-v2",
    "content": "sentence-transformers/all-MiniLM-L6-v2",  # stores response content verbatim
}


def get_model_for_doc_type(doc_type: str) -> str:
    return doc_type_to_model.get(doc_type, "sentence-transformers/all-MiniLM-L6-v2")


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
    if mime.endswith("+json"):
        return "json"
    if mime.endswith("+xml"):
        return "xml"
    return MIME_TYPE_ALIASES.get(mime, "default")
