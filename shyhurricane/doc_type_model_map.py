import sys
from typing import List, Dict, Optional

DEFAULT_EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
# CODE_EMBEDDING_MODEL = "microsoft/codebert-base" # 512 tokens
# CODE_EMBEDDING_MODEL = "nomic-ai/nomic-embed-code" # 7B, very large
CODE_EMBEDDING_MODEL = "jinaai/jina-embeddings-v2-base-code"


def get_chroma_collection_name_by_doc_type_token_length(doc_type: str, token_length: int) -> str:
    if token_length == sys.maxsize:
        return doc_type
    else:
        return f"{doc_type}_{token_length}"


class EmbeddingModelConfig:
    def __init__(
            self,
            doc_type: str,
            model_name: str,
            token_lengths: Optional[List[int]] = None,
    ):
        """
        :param doc_type:
        :param model_name:
        :param token_lengths: empty means "do not split doc, use default model token size", sys.maxsize uses max model size
        """
        self.doc_type = doc_type
        self.model_name = model_name
        self.token_lengths = token_lengths

    def get_chroma_collections(self) -> set[str]:
        collections = set()
        if not self.token_lengths:
            collections.add(self.doc_type)
        else:
            for tl in self.token_lengths:
                collections.add(self.get_chroma_collection(tl))
        return collections

    def get_chroma_collection(self, token_length: int = sys.maxsize):
        return get_chroma_collection_name_by_doc_type_token_length(self.doc_type, token_length)

    def get_primary_token_length(self) -> int:
        if not self.token_lengths:
            return sys.maxsize
        else:
            return self.token_lengths[0]


# Mapping of document types (collections) to embedding model names
# TODO: remove some of these for low_power mode
_doc_type_to_model: Dict[str, EmbeddingModelConfig] = {
    # for any collection that needs full content, do not add token_lengths
    "html": EmbeddingModelConfig("html", CODE_EMBEDDING_MODEL, token_lengths=[sys.maxsize, 256]),
    "xml": EmbeddingModelConfig("xml", CODE_EMBEDDING_MODEL, token_lengths=[sys.maxsize, 256]),
    "javascript": EmbeddingModelConfig("javascript", CODE_EMBEDDING_MODEL, token_lengths=[sys.maxsize, 256]),
    "json": EmbeddingModelConfig("json", CODE_EMBEDDING_MODEL, token_lengths=[sys.maxsize, 256]),
    "css": EmbeddingModelConfig("css", CODE_EMBEDDING_MODEL, token_lengths=[sys.maxsize, 256]),
    "network": EmbeddingModelConfig("network", DEFAULT_EMBEDDING_MODEL, token_lengths=[sys.maxsize, 256]),
    "forms": EmbeddingModelConfig("forms", CODE_EMBEDDING_MODEL, token_lengths=[256]),
    "nmap": EmbeddingModelConfig("nmap", CODE_EMBEDDING_MODEL),  # store raw nmap xml
    "portscan": EmbeddingModelConfig("portscan", CODE_EMBEDDING_MODEL),  # store json port scan model
    "finding": EmbeddingModelConfig("finding", DEFAULT_EMBEDDING_MODEL, token_lengths=[sys.maxsize, 256]),
    # store markdown formatted findings
    "default": EmbeddingModelConfig("default", DEFAULT_EMBEDDING_MODEL, token_lengths=[sys.maxsize, 256]),
    "content": EmbeddingModelConfig("content", DEFAULT_EMBEDDING_MODEL),  # stores response content verbatim
}


def doc_type_to_model() -> Dict[str, EmbeddingModelConfig]:
    return _doc_type_to_model


def get_model_for_doc_type(doc_type: str) -> EmbeddingModelConfig:
    return doc_type_to_model().get(doc_type, doc_type_to_model().get("default"))


def get_all_required_models(collections: list[str]) -> set[str]:
    return {doc_type_to_model()[c].model_name for c in collections if c in doc_type_to_model}


def get_chroma_collections() -> set[str]:
    collections = set()
    for model in doc_type_to_model().values():
        collections.update(model.get_chroma_collections())
    return collections


# MIME to Logical Type Map
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
    "text/x-finding": "finding",
}


def map_mime_to_type(mime: str) -> str:
    if not mime:
        return "default"
    if mime.endswith("+json"):
        return "json"
    if mime.endswith("+xml"):
        return "xml"
    return MIME_TYPE_ALIASES.get(mime, "default")
