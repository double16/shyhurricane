import sys

from shyhurricane.doc_type_model_map import (
    CODE_EMBEDDING_MODEL,
    DEFAULT_EMBEDDING_MODEL,
    EmbeddingModelConfig,
    ModelConfig,
    doc_type_to_model,
    get_all_required_models,
    get_model_for_doc_type,
    get_qdrant_collection_name_by_doc_type_token_length,
    get_qdrant_collections,
    map_mime_to_type,
)


def test_qdrant_collection_name_omits_maxsize_suffix():
    assert get_qdrant_collection_name_by_doc_type_token_length("html", sys.maxsize) == "html"
    assert get_qdrant_collection_name_by_doc_type_token_length("html", 256) == "html_256"


def test_embedding_model_config_collections_and_primary_token_length():
    split = EmbeddingModelConfig("javascript", CODE_EMBEDDING_MODEL, token_lengths=[sys.maxsize, 256])
    unsplit = EmbeddingModelConfig("content", DEFAULT_EMBEDDING_MODEL)

    assert split.get_qdrant_collections() == {"javascript", "javascript_256"}
    assert split.get_qdrant_collection(128) == "javascript_128"
    assert split.get_primary_token_length() == sys.maxsize
    assert unsplit.get_qdrant_collections() == {"content"}
    assert unsplit.get_primary_token_length() == sys.maxsize


def test_model_lookup_defaults_unknown_doc_type():
    assert get_model_for_doc_type("html").doc_type == "html"
    assert get_model_for_doc_type("unknown").doc_type == "default"
    assert doc_type_to_model()["network"].model_config is DEFAULT_EMBEDDING_MODEL


def test_get_all_required_models_ignores_unknown_collections():
    required = get_all_required_models(["html", "network", "missing"])

    assert required == {CODE_EMBEDDING_MODEL, DEFAULT_EMBEDDING_MODEL}


def test_get_qdrant_collections_includes_split_and_unsplit_names():
    collections = get_qdrant_collections()

    assert "html" in collections
    assert "html_256" in collections
    assert "content" in collections
    assert "content_256" not in collections


def test_map_mime_to_type_aliases_suffixes_and_defaults():
    assert map_mime_to_type("") == "default"
    assert map_mime_to_type("application/vnd.api+json") == "json"
    assert map_mime_to_type("application/rss+xml") == "xml"
    assert map_mime_to_type("text/html") == "html"
    assert map_mime_to_type("image/svg+xml") == "xml"
    assert map_mime_to_type("application/octet-stream") == "default"


def test_model_config_stores_constructor_values():
    config = ModelConfig("model-name", 123)

    assert config.model_name == "model-name"
    assert config.max_token_length == 123
