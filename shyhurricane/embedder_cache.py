import logging
import os
from typing import Dict
from haystack.components.embedders import SentenceTransformersDocumentEmbedder

from shyhurricane.doc_type_model_map import EmbeddingModelConfig

logger = logging.getLogger(__name__)


class EmbedderCache:
    def __init__(self):
        self.cache: Dict[str, SentenceTransformersDocumentEmbedder] = dict()

    def get(self, config: str | EmbeddingModelConfig) -> SentenceTransformersDocumentEmbedder:
        if isinstance(config, EmbeddingModelConfig):
            model_name = config.model_name
        else:
            model_name = str(config)

        if model_name in self.cache:
            embedder = self.cache[model_name]
        else:
            logger.info(f"Loading new embedder for {model_name} in PID {os.getpid()}")
            embedder = SentenceTransformersDocumentEmbedder(
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
            self.cache[model_name] = embedder
        return embedder
