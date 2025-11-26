import logging
import os
from typing import Dict
from haystack.core.component import Component

from shyhurricane.doc_type_model_map import EmbeddingModelConfig
from shyhurricane.generator_config import GeneratorConfig

logger = logging.getLogger(__name__)


class EmbedderCache:
    def __init__(self, generator_config: GeneratorConfig):
        self.cache: Dict[str, Component] = dict()
        self.generator_config = generator_config

    def get(self, config: str | EmbeddingModelConfig) -> Component:
        if isinstance(config, EmbeddingModelConfig):
            model_name = config.model_config.model_name
        else:
            model_name = str(config)

        if model_name in self.cache:
            embedder = self.cache[model_name]
        else:
            logger.info(f"Loading embedder for {model_name} in PID {os.getpid()}")
            embedder = self.generator_config.create_document_embedder(config.model_config)
            if hasattr(embedder, "warm_up"):
                embedder.warm_up()
            logger.info(
                f"Loaded embedder for {model_name}, {config.model_config.max_token_length} max tokens in PID {os.getpid()}")
            self.cache[model_name] = embedder
        return embedder
