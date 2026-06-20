from shyhurricane.doc_type_model_map import EmbeddingModelConfig, ModelConfig
from shyhurricane.embedder_cache import EmbedderCache


class FakeEmbedder:
    def __init__(self):
        self.warm_up_calls = 0

    def warm_up(self):
        self.warm_up_calls += 1


class FakeGeneratorConfig:
    def __init__(self):
        self.created = []

    def create_document_embedder(self, model_config):
        self.created.append(model_config)
        return FakeEmbedder()


def test_embedder_cache_creates_warms_and_reuses_embedder():
    model_config = ModelConfig("test-model", 256)
    config = EmbeddingModelConfig("html", model_config)
    generator_config = FakeGeneratorConfig()
    cache = EmbedderCache(generator_config)

    first = cache.get(config)
    second = cache.get(config)

    assert first is second
    assert first.warm_up_calls == 1
    assert generator_config.created == [model_config]
