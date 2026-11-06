import pytest

from shyhurricane.structured_generation import StructuredGenerator, TitleDescription, _UNSUPPORTED


@pytest.mark.parametrize("unsupported", [False, True])
def test_validated_generation_and_capability_cache(unsupported):
    _UNSUPPORTED.clear()
    modes = []

    class Generator:
        def warm_up(self):
            pass

        def run(self, prompt):
            if unsupported and modes[-1]:
                raise ValueError("response_format unsupported")
            return {"replies": ['{"title":"Title","description":"Description"}']}

    def factory(mode):
        modes.append(mode)
        return Generator()

    for _ in range(2):
        result = StructuredGenerator(factory, TitleDescription, ("test",)).run("input")
        assert '"title":"Title"' in result["replies"][0]
    assert modes == ([True, False, False] if unsupported else [True, True])


@pytest.mark.parametrize("response", ['{}', '{"title":1,"description":"x"}', 'not json'])
def test_invalid_output_is_rejected(response):
    class Generator:
        def warm_up(self):
            pass

        def run(self, prompt):
            return {"replies": [response]}

    with pytest.raises(ValueError):
        StructuredGenerator(lambda mode: Generator(), TitleDescription, ("invalid",)).run("input")


@pytest.mark.parametrize("provider", ["ollama", "openai", "gemini", "bedrock", "litellm"])
def test_provider_structured_options(monkeypatch, provider):
    from types import SimpleNamespace
    from shyhurricane.generator_config import GeneratorConfig

    captured = []

    class Fake:
        chat_generator = SimpleNamespace(response_format=None)

        def warm_up(self):
            pass

        def run(self, prompt):
            return {"replies": ['{"title":"A","description":"B"}']}

    def create(self, temperature, options):
        captured.append(options)
        return Fake()

    monkeypatch.setattr(GeneratorConfig, "_create_generator", create)
    config = GeneratorConfig(**{f"{provider}_model": "test"})
    generator = config.create_generator(response_schema=TitleDescription, max_output_tokens=384)
    generator.run("hello")
    budget = {"ollama": "num_predict", "gemini": "max_output_tokens", "bedrock": "maxTokens"}.get(provider, "max_tokens")
    assert captured[0][budget] == 384
    if provider != "ollama":
        assert "response_format" in captured[0]


def test_transport_error_does_not_disable_schema():
    key = ("transport",)

    class Generator:
        def warm_up(self):
            pass

        def run(self, prompt):
            raise TimeoutError("timed out")

    with pytest.raises(TimeoutError):
        StructuredGenerator(lambda mode: Generator(), TitleDescription, key).run("input")
    assert key not in _UNSUPPORTED


def test_empty_response_and_close():
    closed = []

    class Generator:
        def warm_up(self):
            pass

        def close(self):
            closed.append(True)

        def run(self, prompt):
            return {"replies": []}

    generator = StructuredGenerator(lambda mode: Generator(), TitleDescription, ("empty",))
    with pytest.raises(ValueError, match="Empty"):
        generator.run("input")
    generator.close()
    assert closed


@pytest.mark.parametrize("provider,model,expected", [
    ("gemini", "nomic-embed-text", "text-embedding-004"),
    ("gemini", "nomic-embed-code", "gemini-embedding-001"),
    ("gemini", "unknown", "text-embedding-004"),
    ("bedrock", "unknown", "amazon.titan-embed-text-v2:0"),
])
def test_embedding_model_mapping(provider, model, expected):
    from shyhurricane.generator_config import GeneratorConfig

    config = GeneratorConfig(**{f"{provider}_model": "test"})
    assert config._embedder_model_name_to_path(model) == expected


@pytest.mark.parametrize("model,expected", [
    ("all-MiniLM-L6-v2", "mahonzhan/all-MiniLM-L6-v2:latest"),
    ("nomic-embed-code", "manutic/nomic-embed-code:latest"),
    ("unknown", "unknown"),
    ("nomic-embed-text", "nomic-embed-text:latest"),
    ("jina-embeddings-v2-base-code", "unclemusclez/jina-embeddings-v2-base-code:latest"),
])
def test_ollama_embedding_model_mapping(monkeypatch, model, expected):
    from shyhurricane.generator_config import GeneratorConfig

    monkeypatch.setattr(GeneratorConfig, "_embedder_enable_ollama", lambda self: True)
    config = GeneratorConfig(ollama_model="test")
    assert config._embedder_model_name_to_path(model) == expected
