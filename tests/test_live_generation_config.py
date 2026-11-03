"""Offline checks for bounded live-model test configuration."""

from unittest.mock import Mock

import pytest

from shyhurricane.generator_config import GeneratorConfig


@pytest.mark.parametrize("overrides", [None, {"seed": 7, "num_predict": 128}])
def test_live_generation_defaults_and_overrides(monkeypatch, request, overrides):
    original = Mock()
    monkeypatch.setattr(GeneratorConfig, "create_generator", original)
    request.getfixturevalue("bounded_ollama_generation")
    config = GeneratorConfig(ollama_model="llama3.2:3b")

    config.create_generator(temperature=0.1, generation_kwargs=overrides)

    original.assert_called_once_with(
        config, temperature=0.1,
        generation_kwargs={"num_predict": 2048, "seed": 0} | (overrides or {}),
    )


@pytest.mark.parametrize(("module_name", "class_name"), [
    ("test_query_expander", "TestQueryExpanderNaturalLanguage"),
    ("test_vuln_type_parser", "VulnTypeParserTest"),
    ("test_website_context_pipeline", "WebsiteContextPipelineTest"),
])
def test_live_pipelines_initialize_during_setup(monkeypatch, module_name, class_name):
    import importlib

    module = importlib.import_module(module_name)
    factory = Mock(side_effect=RuntimeError("setup reached generator creation"))
    monkeypatch.setattr(GeneratorConfig, "create_generator", factory)

    case = getattr(module, class_name)("runTest")
    factory.assert_not_called()
    with pytest.raises(RuntimeError, match="setup reached generator creation"):
        case.setUp()
    factory.assert_called_once()
