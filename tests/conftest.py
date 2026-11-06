import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Disable telemetry before importing Haystack or any integration that imports it.
# Changing the environment after import leaves its initialized background client active.
os.environ["HAYSTACK_TELEMETRY_ENABLED"] = "False"

import pytest
import requests
from tldextract import tldextract as tldextract_module
from tldextract.tldextract import TLDExtract

tldextract_module.TLD_EXTRACTOR = TLDExtract(cache_dir=None, suffix_list_urls=())

def pytest_addoption(parser):
    parser.addoption(
        "--ollama",
        action="store_true",
        default=False,
        help="Run tests that require the Ollama."
    )


def pytest_runtest_setup(item):
    if "ollama" in item.keywords:
        if item.config.getoption("--ollama"):
            ollama_host = os.environ.get("OLLAMA_HOST", "127.0.0.1:11434")
            try:
                r = requests.get(f"http://{ollama_host}/api/tags", timeout=5)
                r.raise_for_status()
            except (requests.RequestException, ValueError):
                pytest.skip(f"Skipping tests: Ollama is not available at http://{ollama_host}", allow_module_level=True)
        else:
            pytest.skip("Test requires --ollama option to run.")


@pytest.fixture(autouse=True)
def isolated_application_data(monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "application_data"))
    for name in ("TOOL_CACHE", "MCP_SESSION_VOLUME", "QDRANT", "NEO4J"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def offline_ollama_preparation(monkeypatch, request):
    """Keep ordinary server startup tests independent of a running Ollama."""
    if request.node.get_closest_marker("ollama") is None:
        from shyhurricane.generator_config import GeneratorConfig

        monkeypatch.setattr(GeneratorConfig, "prepare_ollama_models", lambda self: None)


@pytest.fixture
def bounded_ollama_generation(monkeypatch):
    """Bound live integration output without changing production generation defaults."""
    from shyhurricane.generator_config import GeneratorConfig

    original = GeneratorConfig.create_generator

    def create(self, temperature=None, generation_kwargs=None, **kwargs):
        return original(
            self, temperature=temperature,
            generation_kwargs={"num_predict": 2048, "seed": 0} | (generation_kwargs or {}),
            **kwargs,
        )

    monkeypatch.setattr(GeneratorConfig, "create_generator", create)
