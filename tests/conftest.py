import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
import requests
from tldextract import tldextract as tldextract_module
from tldextract.tldextract import TLDExtract

tldextract_module.TLD_EXTRACTOR = TLDExtract(cache_dir=None)

from shyhurricane.generator_config import GeneratorConfig


def pytest_configure(config):
    def noop(*args, **kwargs):
        pass
    GeneratorConfig.ollama_pull = noop


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
