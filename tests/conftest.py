import os

import pytest
import requests


def pytest_runtest_setup(item):
    if "ollama" in item.keywords:
        ollama_host = os.environ.get("OLLAMA_HOST", "127.0.0.1:11434")
        try:
            r = requests.get(f"http://{ollama_host}/api/tags", timeout=2)
            r.raise_for_status()
        except (requests.RequestException, ValueError):
            pytest.skip(f"Skipping tests: Ollama is not available at http://{ollama_host}", allow_module_level=True)
