import logging

from shyhurricane.config import configure


def test_configure_sets_runtime_environment(monkeypatch):
    for key in [
        "PYTORCH_ENABLE_MPS_FALLBACK",
        "ANONYMIZED_TELEMETRY",
        "HAYSTACK_TELEMETRY_ENABLED",
        "HAYSTACK_TELEMETRY_DISABLED",
        "TOKENIZERS_PARALLELISM",
    ]:
        monkeypatch.delenv(key, raising=False)

    configure()

    assert logging.getLogger("httpx").level == logging.CRITICAL
    assert {
               "PYTORCH_ENABLE_MPS_FALLBACK": "1",
               "ANONYMIZED_TELEMETRY": "False",
               "HAYSTACK_TELEMETRY_ENABLED": "False",
               "HAYSTACK_TELEMETRY_DISABLED": "1",
               "TOKENIZERS_PARALLELISM": "false",
           }.items() <= __import__("os").environ.items()
