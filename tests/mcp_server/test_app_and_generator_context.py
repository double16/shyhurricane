from shyhurricane.mcp_server.app_context import AppContext
from shyhurricane.mcp_server.generator_config import get_generator_config, set_generator_config


def test_app_context_cache_path_is_stable_and_includes_hosts(tmp_path):
    app_context = AppContext({}, {}, str(tmp_path), "ctx", "/work")

    first = app_context.get_cache_path_for_tool("tool", {"b.test": "127.0.0.2", "a.test": "127.0.0.1"})
    second = app_context.get_cache_path_for_tool("tool", {"b.test": "127.0.0.2", "a.test": "127.0.0.1"})
    different_hosts = app_context.get_cache_path_for_tool("tool", {"a.test": "127.0.0.1"})

    assert first == second
    assert first != different_hosts
    assert first.startswith(str(tmp_path))
    assert len(first.split("/")[-1]) == 124


def test_app_context_cache_path_handles_empty_hosts(tmp_path):
    app_context = AppContext({}, {}, str(tmp_path), "ctx", "/work")

    path = app_context.get_cache_path_for_tool("tool", {})

    assert path.startswith(str(tmp_path))


def test_generator_config_global_setter_round_trips():
    original = get_generator_config()
    replacement = object()

    try:
        set_generator_config(replacement)
        assert get_generator_config() is replacement
    finally:
        set_generator_config(original)
