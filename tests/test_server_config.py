import argparse

from shyhurricane.server_config import (
    OASTConfig,
    ServerConfig,
    add_oast_args,
    get_server_config,
    set_server_config,
)


def test_oast_config_from_env(monkeypatch):
    monkeypatch.setenv("OAST_PROVIDER", "interactsh")
    monkeypatch.setenv("INTERACT_SERVER", "oast.test")
    monkeypatch.setenv("INTERACT_TOKEN", "token")
    monkeypatch.setenv("WEBHOOK_API_KEY", "api-key")

    config = OASTConfig.from_env()

    assert config.provider == "interactsh"
    assert config.interact_server == "oast.test"
    assert config.interact_token == "token"
    assert config.webhook_api_key == "api-key"


def test_oast_config_from_args_prefers_args_over_env(monkeypatch):
    monkeypatch.setenv("OAST_PROVIDER", "webhook_site")
    monkeypatch.setenv("INTERACT_SERVER", "env-server")
    args = argparse.Namespace(
        oast_provider="interactsh",
        interact_server="arg-server",
        interact_token="arg-token",
        webhook_api_key="arg-key",
    )

    config = OASTConfig.from_args(args)

    assert config.provider == "interactsh"
    assert config.interact_server == "arg-server"
    assert config.interact_token == "arg-token"
    assert config.webhook_api_key == "arg-key"


def test_add_oast_args_parses_defaults_and_choices():
    parser = argparse.ArgumentParser()
    add_oast_args(parser)

    parsed = parser.parse_args([])
    explicit = parser.parse_args(["--oast-provider", "interactsh", "--interact-server", "srv"])

    assert parsed.oast_provider == "webhook_site"
    assert explicit.oast_provider == "interactsh"
    assert explicit.interact_server == "srv"


def test_server_config_global_setter_round_trips():
    original = get_server_config()
    replacement = ServerConfig(database="db", task_pool_size=7, ingest_pool_size=2, open_world=False, low_power=True)

    try:
        set_server_config(replacement)
        assert get_server_config() is replacement
    finally:
        set_server_config(original)
