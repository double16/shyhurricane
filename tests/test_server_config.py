from shyhurricane.server_config import (
    ServerConfig,
    get_server_config,
    set_server_config,
)


def test_server_config_global_setter_round_trips():
    original = get_server_config()
    replacement = ServerConfig(database="db", task_pool_size=7, ingest_pool_size=2, open_world=False, low_power=True)

    try:
        set_server_config(replacement)
        assert get_server_config() is replacement
    finally:
        set_server_config(original)


def test_indexing_timeout_preserves_existing_positional_configuration():
    config = ServerConfig("db", "graph", 3, 1, True, True)
    assert config.low_power is True
    assert config.indexing_wait_timeout_seconds == 60
