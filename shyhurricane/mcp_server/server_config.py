from dataclasses import dataclass


@dataclass
class ServerConfig:
    task_pool_size: int = 3
    ingest_pool_size: int = 1
    open_world: bool = True
    low_power: bool = False
    """
    Enables "low-power" mode that disables features that require GPU or other compute intenstive tasks.
    """


_server_config: ServerConfig = ServerConfig()


def set_server_config(config: ServerConfig):
    global _server_config
    _server_config = config


def get_server_config() -> ServerConfig:
    global _server_config
    return _server_config
