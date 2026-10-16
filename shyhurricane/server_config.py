import math
from dataclasses import dataclass


@dataclass
class ServerConfig:
    database: str = None
    graph_database: str = None
    task_pool_size: int = 3
    ingest_pool_size: int = 1
    open_world: bool = True
    low_power: bool = False
    """
    Enables "low-power" mode that disables features that require GPU or other compute intenstive tasks.
    """
    indexing_wait_timeout_seconds: float = 60.0

    def __post_init__(self):
        if not math.isfinite(self.indexing_wait_timeout_seconds) or self.indexing_wait_timeout_seconds < 0:
            raise ValueError("Indexing wait timeout must be finite and nonnegative")


_server_config: ServerConfig = ServerConfig()


def set_server_config(config: ServerConfig):
    global _server_config
    _server_config = config


def get_server_config() -> ServerConfig:
    global _server_config
    return _server_config
