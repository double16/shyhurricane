import math
import os
from dataclasses import dataclass

from shyhurricane.data_paths import neo4j_location, qdrant_location, resolve_data_dir
from shyhurricane.disk_space import validate_disk_config
from shyhurricane.graph.config import graph_timeouts


@dataclass
class ServerConfig:
    data_dir: str | None = None
    task_pool_size: int = 3
    ingest_pool_size: int = 1
    open_world: bool = True
    low_power: bool = False
    """
    Enables "low-power" mode that disables features that require GPU or other compute intenstive tasks.
    """
    indexing_wait_timeout_seconds: float = 60.0

    disk_min_free_percent: float = 3.0
    disk_min_free_bytes: int = 2 * 1024**3
    disk_resume_margin_percent: float = 1.0
    disk_resume_margin_bytes: int = 512 * 1024**2

    @property
    def database(self) -> str:
        return qdrant_location(self.data_dir)

    @property
    def graph_database(self) -> str:
        return neo4j_location(self.data_dir)

    def __post_init__(self):
        graph_timeouts()
        validate_disk_config(self)
        if self.data_dir is not None:
            self.data_dir = str(resolve_data_dir(self.data_dir))
        if not math.isfinite(self.indexing_wait_timeout_seconds) or self.indexing_wait_timeout_seconds < 0:
            raise ValueError("Indexing wait timeout must be finite and nonnegative")


_server_config: ServerConfig = ServerConfig()


def set_server_config(config: ServerConfig):
    global _server_config
    if config.data_dir is not None:
        os.environ["DATA_DIR"] = config.data_dir
    _server_config = config


def get_server_config() -> ServerConfig:
    global _server_config
    return _server_config
