import os
from dataclasses import dataclass, field
from typing import Optional, Literal

ProviderName = Literal["interactsh", "webhook_site", "burp_collaborator"]


@dataclass
class OutOfBandConfig:
    provider: ProviderName = "webhook_site"
    # interact.sh
    interact_server: Optional[str] = None
    interact_token: Optional[str] = None
    # webhook.site
    webhook_api_key: Optional[str] = None
    # burp collaborator bridge
    burp_bridge_url: Optional[str] = None
    burp_bridge_secret: Optional[str] = None

    @staticmethod
    def from_env():
        return OutOfBandConfig(
            provider=os.getenv("OOB_PROVIDER", "interactsh"),  # interactsh|webhook_site|burp_collaborator
            interact_server=os.getenv("INTERACT_SERVER"),  # e.g. oast.pro
            interact_token=os.getenv("INTERACT_TOKEN"),  # e.g. Bearer <key> (optional)
            webhook_api_key=os.getenv("WEBHOOK_API_KEY"),  # optional
            burp_bridge_url=os.getenv("BURP_COLLAB_BRIDGE_URL"),  # optional (required for burp_collaborator)
            burp_bridge_secret=os.getenv("BURP_COLLAB_BRIDGE_SECRET"),
        )

@dataclass
class ServerConfig:
    task_pool_size: int = 3
    ingest_pool_size: int = 1
    open_world: bool = True
    low_power: bool = False
    """
    Enables "low-power" mode that disables features that require GPU or other compute intenstive tasks.
    """
    out_of_band: OutOfBandConfig = field(default_factory=OutOfBandConfig.from_env)


_server_config: ServerConfig = ServerConfig()


def set_server_config(config: ServerConfig):
    global _server_config
    _server_config = config


def get_server_config() -> ServerConfig:
    global _server_config
    return _server_config
