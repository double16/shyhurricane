import argparse
import os
from dataclasses import dataclass, field
from typing import Optional, Literal

OASTProviderName = Literal["webhook_site", "interactsh"]


def add_oast_args(ap: argparse.ArgumentParser):
    ap.add_argument("--oast-provider", default="webhook_site", choices=["webhook_site", "interactsh"],
                    help="OAST provider")
    ap.add_argument("--webhook-api-key", required=False, help="webhook.site API key to use more features")
    ap.add_argument("--interact-server", required=False, help="Interact.sh server to use, i.e. oast.site or oast.me")
    ap.add_argument("--interact-token", required=False, help="Interact.sh token to use, for private servers")


@dataclass
class OASTConfig:
    provider: OASTProviderName = "webhook_site"
    # interact.sh
    interact_server: Optional[str] = None
    interact_token: Optional[str] = None
    # webhook.site
    webhook_api_key: Optional[str] = None

    @staticmethod
    def from_env():
        return OASTConfig(
            provider=os.getenv("OAST_PROVIDER", "webhook_site"),  # interactsh|webhook_site
            interact_server=os.getenv("INTERACT_SERVER"),
            interact_token=os.getenv("INTERACT_TOKEN"),
            webhook_api_key=os.getenv("WEBHOOK_API_KEY"),
        )

    @staticmethod
    def from_args(args):
        return OASTConfig(
            provider=args.oast_provider or os.getenv("OAST_PROVIDER", "webhook_site"),
            interact_server=args.interact_server or os.getenv("INTERACT_SERVER"),
            interact_token=args.interact_token or os.getenv("INTERACT_TOKEN"),
            webhook_api_key=args.webhook_api_key or os.getenv("WEBHOOK_API_KEY"),
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
    oast: OASTConfig = field(default_factory=OASTConfig.from_env)


_server_config: ServerConfig = ServerConfig()


def set_server_config(config: ServerConfig):
    global _server_config
    _server_config = config


def get_server_config() -> ServerConfig:
    global _server_config
    return _server_config
