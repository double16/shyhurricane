import hashlib
import json
import logging
import os
from dataclasses import field, dataclass
from typing import Dict

from shyhurricane.channels import ChannelManager
from shyhurricane.oast import OASTProvider

logger = logging.getLogger(__name__)


@dataclass
class AppContext:
    # TODO: add scope?
    cached_get_additional_hosts: Dict[str, str]
    cache_path: str
    app_context_id: str
    work_path: str
    oast_provider: OASTProvider
    channel_manager: ChannelManager = field(default_factory=ChannelManager)

    def get_cache_path_for_tool(self, tool_id_str: str, additional_hosts: Dict[str, str]) -> str:
        digest = hashlib.sha512()
        digest.update(tool_id_str.encode("utf-8"))
        if additional_hosts:
            digest.update(json.dumps(additional_hosts).encode("utf-8"))
        sha512_str = digest.hexdigest()
        path = os.path.join(self.cache_path, sha512_str[0:2], sha512_str[2:4], sha512_str[4:])
        os.makedirs(path, exist_ok=True)
        return path
