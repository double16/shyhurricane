import hashlib
import json
import logging
import os
from dataclasses import dataclass
from typing import Dict

logger = logging.getLogger(__name__)


@dataclass
class AppContext:
    # TODO: add scope?
    cached_get_additional_hosts: Dict[str, str]
    http_headers: Dict[str, str]
    cache_path: str
    app_context_id: str
    work_path: str

    def get_cache_path_for_tool(self, tool_id_str: str, additional_hosts: Dict[str, str]) -> str:
        digest = hashlib.sha512()
        digest.update(tool_id_str.encode("utf-8"))
        if additional_hosts:
            digest.update(json.dumps(additional_hosts).encode("utf-8"))
        sha512_str = digest.hexdigest()
        path = os.path.join(self.cache_path, sha512_str[0:2], sha512_str[2:4], sha512_str[4:])
        os.makedirs(path, exist_ok=True)
        return path
