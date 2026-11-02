"""Finding target coordinates without constructing ambiguous IPv6 authorities."""

from dataclasses import dataclass
from urllib.parse import urlsplit

from shyhurricane.graph.model import web_url
from shyhurricane.target_info import parse_target_info


@dataclass(frozen=True)
class TargetCoordinates:
    host_key: str
    scope: str
    comparison_url: str
    url: str | None


def target_coordinates(target):
    explicit = "://" in target
    info = parse_target_info(f"https://{target}" if target.startswith("[") and not explicit else target)
    host = info.host.lower()
    authority = f"[{host}]" if ":" in host else host
    port = (
        urlsplit(target if explicit else f"https://{target}").port if explicit or target.startswith("[") else info.port
    )
    if port is not None:
        authority += f":{port}"
    return TargetCoordinates(
        ".".join(reversed(host.split("."))),
        authority,
        target if explicit else f"https://{authority}/",
        web_url(target) if explicit else None,
    )
