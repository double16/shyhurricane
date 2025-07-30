from typing import Optional, Iterable, List

from pydantic import BaseModel, Field

from shyhurricane.utils import urlparse_ext, extract_domain, filter_hosts_and_addresses, query_to_netloc


class TargetInfo(BaseModel):
    url: Optional[str] = Field(default="URL")
    netloc: Optional[str] = Field(default="host:port")
    host: str = Field(default="host")
    port: Optional[int] = Field(default="port")
    domain: str = Field(default="domain")


def parse_target_info(target: str) -> TargetInfo:
    """
    Parse a target info string. Maybe a URL, host, host:port, or domain.
    :exception: ValueError if malformed
    """
    try:
        if "://" in target:
            url_parsed = urlparse_ext(target)
            if url_parsed.hostname:
                return TargetInfo(
                    url=target,
                    netloc=url_parsed.netloc,
                    host=url_parsed.hostname,
                    port=url_parsed.port,
                    domain=extract_domain(url_parsed.hostname),
                )
    except ValueError:
        pass

    host, port = query_to_netloc(target)
    if host and filter_hosts_and_addresses([host]):
        return TargetInfo(
            url=None,
            netloc=f"{host}:{port}" if port else None,
            host=host,
            port=port,
            domain=extract_domain(host),
        )

    if filter_hosts_and_addresses([target]):
        return TargetInfo(
            url=None,
            netloc=None,
            host=target,
            port=None,
            domain=extract_domain(target),
        )

    raise ValueError()


def filter_targets_str(targets: Iterable[str]) -> List[str]:
    result = []
    for target_in in targets:
        try:
            parse_target_info(target_in)
            result.append(target_in)
        except ValueError:
            pass
    return result
