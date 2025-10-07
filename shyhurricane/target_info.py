from typing import Optional, Iterable, List

from pydantic import BaseModel, Field
from tldextract import tldextract

from shyhurricane.utils import urlparse_ext, extract_domain, filter_hosts_and_addresses, query_to_netloc


class TargetInfo(BaseModel):
    url: Optional[str] = Field(default="URL")
    netloc: Optional[str] = Field(default="host:port")
    host: str = Field(default="host")
    port: Optional[int] = Field(default="port")
    domain: str = Field(default="domain")

    def to_url(self) -> str:
        if self.url:
            return self.url
        scheme = "https" if self.port and self.port % 1000 == 443 else "http"
        if self.netloc:
            return f"{scheme}://{self.netloc}"
        host = self.host or self.domain
        if tldextract.extract(host, include_psl_private_domains=False).top_domain_under_public_suffix:
            scheme = "https"
        else:
            scheme = "http"
        return f"{scheme}://{host}"

    def with_port(self, new_port: int) -> "TargetInfo":
        return TargetInfo(
            url=self.url,
            netloc=f"{self.host}:{new_port}" if self.host else None,
            host=self.host,
            port=new_port,
            domain=self.domain,
        )


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


def filter_targets_query(query: str) -> List[str]:
    result = []
    for part in query.split():
        # check for end of sentence
        if part[-1] in ['.', '!', '?', ':', ';']:
            part = part[:-1]
        try:
            parse_target_info(part)
            result.append(part)
        except ValueError:
            pass
    return result
