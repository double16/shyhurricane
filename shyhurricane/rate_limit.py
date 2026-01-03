import ipaddress
from typing import Optional

import tldextract
import validators
from pydantic import ValidationError

from shyhurricane.utils import urlparse_ext


def _is_public_registrable_domain(s: str) -> bool:
    r = tldextract.extract(s, include_psl_private_domains=False)
    # Empty if invalid / not registrable (e.g., "co.uk", "localhost", "corp", IPs, unknown TLDs)
    return bool(r.top_domain_under_public_suffix)


def _is_public_target(target: str) -> bool:
    try:
        return ipaddress.ip_address(target).is_global
    except ValueError:
        try:
            validators.url(target, skip_ipv4_addr=False, skip_ipv6_addr=False, simple_host=True, strict_query=False,
                           consider_tld=False)
            if "://" in target:
                url_parsed = urlparse_ext(target)
            else:
                url_parsed = urlparse_ext("http://" + target)
            if url_parsed.hostname:
                target = url_parsed.hostname
        except ValidationError:
            try:
                validators.hostname(target, skip_ipv4_addr=False, skip_ipv6_addr=False, may_have_port=True,
                                    simple_host=True, consider_tld=False)
                target = urlparse_ext("http://" + target).hostname
            except ValidationError:
                return False
    try:
        return ipaddress.ip_address(target).is_global
    except ValueError:
        pass
    return _is_public_registrable_domain(target)


def get_rate_limit_requests_per_second(target: str) -> Optional[int]:
    if not _is_public_target(target):
        return None
    return 5
