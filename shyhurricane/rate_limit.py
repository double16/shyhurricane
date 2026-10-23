import ipaddress
from typing import Annotated, Optional, TypeAlias

import tldextract
from pydantic import Field

from shyhurricane.utils import urlparse_ext

RateLimitRequestsPerSecondField: TypeAlias = Optional[Annotated[int, Field(
    strict=True,
    ge=0,
    description=(
        "Maximum requests/second for this scan. A positive integer sets the limit; 0 disables "
        "the explicit limit (Katana uses a high ceiling of 3000 requests/second). Omitted or null uses 5 "
        "requests/second for public targets and preserves scanner defaults for non-public targets. "
        "Concurrent scans have separate budgets."
    ),
)]]


def _is_public_registrable_domain(s: str) -> bool:
    r = tldextract.extract(s, include_psl_private_domains=False)
    # Empty if invalid / not registrable (e.g., "co.uk", "localhost", "corp", IPs, unknown TLDs)
    return bool(r.top_domain_under_public_suffix)


def _is_public_target(target: str) -> bool:
    try:
        return ipaddress.ip_address(target).is_global
    except ValueError:
        pass
    try:
        target = urlparse_ext(target if "://" in target else f"http://{target}").hostname
    except ValueError:
        return False
    if not target:
        return False
    try:
        return ipaddress.ip_address(target).is_global
    except ValueError:
        pass
    return _is_public_registrable_domain(target)


def get_rate_limit_requests_per_second(target: str, override: Optional[int] = None) -> Optional[int]:
    """Resolve a per-scan limit without conflating explicit zero with an omitted limit."""
    if override is not None:
        if type(override) is not int or override < 0:
            raise ValueError("rate_limit_requests_per_second must be a non-negative integer or null")
        return override
    if not _is_public_target(target.strip()):
        return None
    return 5
