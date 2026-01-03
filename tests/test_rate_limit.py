import pytest

from shyhurricane.rate_limit import get_rate_limit_requests_per_second


@pytest.mark.parametrize(
    "target",
    ["google.com", "8.8.8.8"]
)
def test_get_rate_limit_requests_per_second_public(target):
    assert get_rate_limit_requests_per_second(target) == 5


@pytest.mark.parametrize(
    "target",
    ["host1.local", "192.168.1.1", "127.0.0.1", "co.uk"]
)
def test_get_rate_limit_requests_per_second_private(target):
    assert get_rate_limit_requests_per_second(target) is None
