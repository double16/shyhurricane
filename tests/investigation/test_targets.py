"""Finding target and scope coordinates retain ports and bracket IPv6 correctly."""

import pytest

from shyhurricane.investigation.targets import target_coordinates


@pytest.mark.parametrize(
    "target,scope,url",
    [
        ("2001:db8::1", "[2001:db8::1]", None),
        ("[2001:db8::1]", "[2001:db8::1]", None),
        ("[2001:db8::1]:8443", "[2001:db8::1]:8443", None),
        ("https://[2001:db8::1]:8443/path", "[2001:db8::1]:8443", "https://[2001:db8::1]:8443/path"),
        ("https://example.com/path", "example.com", "https://example.com/path"),
        ("127.0.0.1:8080", "127.0.0.1:8080", None),
        ("example.com", "example.com", None),
    ],
)
def test_coordinates(target, scope, url):
    result = target_coordinates(target)
    assert result.scope == scope and result.url == url
    if url is None:
        assert result.comparison_url == f"https://{scope}/"


@pytest.mark.parametrize("target", ["", "[broken]", "https://[bad]/"])
def test_invalid_coordinates_are_rejected(target):
    with pytest.raises(ValueError):
        target_coordinates(target)
