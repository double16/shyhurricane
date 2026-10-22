"""Finding predicates, metadata, and conservative indexed filtering."""

from urllib.parse import urlsplit

import pytest
from qdrant_client.local.payload_filters import check_filter

from shyhurricane.finding_search import (
    finding_candidate_filter,
    finding_matches,
    finding_predicates,
    finding_search_metadata,
)
from shyhurricane.task_queue.finding_worker import FINDING_VERSION


def metadata(url="", host="example.com", port=0):
    parsed = urlsplit(url)
    return {
        "url": url,
        "host": parsed.hostname or host,
        "port": parsed.port or {"https": 443, "http": 80}.get(parsed.scheme, port),
        "version": FINDING_VERSION,
        **finding_search_metadata(url, parsed.hostname or host),
    }


@pytest.mark.parametrize(
    "target,scope",
    [
        ("https://example.com/", "example.com"),
        ("http://example.com", "example.com"),
        ("https://example.com:8443/", "example.com:8443"),
        ("https://example.com/api/", "https://example.com/api/"),
        ("[::1]:8080", "[::1]:8080"),
        ("site:https://example.com/", "https://example.com/"),
    ],
)
def test_plain_scope_normalization(target, scope):
    assert finding_predicates(target)[0].value == scope


@pytest.mark.parametrize(
    "target",
    [
        "",
        "not a target",
        "inurl:admin",
        "-site:example.com",
        "site:",
        "site:example.com XSS",
        "site:example.com intitle:test",
        "site:example.com status:201",
        "site:example.com method:POST",
        "site:example.com mime:text/html",
        "site:example.com type:network",
        "https://example.com/?q=1",
        "https://example.com/#part",
        "https://user:pass@example.com/",
        "ftp://example.com",
        "site:example.com:99999",
        'site:example.com inurl:"',
    ],
)
def test_reject_invalid_queries(target):
    with pytest.raises(ValueError):
        finding_predicates(target)


@pytest.mark.parametrize(
    "host,suffixes",
    [
        ("API.Example.COM", ["api.example.com", "example.com", "com"]),
        ("192.0.2.1", ["192.0.2.1"]),
        ("2001:db8::1", ["2001:db8::1"]),
    ],
)
def test_metadata(host, suffixes):
    meta = finding_search_metadata("https://example.com/App.JS?q=.html", host)
    assert meta["search_host_suffixes"] == suffixes
    assert meta["search_extension"] == "js"
    assert meta["search_scheme"] == "https"
    assert finding_search_metadata("", host)["search_extension"] == ""


@pytest.mark.parametrize(
    "query,url,host,port,expected",
    [
        ("example.com", "", "api.example.com", 0, True),
        ("example.com", "", "notexample.com", 0, False),
        ("example.com:8443", "", "example.com", 8443, True),
        ("example.com:8443", "", "example.com", 0, False),
        ("site:https://example.com/", "", "example.com", 0, False),
        ("site:example.com/api/", "", "example.com", 0, False),
        ("site:example.com -site:api.example.com", "", "api.example.com", 0, False),
        ("site:example.com -site:https://example.com/", "", "example.com", 0, True),
        ("site:example.com ext:js", "", "example.com", 0, False),
        ("site:example.com -ext:js", "", "example.com", 0, True),
        ("192.0.2.1", "", "192.0.2.1", 0, True),
        ("192.0.2.1", "", "sub.192.0.2.1", 0, False),
        ("[::1]:8080", "http://[::1]:8080/a", "", 0, True),
        ("site:https://example.com/api", "https://api.example.com/api/a", "", 0, True),
        ("site:https://example.com/api", "http://example.com/api/a", "", 0, False),
        ("site:example.com:443", "https://example.com/a", "", 0, True),
        ("site:example.com ext:JS", "https://example.com/a.Js?q=.html", "", 0, True),
        ('site:example.com inurl:"admin panel"', "https://example.com/admin panel", "", 0, True),
        ("site:example.com inurl:Admin", "https://example.com/admin", "", 0, False),
        ("site:example.com inurl:ab", "https://example.com/ab", "", 0, True),
        ("site:example.com inurl:abcd", "https://example.com/abc--bcd", "", 0, False),
        ("site:example.com -inurl:admin", "https://example.com/admin", "", 0, False),
        ("site:example.com site:other.test", "https://example.com/", "", 0, False),
    ],
)
def test_indexed_candidates_preserve_exact_matches(query, url, host, port, expected):
    meta = metadata(url, host, port)
    predicates = finding_predicates(query)
    matched = finding_matches(meta, predicates)
    candidate = check_filter(finding_candidate_filter(predicates, FINDING_VERSION), {"meta": meta}, 1, {})
    assert matched == expected
    assert not matched or candidate
    assert (candidate and matched) == expected


def test_trigrams_are_approximate_and_exclusions_are_not_pushed():
    predicates = finding_predicates("site:example.com inurl:abcd -inurl:secret")
    meta = metadata("https://example.com/abc--bcd")
    filters = finding_candidate_filter(predicates, FINDING_VERSION)
    assert check_filter(filters, {"meta": meta}, 1, {})
    assert not finding_matches(meta, predicates)
    assert not filters.must_not
    meta["version"] = FINDING_VERSION - 1
    assert not check_filter(filters, {"meta": meta}, 1, {})


@pytest.mark.parametrize("query, text, scope", [
    ("site:example.com authentication bypass", "authentication bypass", "example.com"),
    ("authentication site:example.com bypass -ext:js", "authentication  bypass", "example.com"),
    ('site:example.com inurl:"admin panel" session fixation', "session fixation", "example.com"),
    ("site:[2001:db8::1]:8443 sessions", "sessions", "[2001:db8::1]:8443"),
    ("site:https://example.com/api/ SSRF", "SSRF", "https://example.com/api/"),
    ("site:example.com", "", "example.com"),
    (" https://example.com/ ", "", "example.com"),
    ("example.com:8443", "", "example.com:8443"),
])
def test_parse_combined_finding_query(query, text, scope):
    from shyhurricane.finding_search import parse_finding_query

    semantic, predicates = parse_finding_query(query)
    assert semantic == text
    assert predicates[0].value == scope


@pytest.mark.parametrize("query", [
    "", " \n\t", "authentication bypass", "example.com authentication bypass",
    "inurl:admin authentication bypass", "-site:example.com sessions",
    "site:example.com mime:text/html sessions", "site:example.com method:GET sessions",
    "site:example.com status:200 sessions", "site:example.com type:javascript sessions",
    "site: sessions", 'site:example.com inurl:"',
])
def test_combined_finding_query_rejects_invalid_scope_and_unsupported_predicates(query):
    from shyhurricane.finding_search import parse_finding_query

    with pytest.raises(ValueError):
        parse_finding_query(query)


@pytest.mark.parametrize("url,port", [
    ("ftp://example.com/file", 21),
    ("ftps://example.com/file", 990),
    ("ftp://example.com:2121/file", 2121),
    ("ftp://[2001:db8::1]/file", 21),
])
@pytest.mark.parametrize("exclude", [False, True])
@pytest.mark.parametrize("same_port", [False, True])
def test_url_site_filters_use_saved_effective_port(url, port, exclude, same_port):
    parsed = urlsplit(url)
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    wanted_port = port if same_port else port + 1
    query = f"site:{host} {'-' if exclude else ''}site:{host}:{wanted_port}"
    meta = metadata(url, port=port)
    predicates = finding_predicates(query)
    expected = same_port != exclude
    assert finding_matches(meta, predicates) == expected
    candidate = check_filter(finding_candidate_filter(predicates, FINDING_VERSION), {"meta": meta}, 1, {})
    assert (candidate and finding_matches(meta, predicates)) == expected


def test_saved_port_does_not_remove_url_scheme_or_path_restrictions():
    meta = metadata("ftp://example.com/files/report", port=21)
    assert not finding_matches(meta, finding_predicates("site:https://example.com:21/files/"))
    assert not finding_matches(meta, finding_predicates("site:example.com:21/admin/"))
    assert finding_matches(meta, finding_predicates("site:example.com:21/files/"))
    assert not finding_matches(metadata(host="example.com", port=21),
                               finding_predicates("site:example.com:21/files/"))
