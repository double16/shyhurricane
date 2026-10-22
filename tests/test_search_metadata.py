from urllib.parse import urlsplit

import pytest
from qdrant_client.http import models as qm
from qdrant_client.local.payload_filters import check_filter

from shyhurricane.search_metadata import SEARCH_FIELDS, candidate_scope, derive_search_metadata, url_trigrams
from shyhurricane.search_predicates import parse_predicates


@pytest.mark.parametrize("url,extension", [
    ("https://example.com/A.JS?q=.html", "js"),
    ("https://example.com/path/", ""),
    ("https://example.com/.config", "config"),
    ("https://example.com/file.", ""),
])
def test_derived_metadata(url, extension):
    meta = derive_search_metadata(url, "gEt", {"cOnTeNt-TyPe": " Text/HTML ; charset=UTF-8"})
    assert set(meta) == set(SEARCH_FIELDS)
    assert meta["search_method"] == "GET"
    assert meta["search_extension"] == extension
    assert meta["search_response_mime"] == "text/html"
    assert meta["search_scheme"] == "https"
    assert meta["search_url_trigrams"] == sorted(set(url_trigrams(url)))
    assert derive_search_metadata(url, "POST", {})["search_response_mime"] == ""


@pytest.mark.parametrize("value,expected", [
    ("", []), ("ab", []), ("aaa", ["aaa"]), ("aaaa", ["aaa"]),
    ("A%2F/é🐈", ["%2F", "/é🐈", "2F/", "A%2", "F/é"]),
])
def test_url_trigrams_preserve_characters(value, expected):
    assert url_trigrams(value) == expected


def test_inventory_trigrams_use_canonical_lowercase_metadata():
    meta = derive_search_metadata("https://a.test/", "GET", {}, host="WWW.Example.COM", domain="Example.COM")
    assert meta["search_host_trigrams"] == url_trigrams("www.example.com")
    assert meta["search_domain_trigrams"] == url_trigrams("example.com")


@pytest.mark.parametrize("query", [
    "inurl:Admin", "inurl:admin", "inurl:ab", "-inurl:admin", "inurl:'?q=Admin'",
    "inurl:%2F", "inurl:é🐈", "filetype:js", "-ext:js", "method:GET", "-method:GET",
    "mime:text/html", "-mime:text/html", "status:403", "-status:200", "type:network", "-type:network",
    "site:https://example.com/Admin", "site:http://example.com/Admin", "site:example.com:8443/",
    "-site:example.com/Admin", "site:example.com inurl:Admin -method:POST",
])
def test_candidate_filters_never_exclude_exact_matches(query):
    _, predicates = parse_predicates(query)
    scope = candidate_scope(qm.Filter(), predicates, [])
    for url in (
        "https://example.com/Admin.js?q=Admin", "http://example.com/admin.js",
        "https://sub.example.com:8443/Admin/ab", "https://elsewhere.test/%2F/é🐈",
        "https://example.com/abc--bcd",
    ):
        for method, mime, status, kind in (("gEt", "text/html", 200, "content"),
                                            ("POST", "", 403, "network")):
            meta = {
                "url": url, "http_method": method, "status_code": status, "type": kind,
                **derive_search_metadata(url, method, {"Content-Type": mime}),
            }
            expected = all(predicate.matches(meta, mime or None) for predicate in predicates)
            candidate = check_filter(scope, {"meta": meta}, 1, {})
            assert not expected or candidate, (query, meta)
            assert (candidate and all(p.matches(meta, mime or None) for p in predicates)) == expected


def test_trigrams_are_a_positive_approximation_and_short_queries_have_no_filter():
    _, predicates = parse_predicates("inurl:abcd")
    meta = {"url": "https://a.test/abc--bcd"}
    meta.update(derive_search_metadata(meta["url"], "GET", {}))
    assert check_filter(candidate_scope(qm.Filter(), predicates, []), {"meta": meta}, 1, {})
    assert not predicates[0].matches(meta)
    for query in ("inurl:ab", "-inurl:abcd", "-site:https://a.test/path"):
        _, predicates = parse_predicates(query)
        scope = candidate_scope(qm.Filter(), predicates, [])
        assert scope.must == [qm.Filter()]
        assert scope.must_not == []


def test_long_substring_filter_is_bounded_and_method_arguments_intersect():
    value = "".join(chr(index) for index in range(1000, 1200))
    _, predicates = parse_predicates(f"inurl:{value} method:POST")
    scope = candidate_scope(qm.Filter(), predicates, ["GET"])
    assert len(scope.must) == 67
    url = f"https://a.test/{value}"
    meta = derive_search_metadata(url, "POST", {})
    assert not check_filter(scope, {"meta": meta}, 1, {})
    assert urlsplit(url).path.endswith(value)
