import pytest

from shyhurricane.search_predicates import Predicate, parse_predicates, resource_key, response_mime


@pytest.mark.parametrize(("query", "operator", "value"), [
    ("SITE:Example.com", "site", "Example.com"),
    ("inurl:'admin panel'", "inurl", "admin panel"),
    ('inurl:"admin panel"', "inurl", "admin panel"),
    ("ext:.JS", "filetype", "js"),
    ("filetype:JSON", "filetype", "json"),
    ("mime:Application/JSON", "mime", "application/json"),
    ("method:post", "method", "POST"),
    ("status:200", "status", "200"),
    ("type:NETWORK", "type", "network"),
    ("site:[::1]:8080", "site", "[::1]:8080"),
    ('inurl:"a\\\"b"', "inurl", 'a"b'),
])
def test_parse_normalization(query, operator, value):
    prose, predicates = parse_predicates(query)
    assert prose == ""
    assert predicates == [Predicate(operator, value)]


def test_parser_preserves_prose_and_unsupported_syntax():
    query = 'site:example.com find "site:quoted.test" https://a.test:8443/ intitle:login -inurl:logout'
    prose, predicates = parse_predicates(query)
    assert prose == 'find "site:quoted.test" https://a.test:8443/ intitle:login'
    assert predicates == [Predicate("site", "example.com"), Predicate("inurl", "logout", True)]
    assert parse_predicates("--site:example.com")[1] == []
    assert len(parse_predicates("site:a.test site:b.test")[1]) == 2
    assert parse_predicates('site:example.com "a    b"')[0] == '"a    b"'


@pytest.mark.parametrize("query", [
    "site:", "site:https://", "site:https://user:pass@example.com/", "site:bad!host",
    "site:ftp://example.com", "site:example.com:0", "site:example.com:65536", "site:example.com:abc",
    "site:https://example.com/?q=1", "site:https://example.com/#part", "filetype:.", "ext:a/b",
    "mime:json", "method:'bad method'", "status:no", "status:99", "status:600", "status:２００",
    "type:nmap", 'inurl:"', "inurl:''", 'inurl:"admin"junk',
])
def test_invalid_predicate_values(query):
    with pytest.raises(ValueError):
        parse_predicates(query)


@pytest.mark.parametrize(("site", "url", "matches"), [
    ("example.com", "https://example.com/", True),
    ("example.com", "https://a.example.com:9443/", True),
    ("example.com", "https://otherexample.com/", False),
    ("sub.example.com", "https://example.com/", False),
    ("example.com:443", "https://example.com/", True),
    ("example.com:443", "http://example.com/", False),
    ("https://example.com/app/", "https://example.com:9443/app/a", True),
    ("https://example.com/app/", "http://example.com/app/a", False),
    ("https://example.com/app/", "https://example.com/application", False),
    ("127.0.0.1", "http://127.0.0.1/", True),
    ("127.0.0.1", "http://x.127.0.0.1/", False),
    ("[::1]:8080", "http://[::1]:8080/", True),
    ("example.com", "", False),
])
def test_site_matching(site, url, matches):
    assert Predicate("site", site).matches({"url": url}) is matches


@pytest.mark.parametrize(("site", "netloc", "matches"), [
    ("[::1]:8080", "::1:8080", True),
    ("[::1]:8080", "[::1]:8080", True),
    ("[::1]", "::1:443", True),
    ("[::1]:8080", "::1:443", False),
    ("https://example.com/app/", "example.com:9443", True),
    ("example.com", "otherexample.com:443", False),
])
def test_site_network_scope_ignores_path_and_scheme(site, netloc, matches):
    assert Predicate("site", site).matches_netloc(netloc) is matches


@pytest.mark.parametrize(("operator", "value", "meta", "mime", "matches"), [
    ("inurl", "Admin", {"url": "https://a.test/?q=Admin"}, None, True),
    ("inurl", "admin", {"url": "https://a.test/Admin"}, None, False),
    ("filetype", "js", {"url": "https://a.test/app.JS?x=.css#frag"}, None, True),
    ("filetype", "js", {"url": "https://a.test/app?x=.js"}, None, False),
    ("filetype", "js", {"url": "https://a.test/app.js/"}, None, False),
    ("mime", "application/json", {}, "Application/JSON; charset=utf8", True),
    ("mime", "application/json", {}, None, False),
    ("mime", "application/json", {}, "text/html", False),
    ("method", "POST", {"http_method": "post"}, None, True),
    ("method", "POST", {}, None, False),
    ("status", "200", {"status_code": 200}, None, True),
    ("status", "200", {"status_code": 403}, None, False),
    ("type", "network", {"type": "network"}, None, True),
    ("type", "network", {"type": "content"}, None, False),
])
def test_predicate_matching_and_exclusions(operator, value, meta, mime, matches):
    assert Predicate(operator, value).matches(meta, mime) is matches
    assert Predicate(operator, value, True).matches(meta, mime) is not matches


@pytest.mark.parametrize(("meta", "expected"), [
    ({"type": "content", "content_type": "text/html"}, "text/html"),
    ({"type": "network", "content_type": "text/plain",
      "response_headers": '{"content-type": "application/json"}'}, "application/json"),
    ({"type": "forms", "response_headers": "[]"}, None),
    ({"type": "network", "response_headers": "not json"}, None),
    ({"type": "network", "response_headers": None}, None),
    ({"type": "network"}, None),
])
def test_response_mime(meta, expected):
    assert response_mime(meta) == expected


def test_resource_identity_includes_capture_timestamp():
    assert resource_key({}) == (None, None, None, None)
    assert resource_key({"url": "u", "http_method": "GET", "status_code": 200, "timestamp": "t"}) == (
        "u", "GET", 200, "t",
    )
