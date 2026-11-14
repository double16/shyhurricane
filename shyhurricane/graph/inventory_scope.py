"""Typed URL facets shared by inventory writers and scoped Cypher readers."""

from urllib.parse import urlsplit

from shyhurricane.graph.model import optional_filter


def url_properties(url):
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    return {"host": host, "reverse_host": host[::-1] + ".", "scheme": parsed.scheme,
            "port": parsed.port or (443 if parsed.scheme in {"https", "wss"} else 80),
            "path": parsed.path or "/"}


def scope_parameters(scope):
    from shyhurricane.graph.query import scope_predicate

    scope_predicate(scope)
    explicit = "://" in scope
    parsed = urlsplit(scope if explicit else "https://" + scope)
    return {"scope_host": parsed.hostname.lower(), "scope_reverse_host": parsed.hostname.lower()[::-1] + ".", "scope_port": parsed.port,
            "scope_scheme": parsed.scheme if explicit else None,
            "scope_path": (parsed.path or "/") if explicit else None,
            "scope_subdomains": not explicit}


def scope_clause(alias):
    """The alias is an internal literal, never request data."""
    return (
        f"{alias}.reverse_host STARTS WITH $scope_reverse_host "
        f"AND ($scope_subdomains OR {alias}.reverse_host=$scope_reverse_host) "
        f"AND ($scope_port IS NULL OR {alias}.port=$scope_port) "
        f"AND ($scope_scheme IS NULL OR {alias}.scheme=$scope_scheme) "
        f"AND ($scope_path IS NULL OR {alias}.path STARTS WITH $scope_path)"
    )


def inventory_filters(kind=None, kinds=None, role=None, url=None, method=None, capture_id=None, exclude_kinds=()):
    parameters = {"kinds": list(kinds or ([kind] if kind else [])), "excluded": list(exclude_kinds),
                  "role": optional_filter(role), "url": optional_filter(url),
                  "method": optional_filter(method), "capture_id": capture_id}
    if parameters["method"]:
        parameters["method"] = parameters["method"].upper()
    return parameters
