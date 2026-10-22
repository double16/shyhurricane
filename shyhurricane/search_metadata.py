"""Indexed HTTP predicate metadata and conservative Qdrant candidate filters."""

from urllib.parse import urlsplit

from qdrant_client.http import models as qm

SEARCH_FIELDS = (
    "search_method", "search_extension", "search_response_mime", "search_scheme",
    "search_url_trigrams", "search_host_trigrams", "search_domain_trigrams",
)


def url_trigrams(value: str) -> list[str]:
    return sorted({value[index:index + 3] for index in range(len(value) - 2)})


def trigram_conditions(field: str, value: str) -> list:
    """Require a bounded subset of trigrams; callers must verify exact matching."""
    return [qm.FieldCondition(key=field, match=qm.MatchValue(value=gram)) for gram in url_trigrams(value)[:64]]


def derive_search_metadata(url: str, method: str, headers: dict, *, host: str = "", domain: str = "") -> dict:
    parsed = urlsplit(url)
    filename = parsed.path.rsplit("/", 1)[-1]
    mime = next((value for key, value in headers.items() if key.lower() == "content-type"), "")
    return {
        "search_method": method.upper(),
        "search_extension": filename.rsplit(".", 1)[-1].lower() if "." in filename else "",
        "search_response_mime": mime.lower().split(";", 1)[0].strip(),
        "search_scheme": parsed.scheme,
        "search_url_trigrams": url_trigrams(url),
        "search_host_trigrams": url_trigrams(host.lower()),
        "search_domain_trigrams": url_trigrams(domain.lower()),
    }


def candidate_scope(scope, predicates, methods):
    """Push exact conditions and positive substring approximations into Qdrant."""
    must = [scope]
    must_not = []
    fields = {
        "method": "search_method", "filetype": "search_extension", "mime": "search_response_mime",
        "status": "status_code", "type": "type",
    }
    if methods:
        must.append(qm.FieldCondition(key="meta.search_method", match=qm.MatchAny(any=methods)))
    for predicate in predicates:
        if predicate.operator in fields:
            value = int(predicate.value) if predicate.operator == "status" else predicate.value
            condition = qm.FieldCondition(key=f"meta.{fields[predicate.operator]}", match=qm.MatchValue(value=value))
            (must_not if predicate.exclude else must).append(condition)
        elif not predicate.exclude:
            substring = ""
            if predicate.operator == "inurl":
                substring = predicate.value
            elif predicate.operator == "site":
                target = urlsplit(predicate.value if "://" in predicate.value else f"//{predicate.value}")
                substring = target.path
                if target.scheme:
                    must.append(qm.FieldCondition(key="meta.search_scheme", match=qm.MatchValue(value=target.scheme)))
            must.extend(trigram_conditions("meta.search_url_trigrams", substring))
    return qm.Filter(must=must, must_not=must_not)
