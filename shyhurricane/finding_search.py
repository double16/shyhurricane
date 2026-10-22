"""Deterministic finding scopes and indexed candidate selection."""

import ipaddress
from dataclasses import replace
from urllib.parse import urlsplit

from haystack_integrations.document_stores.qdrant.document_store import DENSE_VECTORS_NAME
from qdrant_client.http import models as qm

from shyhurricane.qdrant_reads import retrieve_records, scroll_records, to_document
from shyhurricane.search_metadata import derive_search_metadata, trigram_conditions
from shyhurricane.search_predicates import Predicate, parse_predicates

FINDING_SEMANTIC_LIMIT = 1000

FINDING_SEARCH_FIELDS = (
    "search_host_suffixes",
    "search_extension",
    "search_scheme",
    "search_url_trigrams",
)


def finding_search_metadata(url: str, host: str) -> dict:
    """Index only target attributes, never the finding's synthetic HTTP metadata."""
    host = host.lower()
    try:
        ipaddress.ip_address(host)
        suffixes = [host]
    except ValueError:
        labels = host.split(".")
        suffixes = [".".join(labels[index:]) for index in range(len(labels))]
    metadata = derive_search_metadata(url, "", {})
    return {
        "search_host_suffixes": suffixes,
        **{key: metadata[key] for key in FINDING_SEARCH_FIELDS if key != "search_host_suffixes"},
    }


def finding_predicates(target: str) -> list[Predicate]:
    """Accept a plain scope or a strictly predicate-only expression."""
    remaining, predicates = parse_predicates(target)
    if not predicates:
        value = target.strip()
        parsed = urlsplit(value if "://" in value else f"//{value}")
        # Validate before removing any URL components.
        leftover, predicates = parse_predicates(f"site:{value}")
        if leftover or len(predicates) != 1:
            raise ValueError("Plain targets must be a single hostname, IP, host:port, or HTTP(S) URL")
        if parsed.scheme in {"http", "https"} and parsed.path in {"", "/"}:
            _, predicates = parse_predicates(f"site:{parsed.netloc}")
        return predicates
    if remaining:
        raise ValueError("Finding searches accept predicates only; remove free text or unsupported predicates")
    validate_finding_predicates(predicates)
    return predicates


def validate_finding_predicates(predicates: list[Predicate]) -> None:
    """Require an explicit scope and only predicates applicable to findings."""
    if any(predicate.operator not in {"site", "inurl", "filetype"} for predicate in predicates):
        raise ValueError("Findings support only site:, inurl:, and filetype:/ext:")
    if not any(predicate.operator == "site" and not predicate.exclude for predicate in predicates):
        raise ValueError("Include a positive site: scope, such as site:example.com")


def parse_finding_query(query: str) -> tuple[str, list[Predicate]]:
    """Separate semantic text from mandatory, exactly verified finding scope."""
    if not query.strip():
        raise ValueError("Include a scope such as site:example.com; query must not be blank")
    semantic_query, predicates = parse_predicates(query)
    if predicates:
        validate_finding_predicates(predicates)
        return semantic_query, predicates
    # Standalone targets retain shorthand and root-URL normalization.
    return "", finding_predicates(query)


def finding_matches(meta: dict, predicates: list[Predicate]) -> bool:
    """Use saved effective ports and preserve actual URL scheme/path restrictions."""
    for predicate in predicates:
        if predicate.operator == "site":
            scope = urlsplit(predicate.value if "://" in predicate.value else f"//{predicate.value}")
            url = urlsplit(meta.get("url", ""))
            host = (url.hostname or meta.get("host", "")).lower()
            wanted = scope.hostname.lower()
            try:
                ipaddress.ip_address(wanted)
                matched = host == wanted
            except ValueError:
                matched = host == wanted or host.endswith(f".{wanted}")
            matched = matched and (not scope.scheme or scope.scheme == url.scheme)
            matched = matched and (not scope.path or bool(meta.get("url")) and url.path.startswith(scope.path))
            matched = matched and (scope.port is None or scope.port == meta.get("port"))
            if matched == predicate.exclude:
                return False
        elif not predicate.matches(meta):
            return False
    return True


def finding_candidate_filter(predicates: list[Predicate], version: int) -> qm.Filter:
    """Build conservative indexed filters; substring candidates need exact verification."""
    must = [qm.FieldCondition(key="meta.version", match=qm.MatchValue(value=version))]
    must_not = []
    for predicate in predicates:
        if predicate.operator == "filetype":
            condition = qm.FieldCondition(key="meta.search_extension", match=qm.MatchValue(value=predicate.value))
            (must_not if predicate.exclude else must).append(condition)
        elif not predicate.exclude:
            if predicate.operator == "site":
                scope = urlsplit(predicate.value if "://" in predicate.value else f"//{predicate.value}")
                must.append(
                    qm.FieldCondition(
                        key="meta.search_host_suffixes",
                        match=qm.MatchValue(value=scope.hostname.lower()),
                    )
                )
                if scope.port is not None:
                    must.append(qm.FieldCondition(key="meta.port", match=qm.MatchValue(value=scope.port)))
                if scope.scheme:
                    must.append(qm.FieldCondition(key="meta.search_scheme", match=qm.MatchValue(value=scope.scheme)))
                substring = scope.path
            else:
                substring = predicate.value
            must.extend(trigram_conditions("meta.search_url_trigrams", substring))
    return qm.Filter(must=must, must_not=must_not)


async def finding_ids(client, predicates: list[Predicate], version: int):
    """Verify projected candidates without hydrating finding bodies."""
    fields = [f"meta.{name}" for name in ("url", "host", "port")]
    ids = []
    async for point in scroll_records(client, "finding", finding_candidate_filter(predicates, version), fields):
        if finding_matches((point.payload or {}).get("meta", {}), predicates):
            ids.append(point.id)
    ids.sort(key=str)
    return ids


async def search_findings(client, predicates: list[Predicate], version: int):
    """Verify projected candidates before hydrating complete finding bodies."""
    ids = await finding_ids(client, predicates, version)
    return await load_findings(client, ids)


async def load_findings(client, ids, scores=None):
    docs = []
    for point in await retrieve_records(client, "finding", ids):
        docs.append(replace(to_document(point), score=(scores or {}).get(str(point.id))))
    return docs


async def rank_findings(client, ids, embedding, score_threshold):
    """Rank exact scoped IDs, returning bounded IDs and scores without bodies."""
    result = await client.query_points(
        collection_name="finding",
        query=embedding,
        using=DENSE_VECTORS_NAME,
        query_filter=qm.Filter(must=[qm.HasIdCondition(has_id=ids)]),
        search_params=qm.SearchParams(exact=True),
        limit=FINDING_SEMANTIC_LIMIT + 1,
        score_threshold=score_threshold,
        with_payload=False,
        with_vectors=False,
    )
    points = sorted(result.points, key=lambda point: (-point.score, str(point.id)))
    return points[:FINDING_SEMANTIC_LIMIT], len(points) > FINDING_SEMANTIC_LIMIT
