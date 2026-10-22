"""Create and repair payload indexes with the application's tuned settings."""

import re
from enum import Enum

from haystack_integrations.document_stores.qdrant import QdrantDocumentStore
from qdrant_client.http import models as qm

SEMANTIC_FILTER_FIELDS = frozenset({
    "meta.version", "meta.netloc", "meta.domain", "meta.http_method", "meta.status_code",
})
INDEX_PARAMS = {
    "integer": qm.IntegerIndexParams,
    "keyword": qm.KeywordIndexParams,
    "float": qm.FloatIndexParams,
    "datetime": qm.DatetimeIndexParams,
    "bool": qm.BoolIndexParams,
    "text": qm.TextIndexParams,
}


def index_type(schema):
    """Read the base type from a field declaration or parameterized schema."""
    if isinstance(schema, Enum):
        return schema.value
    if isinstance(schema, str):
        return schema
    if isinstance(schema, dict):
        return index_type(schema["type"])
    return index_type(schema.type)


def tuned_indexes(fields):
    """Avoid range indexes and HNSW edges unused by application queries."""
    tuned = []
    for declaration in fields or []:
        schema = declaration["field_schema"]
        kind = index_type(schema)
        params = {} if isinstance(schema, str) else (
            dict(schema) if isinstance(schema, dict) else schema.model_dump(exclude_unset=True)
        )
        params.update(type=kind, enable_hnsw=declaration["field_name"] in SEMANTIC_FILTER_FIELDS)
        if kind == "integer":
            params.update(lookup=True, range=False)
        tuned.append({**declaration, "field_schema": INDEX_PARAMS[kind](**params)})
    return tuned


def require_tuned_index_version(version):
    """Reject unsupported servers before creating or replacing a collection."""
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[-+].*)?", version)
    if match is None or tuple(map(int, match.groups())) < (1, 17, 0):
        raise ValueError(
            f"Creating tuned payload indexes requires Qdrant 1.17+; server reports {version!r}. "
            "Upgrade Qdrant before creating collections or repairing missing indexes."
        )


def _limit_connect_timeout(request):
    """Keep connection establishment short without shortening response or upload waits."""
    timeouts = dict(request.extensions.get("timeout", {}))
    connect = timeouts.get("connect")
    timeouts["connect"] = min(connect, 5) if connect is not None else 5
    request.extensions["timeout"] = timeouts


def short_connect(request, call_next):
    _limit_connect_timeout(request)
    return call_next(request)


async def short_connect_async(request, call_next):
    _limit_connect_timeout(request)
    return await call_next(request)


def missing_indexes(schema, fields):
    """Return absent declarations and reject incompatible existing index types."""
    missing = []
    for declaration in fields or []:
        name = declaration["field_name"]
        expected = index_type(declaration["field_schema"])
        if name not in schema:
            missing.append(declaration)
        elif schema[name].data_type != expected:
            raise ValueError(f"Qdrant payload index {name} requires type {expected}")
    return missing


class IndexedQdrantDocumentStore(QdrantDocumentStore):
    """Ensure declared indexes exist on both new and previously populated collections."""

    def recreate_collection(self, *args, **kwargs):
        if self.payload_fields_to_index:
            self._initialize_client()
            require_tuned_index_version(self._client.info().version)
        return super().recreate_collection(*args, **kwargs)

    async def recreate_collection_async(self, *args, **kwargs):
        if self.payload_fields_to_index:
            await self._initialize_async_client()
            require_tuned_index_version((await self._async_client.info()).version)
        return await super().recreate_collection_async(*args, **kwargs)

    def _create_payload_index(self, collection_name, payload_fields_to_index=None):
        # Haystack calls this hook only when creating/recreating a collection.
        for declaration in tuned_indexes(payload_fields_to_index):
            self._client.create_payload_index(collection_name=collection_name, wait=True, **declaration)

    async def _create_payload_index_async(self, collection_name, payload_fields_to_index=None):
        for declaration in tuned_indexes(payload_fields_to_index):
            await self._async_client.create_payload_index(collection_name=collection_name, wait=True, **declaration)

    def _set_up_collection(self, *args, **kwargs):
        try:
            self._client.http.client.add_middleware(short_connect)
        except NotImplementedError:
            pass  # In-memory Qdrant clients have no HTTP transport.
        super()._set_up_collection(*args, **kwargs)
        schema = self._client.get_collection(self.index).payload_schema
        missing = missing_indexes(schema, tuned_indexes(self.payload_fields_to_index))
        if missing:
            require_tuned_index_version(self._client.info().version)
        for declaration in missing:
            self._client.create_payload_index(collection_name=self.index, wait=True, **declaration)

    async def _set_up_collection_async(self, *args, **kwargs):
        try:
            self._async_client.http.client.add_middleware(short_connect_async)
        except NotImplementedError:
            pass  # In-memory Qdrant clients have no HTTP transport.
        await super()._set_up_collection_async(*args, **kwargs)
        schema = (await self._async_client.get_collection(self.index)).payload_schema
        missing = missing_indexes(schema, tuned_indexes(self.payload_fields_to_index))
        if missing:
            require_tuned_index_version((await self._async_client.info()).version)
        for declaration in missing:
            await self._async_client.create_payload_index(collection_name=self.index, wait=True, **declaration)
