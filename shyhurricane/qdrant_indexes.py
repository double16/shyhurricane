"""Reconcile payload indexes when Haystack opens an existing collection."""

from haystack_integrations.document_stores.qdrant import QdrantDocumentStore


def missing_indexes(schema, fields):
    """Return absent declarations and reject incompatible existing index types."""
    missing = []
    for declaration in fields or []:
        name = declaration["field_name"]
        expected = declaration["field_schema"]
        if name not in schema:
            missing.append(declaration)
        elif schema[name].data_type != expected:
            raise ValueError(f"Qdrant payload index {name} requires type {expected}")
    return missing


class IndexedQdrantDocumentStore(QdrantDocumentStore):
    """Ensure declared indexes exist on both new and previously populated collections."""

    def _set_up_collection(self, *args, **kwargs):
        super()._set_up_collection(*args, **kwargs)
        schema = self._client.get_collection(self.index).payload_schema
        for declaration in missing_indexes(schema, self.payload_fields_to_index):
            self._client.create_payload_index(collection_name=self.index, wait=True, **declaration)

    async def _set_up_collection_async(self, *args, **kwargs):
        await super()._set_up_collection_async(*args, **kwargs)
        schema = (await self._async_client.get_collection(self.index)).payload_schema
        for declaration in missing_indexes(schema, self.payload_fields_to_index):
            await self._async_client.create_payload_index(collection_name=self.index, wait=True, **declaration)
