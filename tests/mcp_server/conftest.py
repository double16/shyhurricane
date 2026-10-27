"""Keep tool-result snapshots isolated from the running server in unit tests."""

import pytest

from shyhurricane import result_pages


@pytest.fixture(autouse=True)
def result_store(tmp_path, monkeypatch):
    store = result_pages.ResultPageStore(str(tmp_path))

    async def get_store():
        return store

    monkeypatch.setattr(result_pages, "get_result_store", get_store)
    yield store
    store.close()
