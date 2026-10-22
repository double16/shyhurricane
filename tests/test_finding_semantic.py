"""Lazy provider initialization, serialization, cancellation, and failure recovery."""

import asyncio
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import shyhurricane.finding_semantic as semantic


@pytest.mark.asyncio
@pytest.mark.parametrize("warm_up", [True, False])
async def test_lazy_embedder_reuses_matching_model(monkeypatch, warm_up):
    embedder = SimpleNamespace(run=Mock(return_value={"embedding": [0.5, 0.2]}))
    if warm_up:
        embedder.warm_up = Mock()
    factory = Mock(return_value=embedder)
    search = semantic.FindingSemanticSearch(lambda: SimpleNamespace(create_text_embedder=factory))
    factory.assert_not_called()
    await search.prepare()
    await search.prepare()
    assert await search.embed("first") == [0.5, 0.2]
    assert await search.embed("second") == [0.5, 0.2]
    factory.assert_called_once_with(semantic.get_model_for_doc_type("finding").model_config)
    assert embedder.run.call_args_list[0].kwargs == {"text": "first"}
    if warm_up:
        embedder.warm_up.assert_called_once()


@pytest.mark.asyncio
async def test_initialization_failure_can_retry(monkeypatch):
    embedder = SimpleNamespace(run=lambda **kwargs: {"embedding": [1.0]})
    factory = Mock(side_effect=[RuntimeError("provider unavailable"), embedder])
    search = semantic.FindingSemanticSearch(lambda: SimpleNamespace(create_text_embedder=factory))
    with pytest.raises(RuntimeError, match="provider unavailable"):
        await search.embed("first")
    assert search.embedder is None
    assert await search.embed("retry") == [1.0]


@pytest.mark.asyncio
async def test_cancellation_keeps_running_inference_serialized():
    search = semantic.FindingSemanticSearch(lambda: None)
    entered, release = threading.Event(), threading.Event()
    calls = []

    def run(text):
        calls.append(text)
        if text == "first":
            entered.set()
            assert release.wait(5)
        return {"embedding": [1.0]}

    search.embedder = SimpleNamespace(run=run)
    first = asyncio.create_task(search.embed("first"))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        second = asyncio.create_task(search.embed("second"))
        await asyncio.sleep(0)
        assert calls == ["first"]
    finally:
        release.set()
    assert await second == [1.0]
    assert calls == ["first", "second"]
