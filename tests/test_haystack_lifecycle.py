from unittest.mock import Mock

import pytest
from haystack import Pipeline
from haystack.dataclasses import ChatMessage, ChatRole, TextContent

from shyhurricane import haystack_lifecycle as lifecycle
from shyhurricane.generator_config import ChatGeneratorCompatibilityWrapper


@pytest.fixture(autouse=True)
def isolated_resources(monkeypatch):
    monkeypatch.setattr(lifecycle, "_resources", {})
    yield
    lifecycle.close_haystack_resources()


def test_resource_cleanup_is_process_owned_idempotent_and_continues_after_errors(monkeypatch, caplog):
    resource = Mock()
    broken = Mock()
    broken.close.side_effect = RuntimeError("close failed")
    foreign = Mock()
    monkeypatch.setattr(lifecycle.os, "getpid", lambda: 1)
    lifecycle.register_resource(broken)
    assert lifecycle.register_resource(resource) is resource
    lifecycle.register_resource(resource)
    lifecycle.register_resource(object())
    monkeypatch.setattr(lifecycle.os, "getpid", lambda: 2)
    lifecycle.register_resource(foreign)
    monkeypatch.setattr(lifecycle.os, "getpid", lambda: 1)
    lifecycle.close_haystack_resources()
    lifecycle.close_haystack_resources()
    resource.close.assert_called_once_with()
    broken.close.assert_called_once_with()
    foreign.close.assert_not_called()
    assert "close failed" in caplog.text
    monkeypatch.setattr(lifecycle.os, "getpid", lambda: 2)
    lifecycle.close_haystack_resources()
    foreign.close.assert_called_once_with()


def test_managed_factory_preserves_arguments_and_tracks_shared_resource_once():
    resource = Mock()
    factory = Mock(return_value=resource)
    managed = lifecycle.managed_resource(factory)
    assert managed("model", option=True) is resource
    assert managed("model", option=True) is resource
    factory.assert_called_with("model", option=True)
    lifecycle.close_haystack_resources()
    resource.close.assert_called_once_with()


def test_generator_factory_preserves_eager_initialization_and_non_lifecycle_components():
    generator = Mock()
    factory = lifecycle.warmed_generator(Mock(return_value=generator))
    assert factory("model") is generator
    generator.warm_up.assert_called_once_with()
    minimal = object()
    assert lifecycle.warmed_generator(lambda: minimal)() is minimal


@pytest.mark.parametrize("close_fails", [False, True])
def test_generator_factory_closes_failed_initialization_and_preserves_original_error(close_fails):
    generator = Mock()
    generator.warm_up.side_effect = ValueError("missing credential")
    if close_fails:
        generator.close.side_effect = RuntimeError("close failed")
    with pytest.raises(ValueError, match="missing credential"):
        lifecycle.warmed_generator(lambda: generator)()
    generator.close.assert_called_once_with()


def test_generator_lifecycle_supports_direct_calls_pipeline_calls_and_close():
    generator = Mock()
    generator.run.return_value = {
        "replies": [
            ChatMessage(
                _role=ChatRole.ASSISTANT,
                _content=[
                    TextContent(text="one"),
                    TextContent(text="two"),
                ],
            )
        ]
    }
    wrapper = ChatGeneratorCompatibilityWrapper(generator)
    assert wrapper.run(prompt="query", system_prompt="system") == {"replies": ["one", "two"]}
    pipeline = Pipeline()
    pipeline.add_component("llm", wrapper)
    assert pipeline.run({"llm": {"prompt": "again"}}) == {"llm": {"replies": ["one", "two"]}}
    generator.warm_up.assert_called_once_with()
    pipeline.close()
    wrapper.close()
    lifecycle.close_haystack_resources()
    generator.close.assert_called_once_with()
    with pytest.raises(RuntimeError, match="Generator is closed"):
        wrapper.run(prompt="after shutdown")


def test_generator_lifecycle_handles_missing_methods_empty_replies_and_failed_warmup():
    class MinimalGenerator:
        def run(self, **kwargs):
            return {"replies": []}

    wrapper = ChatGeneratorCompatibilityWrapper(MinimalGenerator())
    assert wrapper.run(prompt="query") == {"replies": []}
    wrapper.close()

    generator = Mock()
    generator.warm_up.side_effect = [RuntimeError("initialization failed"), None]
    generator.run.return_value = {"replies": []}
    wrapper = ChatGeneratorCompatibilityWrapper(generator)
    with pytest.raises(RuntimeError, match="initialization failed"):
        wrapper.run(prompt="query")
    generator.run.assert_not_called()
    assert wrapper.run(prompt="retry") == {"replies": []}
    assert generator.warm_up.call_count == 2


def test_partial_initialization_is_closed_during_process_cleanup():
    generator = Mock()
    generator.warm_up.side_effect = RuntimeError("initialization failed")
    wrapper = ChatGeneratorCompatibilityWrapper(generator)
    with pytest.raises(RuntimeError, match="initialization failed"):
        wrapper.warm_up()
    lifecycle.close_haystack_resources()
    generator.close.assert_called_once_with()
