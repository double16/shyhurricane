"""Manage process-owned Haystack resources and synchronous generator lifecycles."""

import atexit
import logging
import os
from functools import wraps

logger = logging.getLogger(__name__)

# Keep resources alive until the process that created them has drained its work.
# PID keys prevent a forked child from closing its parent's resources.
_resources: dict[tuple[int, int], object] = {}


def register_resource(resource):
    """Track closable resources once in the process that creates them."""
    if callable(getattr(resource, "close", None)):
        _resources[(os.getpid(), id(resource))] = resource
    return resource


def managed_resource(factory):
    """Register resources returned by a provider factory without changing its API."""

    @wraps(factory)
    def create(*args, **kwargs):
        return register_resource(factory(*args, **kwargs))

    return create


def warmed_generator(factory):
    """Initialize providers at creation time and release failed initialization resources."""

    @wraps(factory)
    def create(*args, **kwargs):
        generator = factory(*args, **kwargs)
        warm_up = getattr(generator, "warm_up", None)
        if callable(warm_up):
            try:
                warm_up()
            except Exception:
                try:
                    generator.close()
                except Exception:
                    logger.exception("Failed to close partially initialized generator")
                raise
        return generator

    return create


def close_haystack_resources() -> None:
    """Release this process's resources after work drains, including partial startup."""
    pid = os.getpid()
    for key, resource in list(_resources.items()):
        if key[0] != pid:
            continue
        _resources.pop(key)
        try:
            resource.close()
        except Exception:
            logger.exception("Failed to close Haystack resource %s", type(resource).__name__)


class GeneratorLifecycle:
    """Forward lifecycle calls for a synchronous chat-generator adapter."""

    def _initialize_lifecycle(self, chat_generator) -> None:
        self.chat_generator = chat_generator
        self._warmed_up = False
        self._closed = False
        register_resource(self)

    def warm_up(self) -> None:
        if self._closed:
            raise RuntimeError("Generator is closed")
        if not self._warmed_up:
            warm_up = getattr(self.chat_generator, "warm_up", None)
            if callable(warm_up):
                warm_up()
            self._warmed_up = True

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        _resources.pop((os.getpid(), id(self)), None)
        close = getattr(self.chat_generator, "close", None)
        if callable(close):
            close()


atexit.register(close_haystack_resources)
