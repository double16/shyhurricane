"""Disk-space readiness and immutable-by-copy status for indexing."""

import logging
import math
import os
import shutil
import threading
import time

logger = logging.getLogger(__name__)

DISK_DEFAULTS = {
    "disk_min_free_percent": 3.0,
    "disk_min_free_bytes": 2 * 1024**3,
    "disk_resume_margin_percent": 1.0,
    "disk_resume_margin_bytes": 512 * 1024**2,
}


def validate_disk_config(config):
    for name in DISK_DEFAULTS:
        value = getattr(config, name)
        if not math.isfinite(value) or value < 0:
            raise ValueError(f"{name} must be finite and nonnegative")
        if name.endswith("bytes") and (isinstance(value, bool) or not isinstance(value, int)):
            raise ValueError(f"{name} must be an integer")
    if config.disk_min_free_percent + config.disk_resume_margin_percent > 100:
        raise ValueError("Disk free percentage plus resume margin must not exceed 100")


def add_disk_arguments(parser):
    for name, default in DISK_DEFAULTS.items():
        parser.add_argument(
            f"--{name.replace('_', '-')}", type=int if name.endswith("bytes") else float,
            default=os.environ.get(name.upper(), str(default)),
            help=f"Indexing disk guard: {name.replace('_', ' ')} (default: {default})",
        )


class DiskSpaceGuard:
    """Latch disk pauses until both enabled thresholds meet their recovery margins."""

    def __init__(self, path, config):
        validate_disk_config(config)
        self.path = str(path)
        self._limits = {name.removeprefix("disk_"): getattr(config, name) for name in DISK_DEFAULTS}
        self._enabled = bool(config.disk_min_free_percent or config.disk_min_free_bytes)
        self._paused = False
        self._lock = threading.Lock()
        self._snapshot = {
            "path": self.path, **self._limits, "total_bytes": None, "free_bytes": None,
            "free_percent": None, "checked_at": None,
            "state": "checking" if self._enabled else "disabled", "error": None,
        }

    def snapshot(self):
        with self._lock:
            return dict(self._snapshot)

    def check(self):
        if not self._enabled:
            return True
        snapshot = self.snapshot()
        snapshot.update(checked_at=time.time(), error=None)
        try:
            usage = shutil.disk_usage(self.path)
            if usage.total <= 0:
                raise OSError("Filesystem reports zero total capacity")
            percent = usage.free * 100 / usage.total
            percent_limit = self._limits["min_free_percent"]
            byte_limit = self._limits["min_free_bytes"]
            margin = self._paused
            sufficient = (
                (not percent_limit or percent >= percent_limit + margin * self._limits["resume_margin_percent"])
                and (not byte_limit or usage.free >= byte_limit + margin * self._limits["resume_margin_bytes"])
            )
            snapshot.update(total_bytes=usage.total, free_bytes=usage.free, free_percent=percent)
            self._paused = not sufficient
        except OSError as error:
            self._paused = True
            snapshot.update(total_bytes=None, free_bytes=None, free_percent=None, error=str(error))
        snapshot["state"] = "paused" if self._paused else "healthy"
        previous = self.snapshot()
        with self._lock:
            self._snapshot = snapshot
        if (previous["state"], previous["error"] is not None) != (snapshot["state"], snapshot["error"] is not None):
            logger.log(logging.WARNING if self._paused else logging.INFO,
                       "Indexing disk guard: %s; path=%s free=%s bytes (%s%%); error=%s",
                       snapshot["state"], self.path, snapshot["free_bytes"], snapshot["free_percent"], snapshot["error"])
        return not self._paused


def disk_status(server_context):
    """Return the same cached measurement to HTTP, retrieval, and terminal consumers."""
    monitor = getattr(server_context, "health_monitor", None)
    guard = getattr(monitor, "disk_guard", None)
    return guard.snapshot() if guard is not None else None
