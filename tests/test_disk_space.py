"""Disk thresholds, recovery, configuration, and cached status."""

import argparse
import sys
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from shyhurricane import disk_space
from shyhurricane.disk_space import DISK_DEFAULTS, DiskSpaceGuard, add_disk_arguments, disk_status
from shyhurricane.server_config import ServerConfig

GIB = 1024**3
ORIGINAL_MACOS_CAPACITY = disk_space._macos_available_capacity


@pytest.fixture(autouse=True)
def ordinary_capacity(monkeypatch):
    monkeypatch.setattr(disk_space, "_macos_available_capacity", lambda path: None)


def usage(monkeypatch, free, total=100 * GIB):
    monkeypatch.setattr(disk_space.shutil, "disk_usage", lambda path: SimpleNamespace(total=total, free=free))


@pytest.mark.parametrize("free,total,healthy", [
    (3 * GIB, 100 * GIB, True),  # Exact percentage boundary.
    (2 * GIB, 50 * GIB, True),  # Exact absolute boundary.
    (2 * GIB - 1, 50 * GIB, False),  # Bytes only.
    (3 * GIB - 1, 100 * GIB, False),  # Percentage only.
    (GIB, 100 * GIB, False),  # Both.
    (10 * GIB, 100 * GIB, True),
])
def test_thresholds_and_snapshot_copy(monkeypatch, free, total, healthy):
    usage(monkeypatch, free, total)
    guard = DiskSpaceGuard("/data", ServerConfig())
    assert guard.snapshot()["state"] == "checking"
    assert guard.check() is healthy
    snapshot = guard.snapshot()
    assert snapshot["path"] == "/data"
    assert snapshot["free_bytes"] == free
    assert snapshot["free_percent"] == free * 100 / total
    assert snapshot["checked_at"] is not None
    snapshot["state"] = "changed"
    assert guard.snapshot()["state"] == ("healthy" if healthy else "paused")


@pytest.mark.parametrize("free,total", [(4 * GIB - 1, 100 * GIB), (int(2.5 * GIB) - 1, 50 * GIB)])
def test_recovery_requires_both_margins(monkeypatch, free, total):
    guard = DiskSpaceGuard("/data", ServerConfig())
    usage(monkeypatch, GIB, total)
    assert not guard.check()
    usage(monkeypatch, free, total)
    assert not guard.check()
    usage(monkeypatch, max(4 * total // 100, int(2.5 * GIB)), total)
    assert guard.check()
    # Once recovered, normal thresholds apply again.
    usage(monkeypatch, max(3 * total // 100, 2 * GIB), total)
    assert guard.check()


@pytest.mark.parametrize("zero_total", [False, True])
def test_measurement_errors_pause_clear_capacity_and_recover(monkeypatch, zero_total, caplog):
    guard = DiskSpaceGuard("/data", ServerConfig())
    usage(monkeypatch, 10 * GIB)
    assert guard.check()
    if zero_total:
        usage(monkeypatch, 0, 0)
    else:
        def failed(path):
            raise OSError("missing mount")
        monkeypatch.setattr(disk_space.shutil, "disk_usage", failed)
    assert not guard.check()
    snapshot = guard.snapshot()
    assert snapshot["error"]
    assert snapshot["free_bytes"] is snapshot["free_percent"] is snapshot["total_bytes"] is None
    count = len(caplog.records)
    assert not guard.check()
    assert len(caplog.records) == count
    usage(monkeypatch, 3 * GIB)
    assert not guard.check()
    usage(monkeypatch, 4 * GIB)
    assert guard.check()
    assert guard.snapshot()["error"] is None


@pytest.mark.parametrize("minimums,free,total,healthy", [
    ({"disk_min_free_percent": 0}, 2 * GIB, 1000 * GIB, True),
    ({"disk_min_free_bytes": 0}, GIB, 10 * GIB, True),
    ({"disk_min_free_percent": 0}, GIB, 10 * GIB, False),
    ({"disk_min_free_bytes": 0}, GIB, 100 * GIB, False),
])
def test_individually_disabled_limits(monkeypatch, minimums, free, total, healthy):
    usage(monkeypatch, free, total)
    guard = DiskSpaceGuard("/data", ServerConfig(**minimums))
    assert guard.check() is healthy
    usage(monkeypatch, 10 * GIB, total)
    assert guard.check()


def test_disabled_guard_never_reads_filesystem(monkeypatch):
    monkeypatch.setattr(disk_space.shutil, "disk_usage", lambda path: pytest.fail("disabled probe"))
    guard = DiskSpaceGuard("/data", ServerConfig(disk_min_free_percent=0, disk_min_free_bytes=0))
    assert guard.check()
    assert guard.snapshot()["state"] == "disabled"
    assert disk_status(SimpleNamespace()) is None
    assert disk_status(SimpleNamespace(health_monitor=None)) is None
    assert disk_status(SimpleNamespace(health_monitor=SimpleNamespace(disk_guard=guard))) == guard.snapshot()


@pytest.mark.parametrize("name,value", [
    ("disk_min_free_percent", -1), ("disk_min_free_percent", float("nan")),
    ("disk_resume_margin_percent", float("inf")), ("disk_resume_margin_percent", -1),
    ("disk_min_free_percent", 100), ("disk_min_free_bytes", -1),
    ("disk_min_free_bytes", 1.5), ("disk_min_free_bytes", True),
    ("disk_resume_margin_bytes", -1), ("disk_resume_margin_bytes", 1.5),
])
def test_invalid_config(name, value):
    with pytest.raises(ValueError):
        ServerConfig(**{name: value})


def test_cli_environment_precedence_and_validation(monkeypatch):
    for name in DISK_DEFAULTS:
        monkeypatch.delenv(name.upper(), raising=False)
    parser = argparse.ArgumentParser()
    add_disk_arguments(parser)
    assert vars(parser.parse_args([])) == DISK_DEFAULTS
    monkeypatch.setenv("DISK_MIN_FREE_BYTES", "4096")
    monkeypatch.setenv("DISK_MIN_FREE_PERCENT", "2.5")
    parser = argparse.ArgumentParser()
    add_disk_arguments(parser)
    assert parser.parse_args([]).disk_min_free_bytes == 4096
    assert parser.parse_args([]).disk_min_free_percent == 2.5
    config = ServerConfig(**vars(parser.parse_args(["--disk-min-free-bytes", "8192"])))
    assert config.disk_min_free_bytes == 8192
    with pytest.raises(SystemExit):
        parser.parse_args(["--disk-min-free-bytes", "1.5"])


@pytest.mark.parametrize("available", [0, 8 * GIB, None, -1, 101 * GIB, 1.5, True, "123"])
def test_macos_capacity_and_fallback(monkeypatch, available):
    monkeypatch.setattr(disk_space, "sys", SimpleNamespace(platform="darwin"))
    usage(monkeypatch, GIB)
    paths = []

    def native(path):
        paths.append(path)
        return available

    monkeypatch.setattr(disk_space, "_macos_available_capacity", native)
    valid = type(available) is int and 0 <= available <= 100 * GIB
    assert disk_space._disk_capacity("/data/other-volume") == (100 * GIB, available if valid else GIB)
    assert paths == ["/data/other-volume"]


@pytest.mark.parametrize("error", [ImportError("no Foundation"), RuntimeError("bridge failed")])
def test_macos_query_exception_falls_back(monkeypatch, error):
    monkeypatch.setattr(disk_space, "sys", SimpleNamespace(platform="darwin"))
    usage(monkeypatch, 10 * GIB)

    def failed(path):
        raise error

    monkeypatch.setattr(disk_space, "_macos_available_capacity", failed)
    assert disk_space._disk_capacity("/data") == (100 * GIB, 10 * GIB)


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_other_platforms_never_query_foundation(monkeypatch, platform):
    monkeypatch.setattr(disk_space, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(disk_space, "_macos_available_capacity", lambda path: pytest.fail("native query"))
    usage(monkeypatch, 10 * GIB)
    assert disk_space._disk_capacity("/data") == (100 * GIB, 10 * GIB)


@pytest.mark.parametrize("values,error,expected", [
    ({"capacity": 8 * GIB}, None, 8 * GIB), ({}, None, None),
    (None, None, None), ({"capacity": 8 * GIB}, "unavailable", None),
])
def test_foundation_query_uses_fresh_urls_and_autorelease_pool(monkeypatch, values, error, expected):
    events = []

    @contextmanager
    def pool():
        events.append("enter")
        try:
            yield
        finally:
            events.append("exit")

    class URL:
        @classmethod
        def fileURLWithPath_(cls, path):
            events.append(path)
            return cls()

        def resourceValuesForKeys_error_(self, keys, output):
            assert keys == ["capacity"]
            assert output is None
            return values, error

    monkeypatch.setitem(sys.modules, "Foundation", SimpleNamespace(
        NSURL=URL, NSURLVolumeAvailableCapacityForImportantUsageKey="capacity",
    ))
    monkeypatch.setitem(sys.modules, "objc", SimpleNamespace(autorelease_pool=pool))
    # Bypass the portable default fixture to exercise the actual bridge adapter.
    native = ORIGINAL_MACOS_CAPACITY
    assert native("/data/other-volume") == expected
    assert native("/data/other-volume") == expected
    assert events == ["enter", "/data/other-volume", "exit"] * 2


def test_macos_capacity_recovers_indexing_and_keeps_cached_display(monkeypatch):
    from shyhurricane.health import HealthMonitor
    from shyhurricane.monitor import format_disk_status

    monkeypatch.setattr(disk_space, "sys", SimpleNamespace(platform="darwin"))
    usage(monkeypatch, GIB)
    capacities = iter([GIB, 3 * GIB, 4 * GIB, 8 * GIB])
    monkeypatch.setattr(disk_space, "_macos_available_capacity", lambda path: next(capacities))
    dependencies = [True]
    guard = DiskSpaceGuard("/data", ServerConfig())
    monitor = HealthMonitor(lambda: dependencies[0], lambda: True, disk_guard=guard)
    assert not monitor.check()
    assert not monitor.check()
    assert monitor.check()
    assert monitor.ready.is_set()
    snapshot = disk_status(SimpleNamespace(health_monitor=monitor))
    assert snapshot["free_bytes"] == 4 * GIB
    assert snapshot["free_percent"] == 4
    assert "4.00 GiB (4.00%) free" in format_disk_status(snapshot)
    dependencies[0] = False
    assert not monitor.check()
    assert guard.snapshot()["state"] == "healthy"


def test_macos_ordinary_measurement_failure_pauses(monkeypatch):
    monkeypatch.setattr(disk_space, "sys", SimpleNamespace(platform="darwin"))

    def failed(path):
        raise OSError("missing volume")

    monkeypatch.setattr(disk_space.shutil, "disk_usage", failed)
    guard = DiskSpaceGuard("/data", ServerConfig())
    assert not guard.check()
    assert guard.snapshot()["free_bytes"] is None


def test_cocoa_dependency_is_macos_only():
    import tomllib
    from pathlib import Path

    from packaging.requirements import Requirement

    project = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())
    dependency = next(Requirement(item) for item in project["project"]["dependencies"]
                      if item.startswith("pyobjc-framework-Cocoa"))
    assert dependency.marker.evaluate({"sys_platform": "darwin"})
    assert not dependency.marker.evaluate({"sys_platform": "linux"})
    assert not dependency.marker.evaluate({"sys_platform": "win32"})
