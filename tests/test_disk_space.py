"""Disk thresholds, recovery, configuration, and cached status."""

import argparse
from types import SimpleNamespace

import pytest

from shyhurricane import disk_space
from shyhurricane.disk_space import DISK_DEFAULTS, DiskSpaceGuard, add_disk_arguments, disk_status
from shyhurricane.server_config import ServerConfig

GIB = 1024**3


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
