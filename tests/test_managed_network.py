"""Managed database network selection."""
import json
from types import SimpleNamespace

import pytest

from shyhurricane import db


@pytest.mark.parametrize("mode", ["invalid", ""])
def test_invalid_mode(monkeypatch, mode):
    monkeypatch.setenv("MANAGED_DATABASE_NETWORK", mode)
    with pytest.raises(ValueError):
        db.managed_network()


def test_bridge_explicit(monkeypatch):
    monkeypatch.setenv("MANAGED_DATABASE_NETWORK", "bridge")
    assert db.managed_network() == "bridge"


def test_auto_bridge(monkeypatch):
    monkeypatch.delenv("MANAGED_DATABASE_NETWORK", raising=False)
    monkeypatch.setattr(db, "_run", lambda *a, **k: SimpleNamespace(
        returncode=0, stdout=json.dumps([{"Options": {}}])))
    assert db.managed_network() == "bridge"


def test_host_endpoint_and_mismatch():
    info = {"HostConfig": {"NetworkMode": "host"},
            "Config": {"Env": ["PORT=127.0.0.1:12345"]}}
    assert db.managed_endpoint(info, "6333/tcp", "PORT") == ("127.0.0.1", 12345)
    db.validate_network(info, "host")
    with pytest.raises(RuntimeError, match="preserving"):
        db.validate_network(info, "bridge")


@pytest.mark.parametrize("mode", ["host", "auto"])
def test_local_host_selection(monkeypatch, mode):
    import sys

    monkeypatch.setenv("MANAGED_DATABASE_NETWORK", mode)
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.setattr(sys, "platform", "linux")

    def run(command, **kwargs):
        if command[1] == "network":
            value = [{"Options": {"com.docker.network.bridge.name": "none"}}]
        elif command[1] == "context":
            value = [{"Endpoints": {"docker": {"Host": "unix:///var/run/docker.sock"}}}]
        else:
            value = {"OperatingSystem": "Ubuntu", "OSType": "linux"}
        return SimpleNamespace(returncode=0, stdout=json.dumps(value))
    monkeypatch.setattr(db, "_run", run)
    assert db.managed_network() == "host"


def test_auto_inspection_failure(monkeypatch):
    monkeypatch.setenv("MANAGED_DATABASE_NETWORK", "auto")
    monkeypatch.setattr(db, "_run", lambda *a, **k: SimpleNamespace(returncode=1, stderr="denied"))
    with pytest.raises(RuntimeError, match="Cannot inspect"):
        db.managed_network()


def test_cli_network_propagates(monkeypatch):
    import argparse

    from shyhurricane.data_paths import add_data_dir_argument

    monkeypatch.setenv("MANAGED_DATABASE_NETWORK", "bridge")
    parser = argparse.ArgumentParser()
    add_data_dir_argument(parser)
    assert parser.parse_args(["--managed-database-network", "host"]).managed_database_network == "host"
    assert db.os.environ["MANAGED_DATABASE_NETWORK"] == "host"


def test_qdrant_host_creation(monkeypatch, tmp_path):
    commands = []
    monkeypatch.setattr(db, "wait_host_listener", lambda *args: None)
    info = {"Id": "id", "State": {"Running": True},
            "HostConfig": {"NetworkMode": "host"},
            "Mounts": [{"Destination": "/qdrant/storage", "Source": str(tmp_path)}],
            "Config": {"Env": ["QDRANT__SERVICE__HTTP_PORT=12345",
                               "QDRANT__SERVICE__GRPC_PORT=12346"]}}
    inspections = iter([None, info])
    ports = iter([12345, 12346])
    monkeypatch.setattr(db, "managed_network", lambda: "host")
    monkeypatch.setattr(db, "_inspect_container", lambda name: next(inspections))
    monkeypatch.setattr(db, "_find_available_port", lambda host: next(ports))
    monkeypatch.setattr(db, "_run", lambda command, **kwargs: commands.append(command))
    assert db._start_qdrant_docker(storage_dir=str(tmp_path)).http_port == 12345
    command = commands[0]
    assert "--network" in command
    assert "-p" not in command
    assert "QDRANT__SERVICE__HOST=127.0.0.1" in command


def test_listener_failure(monkeypatch):
    monkeypatch.setattr(db, "_inspect_container", lambda name: {"State": {"Running": False}})
    with pytest.raises(RuntimeError, match="stopped"):
        db.wait_host_listener("example", "127.0.0.1", 12345)


def test_listener_success(monkeypatch):
    from contextlib import nullcontext

    monkeypatch.setattr(db, "_inspect_container", lambda name: {"State": {"Running": True}})
    monkeypatch.setattr(db.socket, "create_connection", lambda *a, **k: nullcontext())
    db.wait_host_listener("example", "127.0.0.1", 12345)


def test_listener_timeout(monkeypatch):
    monkeypatch.setattr(db, "_inspect_container", lambda name: {"State": {"Running": True}})

    def fail(*args, **kwargs):
        raise OSError("occupied")
    monkeypatch.setattr(db.socket, "create_connection", fail)
    with pytest.raises(RuntimeError, match="timed out"):
        db.wait_host_listener("example", "127.0.0.1", 12345, timeout=0)


@pytest.mark.parametrize("endpoint,operating_system,platform", [
    ("ssh://example.com", "Ubuntu", "linux"),
    ("unix:///var/run/docker.sock", "Docker Desktop", "linux"),
    ("unix:///var/run/docker.sock", "Ubuntu", "darwin"),
])
def test_unsupported_host_engine(monkeypatch, endpoint, operating_system, platform):
    import sys

    monkeypatch.setenv("MANAGED_DATABASE_NETWORK", "host")
    monkeypatch.setenv("DOCKER_HOST", endpoint)
    monkeypatch.setattr(sys, "platform", platform)
    results = iter([
        [{"Endpoints": {"docker": {"Host": endpoint}}}],
        {"OperatingSystem": operating_system, "OSType": "linux"},
    ])
    monkeypatch.setattr(db, "_run", lambda *a, **k: SimpleNamespace(stdout=json.dumps(next(results))))
    with pytest.raises(RuntimeError, match="local native Linux"):
        db.managed_network()


@pytest.mark.parametrize("error", [
    "Error: No such network: bridge",
    "Error response from daemon: network bridge not found",
])
def test_absent_bridge_selects_host(monkeypatch, error):
    import sys

    monkeypatch.setenv("MANAGED_DATABASE_NETWORK", "auto")
    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    monkeypatch.setattr(sys, "platform", "linux")
    results = iter([
        SimpleNamespace(returncode=1, stderr=error),
        SimpleNamespace(stdout=json.dumps([{"Endpoints": {"docker": {"Host": "unix:///docker.sock"}}}])),
        SimpleNamespace(stdout=json.dumps({"OperatingSystem": "Ubuntu", "OSType": "linux"})),
    ])
    monkeypatch.setattr(db, "_run", lambda *a, **k: next(results))
    assert db.managed_network() == "host"


@pytest.mark.parametrize("running", [True, False])
def test_qdrant_host_reuses_persisted_ports(monkeypatch, tmp_path, running):
    info = {
        "Id": "id",
        "HostConfig": {"NetworkMode": "host"},
        "State": {"Running": running},
        "Mounts": [{"Destination": "/qdrant/storage", "Source": str(tmp_path)}],
        "Config": {"Env": ["QDRANT__SERVICE__HTTP_PORT=12345", "QDRANT__SERVICE__GRPC_PORT=12346"]},
    }
    commands = []
    monkeypatch.setattr(db, "managed_network", lambda: "host")
    monkeypatch.setattr(db, "_inspect_container", lambda name: info)
    monkeypatch.setattr(db, "_run", lambda command, **kwargs: commands.append(command))
    monkeypatch.setattr(db, "wait_host_listener", lambda *args: None)
    result = db._start_qdrant_docker(name="example", storage_dir=str(tmp_path))
    assert (result.http_port, result.grpc_port) == (12345, 12346)
    assert commands == ([] if running else [["docker", "start", "example"]])


def test_explicit_context_wins_over_docker_host(monkeypatch):
    import sys

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("MANAGED_DATABASE_NETWORK", "host")
    monkeypatch.setenv("DOCKER_CONTEXT", "remote")
    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    results = iter([
        [{"Endpoints": {"docker": {"Host": "ssh://example.com"}}}],
        {"OperatingSystem": "Ubuntu", "OSType": "linux"},
    ])
    monkeypatch.setattr(db, "_run", lambda *a, **k: SimpleNamespace(stdout=json.dumps(next(results))))
    with pytest.raises(RuntimeError, match="local native Linux"):
        db.managed_network()
