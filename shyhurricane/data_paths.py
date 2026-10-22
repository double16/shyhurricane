"""Resolve application storage independently of database endpoints and working directories."""

import argparse
import os
import sys
from pathlib import Path


def default_data_dir() -> Path:
    """Prefer the container data directory, then the platform's user state directory."""
    if Path("/data").is_dir():
        return Path("/data")
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "shyhurricane"
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "shyhurricane"
    state_home = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    if not state_home.is_absolute():
        state_home = Path.home() / ".local" / "state"
    return state_home / "shyhurricane"


def resolve_data_dir(value: str | os.PathLike | None = None) -> Path:
    """Resolve relative selections beneath the default, without creating directories."""
    if value is None:
        value = os.environ.get("DATA_DIR")
    if value is None:
        return default_data_dir().resolve()
    if not str(value).strip():
        raise ValueError("DATA_DIR/--data-dir must not be empty")
    path = Path(value).expanduser()
    if path.is_absolute():
        return path.resolve()
    root = default_data_dir().resolve()
    path = (root / path).resolve()
    if not path.is_relative_to(root):
        raise ValueError("Relative --data-dir must stay within the default data directory")
    return path


def add_data_dir_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--data-dir", default=None,
        help="Application data directory (or DATA_DIR); relative paths are beneath the detected default",
    )


def configure_data_dir(value: str | os.PathLike | None = None) -> Path:
    """Create the root and publish its absolute path to spawned worker processes."""
    root = resolve_data_dir(value)
    root.mkdir(parents=True, exist_ok=True)
    os.environ["DATA_DIR"] = str(root)
    return root


def state_path(name: str) -> Path:
    """Return a location without creating it, including for read-only maintenance commands."""
    return resolve_data_dir() / name


def qdrant_location(data_dir: str | os.PathLike | None = None) -> str:
    endpoint = os.environ.get("QDRANT")
    if endpoint is not None:
        host, separator, port = endpoint.rpartition(":")
        if not separator or not host or any(char.isspace() or char in "/\\" for char in host) or not port.isdecimal():
            raise ValueError("QDRANT must be a host:port endpoint; use --data-dir for local storage")
        if not 0 < int(port) <= 65535:
            raise ValueError("QDRANT port must be between 1 and 65535")
        return endpoint
    return str(resolve_data_dir(data_dir) / "qdrant")


def neo4j_location(data_dir: str | os.PathLike | None = None) -> str:
    endpoint = os.environ.get("NEO4J")
    if endpoint is not None:
        if not endpoint.startswith(("bolt://", "bolt+s://", "bolt+ssc://", "neo4j://", "neo4j+s://", "neo4j+ssc://")):
            raise ValueError("NEO4J must be a Bolt/Neo4j URI; use --data-dir for local storage")
        return endpoint
    return str(resolve_data_dir(data_dir) / "graph")
