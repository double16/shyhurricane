"""Portable references to files retained beneath graph_state."""

from pathlib import Path


def resolve_artifact_path(root: Path, reference: str | Path) -> Path:
    """Prefer existing absolute references; rebase missing ones by filename."""
    path = Path(reference)
    if path.is_absolute():
        try:
            path.stat()
        except FileNotFoundError:
            path = Path(path.name)
        else:
            return path
    candidate = root / path
    if not candidate.resolve().is_relative_to(root.resolve()):
        raise ValueError("Artifact escapes graph_state")
    return candidate


def artifact_reference(root: Path, path: str | Path) -> str:
    """Serialize local files relatively while preserving external legacy references."""
    candidate = resolve_artifact_path(root, path)
    resolved = candidate.resolve()
    if resolved.is_relative_to(root.resolve()):
        return resolved.relative_to(root.resolve()).as_posix()
    return str(candidate)
