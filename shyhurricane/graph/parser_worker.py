"""Killable parser process; captured code is never executed."""

import contextlib
import json
import logging
import os
import signal
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path
from uuid import uuid4

import psutil

logger = logging.getLogger(__name__)

MAX_SECONDS = 240
MAX_RSS = 3 * 1024**3
MAX_OUTPUT_BYTES = 64 * 1024 * 1024


def parse(event, artifacts, *, document_contexts=None, open_world=False, **extract_options):
    from shyhurricane.graph.model import restore_projection

    name = "shyhurricane-parse-" + uuid4().hex
    marker = None
    if artifacts.reference_epoch == 0:
        marker = artifacts.write(
            name + "-snapshot",
            {
                "epoch": 0,
                "watermark": artifacts.connection.execute("SELECT coalesce(max(rowid),0) FROM captures").fetchone()[0],
                "policies": [],
            },
        )
    output = artifacts.root / f"{name}.json"
    request = {
        "event": event,
        "root": str(artifacts.root),
        "epoch": artifacts.reference_epoch,
        "document_contexts": document_contexts,
        "open_world": open_world,
        "output": str(output),
        "snapshot_path": marker.name if marker else None,
        "extract_options": extract_options,
    }
    environment = {**os.environ, "_SHYHURRICANE_PARSE_CONTAINER": name}
    started = time.monotonic()
    logger.debug("Graph parser started capture=%s epoch=%s", event["id"], artifacts.reference_epoch)
    with tempfile.TemporaryFile(mode="w+") as source:
        json.dump(request, source)
        source.seek(0)
        try:
            process = subprocess.Popen(
                [sys.executable, "-m", "shyhurricane.graph.parser_worker"],
                stdin=source,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=environment,
                start_new_session=True,
            )
        except OSError:
            if marker:
                marker.unlink(missing_ok=True)
            logger.warning("Graph parser launch failed capture=%s epoch=%s", event["id"], artifacts.reference_epoch)
            raise
        try:
            while process.poll() is None:
                try:
                    rss = psutil.Process(process.pid).memory_info().rss
                except psutil.NoSuchProcess:
                    continue
                if time.monotonic() - started > MAX_SECONDS or rss > MAX_RSS:
                    raise TimeoutError("Graph parser time or memory budget reached; retained source needs expansion")
                time.sleep(0.1)
            if process.returncode != 0 or not output.exists():
                raise ValueError("Graph parser failed; retained source remains available")
            if output.stat().st_size > MAX_OUTPUT_BYTES:
                raise TimeoutError("Graph parser output budget reached; expand a smaller analysis unit")
            result = json.loads(output.read_text())
            if "error" in result:
                detail = result.get("diagnostic", {})
                logger.warning(
                    "Graph parser failed capture=%s epoch=%s stage=%s traceback=%s",
                    event["id"], artifacts.reference_epoch, detail.get("stage"), detail.get("traceback"),
                )
                raise ValueError(result["error"])
            return restore_projection(result)
        except Exception as error:
            logger.warning(
                "Graph parser stopped capture=%s epoch=%s elapsed=%.3f exit=%s reason=%s",
                event["id"], artifacts.reference_epoch, time.monotonic() - started,
                process.returncode, type(error).__name__,
            )
            raise
        finally:
            logger.debug("Graph parser finished capture=%s epoch=%s elapsed=%.3f exit=%s",
                         event["id"], artifacts.reference_epoch, time.monotonic() - started, process.returncode)
            if process.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                subprocess.run(
                    ["docker", "rm", "-f", name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=False,
                )
            output.unlink(missing_ok=True)
            output.with_suffix(".tmp").unlink(missing_ok=True)
            if marker:
                marker.unlink(missing_ok=True)


def main():
    logging.disable(logging.CRITICAL)
    request = json.load(sys.stdin)
    artifacts = None
    stage = "initialization"
    try:
        from shyhurricane.graph.epoch_catalog import SnapshotArtifacts
        from shyhurricane.graph.extract import extract
        from shyhurricane.graph.model import identity, projection_snapshot

        root = Path(request["root"])
        marker = root / (request.get("snapshot_path") or f"{identity(f'epoch-{request["epoch"]}')}.json")
        artifacts = SnapshotArtifacts(root, marker)
        artifacts.map_owner = request["event"]["id"]
        stage = "extraction"
        result = projection_snapshot(
            extract(
                request["event"], artifacts,
                document_contexts=request["document_contexts"],
                open_world=request["open_world"],
                **request.get("extract_options", {}),
            )
        )
    except Exception as error:
        # Frame locations retain the call chain without captured values or exception messages.
        frames = traceback.extract_tb(error.__traceback__)[-32:]
        result = {
            "error": f"{type(error).__name__}: graph parser {stage} failed",
            "diagnostic": {
                "stage": stage,
                "type": type(error).__name__,
                "traceback": [f"{Path(frame.filename).name}:{frame.lineno}:{frame.name}" for frame in frames],
            },
        }
    finally:
        if artifacts is not None:
            artifacts.close()
    output = Path(request["output"])
    temporary = output.with_suffix(".tmp")
    with temporary.open("w") as stream:
        os.chmod(temporary, 0o600)
        json.dump(result, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, output)


if __name__ == "__main__":
    main()
