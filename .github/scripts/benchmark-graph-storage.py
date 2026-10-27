#!/usr/bin/env python3
"""Compare isolated JSON files, packed codecs, and production graph artifact storage."""

import argparse
import json
import os
import sqlite3
import statistics
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

import lz4.frame
import zstandard

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from shyhurricane.graph.blob_store import BlobStore, initialize


def allocated(root):
    files = [path for path in root.rglob("*") if path.is_file()]
    return sum(path.stat().st_blocks * 512 for path in files), len(files)


def benchmark(corpus, output, *, max_files=256, max_bytes=64 * 1024 * 1024):
    documents, used = [], 0
    if corpus.is_file():
        with corpus.open("rb") as stream:
            while len(documents) < max_files:
                raw = stream.readline(max_bytes + 1)
                if not raw:
                    break
                if len(raw) > max_bytes - used:
                    break
                if not raw.strip():
                    continue
                json.loads(raw)
                documents.append(raw)
                used += len(raw)
    else:
        for path in sorted(corpus.glob("*.json")):
            if len(documents) >= max_files:
                break
            size = path.stat().st_size
            if size > max_bytes - used:
                continue
            raw = path.read_bytes()
            json.loads(raw)
            documents.append(raw)
            used += size
    if not documents:
        raise ValueError("Corpus must contain JSON artifacts within the sample limits")
    compressor = zstandard.ZstdCompressor(level=1)
    decompressor = zstandard.ZstdDecompressor()
    codecs = {
        "json_files": (lambda value: value, lambda value: value),
        "sqlite_raw": (lambda value: value, lambda value: value),
        "sqlite_lz4": (lz4.frame.compress, lz4.frame.decompress),
        "sqlite_zstd_level1": (compressor.compress, decompressor.decompress),
    }
    results = []
    with tempfile.TemporaryDirectory(prefix="graph-storage-benchmark-") as directory:
        for mode in [*codecs, "production"]:
            root = Path(directory) / mode
            root.mkdir()
            tracemalloc.start()
            started = time.perf_counter()
            connection = None
            if mode != "json_files":
                connection = sqlite3.connect(root / "artifacts.sqlite")
                if mode == "production":
                    initialize(connection)
                    store = BlobStore(connection)
                else:
                    connection.execute("CREATE TABLE artifacts (id INTEGER PRIMARY KEY,payload BLOB)")
                connection.execute("PRAGMA journal_mode=WAL")
            stored = 0
            references = []
            for index, raw in enumerate(documents):
                if mode == "production":
                    references.append(store.put(f"artifact-{index}", json.loads(raw)))
                else:
                    payload = codecs[mode][0](raw)
                    stored += len(payload)
                    if connection is None:
                        with (root / f"{index}.json").open("wb") as stream:
                            stream.write(payload)
                            stream.flush()
                            os.fsync(stream.fileno())
                    else:
                        connection.execute("INSERT INTO artifacts VALUES (?,?)", (index, payload))
                if connection is not None and (index + 1) % 64 == 0:
                    connection.commit()
            if connection is not None:
                connection.commit()
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            write_seconds = time.perf_counter() - started
            latencies = []
            for index, raw in enumerate(documents):
                started = time.perf_counter()
                if mode == "production":
                    value = store.read(references[index])
                else:
                    packed = (
                        (root / f"{index}.json").read_bytes()
                        if connection is None
                        else connection.execute("SELECT payload FROM artifacts WHERE id=?", (index,)).fetchone()[0]
                    )
                    value = json.loads(codecs[mode][1](packed))
                latencies.append(time.perf_counter() - started)
                assert value == json.loads(raw)
            if mode == "production":
                stored = store.statistics()["stored_payload_bytes"]
            if connection is not None:
                connection.close()
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            disk, count = allocated(root)
            results.append(
                {
                    "mode": mode,
                    "allocated_bytes": disk,
                    "files": count,
                    "payload_bytes": stored,
                    "write_seconds": write_seconds,
                    "read_median_ms": statistics.median(latencies) * 1000,
                    "read_p95_ms": sorted(latencies)[int((len(latencies) - 1) * 0.95)] * 1000,
                    "peak_python_bytes": peak,
                }
            )
    result = {
        "sample_files": len(documents),
        "sqlite_commit_batch": 64,
        "input_bytes": used,
        "results": results,
        "notes": "Warm filesystem cache; JSON files fsynced individually; SQLite commits every 64 records. "
        "Python allocations exclude native codec/SQLite memory. "
        "Packing comparison excludes manifest catalog normalization.",
    }
    output.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-files", type=int, default=256)
    parser.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024)
    args = parser.parse_args()
    if args.max_files <= 0 or args.max_bytes <= 0:
        parser.error("Sample limits must be positive")
    benchmark(args.corpus, args.output, max_files=args.max_files, max_bytes=args.max_bytes)


if __name__ == "__main__":
    main()
