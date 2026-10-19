"""Recover replayable ingestion files without initializing or changing source services."""

import argparse
import hashlib
import json
import math
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from shyhurricane.data_paths import add_data_dir_argument, qdrant_location, resolve_data_dir


def open_qdrant(**kwargs):
    # Keep optional inference-library imports out of --help and graph-only recovery.
    from qdrant_client import QdrantClient

    return QdrantClient(**kwargs)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def endpoint(root, explicit=None):
    if explicit:
        return explicit
    location = qdrant_location(root)
    if os.environ.get("QDRANT"):
        return f"http://{location}"
    name = "qdrant-shyhurricane-" + hashlib.sha256(location.encode()).hexdigest()[:12]
    result = subprocess.run(
        ["docker", "inspect", name],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    container = json.loads(result.stdout)[0]
    if not container["State"]["Running"]:
        raise ValueError("Existing Qdrant container is stopped; start it separately or use --graph-only")
    bindings = container["NetworkSettings"]["Ports"]["6333/tcp"]
    binding = next((item for item in bindings if item["HostIp"] == "127.0.0.1"), bindings[0])
    host = binding["HostIp"]
    host = "127.0.0.1" if host in {"", "0.0.0.0", "::"} else host
    host = f"[{host}]" if ":" in host else host
    return f"http://{host}:{binding['HostPort']}"


def headers(value):
    value = json.loads(value) if isinstance(value, str) else value
    if not isinstance(value, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
        raise ValueError("Invalid headers")
    return value


def katana(data):
    """Validate capture fields without loading application models or normalizers."""
    url = data["url"]
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Invalid capture URL")
    stamp = data["timestamp"]
    datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    method = data["method"]
    status = int(data["response_code"])
    if not isinstance(method, str) or not method or not 100 <= status <= 599:
        raise ValueError("Invalid HTTP metadata")
    for field in ("request_body", "response_body"):
        if data.get(field) is not None and not isinstance(data[field], str):
            raise ValueError("Invalid body")
    for field in ("technologies", "forms"):
        value = data.get(field)
        expected = str if field == "technologies" else dict
        if value is not None and (not isinstance(value, list) or not all(isinstance(v, expected) for v in value)):
            raise ValueError("Invalid optional capture list")
    rtt = data.get("response_rtt")
    if rtt is not None and (not isinstance(rtt, (float, int)) or not math.isfinite(rtt) or rtt < 0):
        raise ValueError("Invalid response RTT")
    response = {
        "status_code": status,
        "headers": headers(data.get("response_headers", {})),
        "body": data.get("response_body"),
    }
    for source, target in (("response_rtt", "rtt"), ("technologies", "technologies"), ("forms", "forms")):
        if data.get(source) is not None:
            response[target] = data[source]
    return {
        "timestamp": stamp,
        "request": {
            "endpoint": url,
            "method": method.upper(),
            "headers": headers(data.get("request_headers", {})),
            "body": data.get("request_body"),
        },
        "response": response,
    }


def group_key(record):
    response = record["response"]
    stamp = datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00"))
    return digest(
        [record["request"]["endpoint"], stamp.isoformat(), record["request"]["method"], response["status_code"]]
    )


def compatible_headers(left, right, *, unknown=False):
    def clean(values, response):
        return {k.lower(): v for k, v in values.items() if not (response and k.lower() == "content-length")}

    return all(
        (unknown and (not a or not b)) or clean(a, response) == clean(b, response)
        for a, b, response in (
            (left["request"]["headers"], right["request"]["headers"], False),
            (left["response"]["headers"], right["response"]["headers"], True),
        )
    )


class Exporter:
    def __init__(self, workspace, report):
        self.workspace = workspace
        self.report = report
        self.db = sqlite3.connect(workspace / "staging.sqlite")
        self.db.executescript(
            "CREATE TABLE inputs (grp TEXT, kind TEXT, record TEXT, hash TEXT, source_id TEXT);"
            "CREATE INDEX input_group ON inputs(grp);"
            "CREATE TABLE output (hash TEXT PRIMARY KEY, stamp TEXT, record TEXT, grp TEXT);"
            "CREATE INDEX output_group ON output(grp);"
            "CREATE TABLE findings (id TEXT PRIMARY KEY, record TEXT, provenance TEXT);"
            "CREATE TABLE issues (record TEXT);"
        )

    def issue(self, source, identifier, reason):
        self.report["skipped_records"] += 1
        # Never include exception messages: they can contain captured text or credentials.
        self.db.execute(
            "INSERT INTO issues VALUES (?)", (canonical({"source": source, "id": str(identifier), "reason": reason}),)
        )

    def add(self, kind, record, identifier, body_hash=None):
        self.db.execute(
            "INSERT INTO inputs VALUES (?,?,?,?,?)",
            (group_key(record), kind, canonical(record), body_hash, str(identifier)),
        )
        counts = self.report["source_records"]
        counts[kind] = counts.get(kind, 0) + 1

    def graph(self, root):
        graph_root = root / "graph_state"
        path = graph_root / "artifacts.sqlite"
        if not path.exists():
            self.report["warnings"].append("graph_state/artifacts.sqlite is missing")
            return
        deadline = time.monotonic() + 30

        def progress(_status, _remaining, _total):
            if time.monotonic() > deadline:
                raise TimeoutError("Graph metadata backup exceeded 30 seconds")

        with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=1)) as source:
            with closing(sqlite3.connect(self.workspace / "captures.sqlite")) as snapshot:
                source.backup(snapshot, pages=256, progress=progress, sleep=0.05)
                for identifier, stored_path in snapshot.execute("SELECT id,path FROM captures ORDER BY id"):
                    try:
                        stored = Path(stored_path)
                        # Artifacts may have been copied from a different container mount.
                        candidate = graph_root / stored.name
                        if not candidate.is_file():
                            raise ValueError("Missing artifact")
                        if not candidate.resolve().is_relative_to(graph_root.resolve()):
                            raise ValueError("Artifact escapes graph_state")
                        event = json.loads(candidate.read_text())
                        if event["id"] != identifier:
                            raise ValueError("Capture identity mismatch")
                        kind = "backfill" if event.get("backfill", False) else "graph"
                        if kind == "backfill" and event["data"].get("response_body") == "":
                            # Backfill uses an empty string for network/forms bodies it never retained.
                            event["data"]["response_body"] = None
                        self.add(kind, katana(event["data"]), identifier)
                    except (OSError, ValueError, KeyError, TypeError, AttributeError):
                        self.issue("graph", identifier, "Missing or invalid capture artifact")

    def qdrant(self, client):
        for kind in ("content", "network", "forms", "finding"):
            if not client.collection_exists(kind):
                self.report["missing_collections"].append(kind)
                continue
            offset = None
            while True:
                records, offset = client.scroll(
                    collection_name=kind, offset=offset, limit=100, with_payload=True, with_vectors=False
                )
                for point in records:
                    try:
                        payload = point.payload or {}
                        meta = payload["meta"]
                        if kind == "finding":
                            self.finding(str(point.id), payload, meta)
                            continue
                        data = {
                            "url": meta["url"],
                            "timestamp": meta["timestamp"],
                            "method": meta["http_method"],
                            "response_code": meta["status_code"],
                            "request_headers": meta.get("request_headers", {}),
                            "response_headers": meta.get("response_headers", {}),
                            "response_body": payload.get("content") if kind == "content" else None,
                            "response_rtt": meta.get("response_rtt"),
                            "technologies": json.loads(meta.get("technologies", "[]")),
                        }
                        if kind == "forms":
                            data["forms"] = json.loads(payload["content"])
                        self.add(kind, katana(data), point.id, meta.get("content_sha256"))
                    except (ValueError, KeyError, TypeError, AttributeError):
                        self.issue(kind, point.id, "Invalid Qdrant payload")
                if offset is None:
                    break

    def finding(self, identifier, payload, meta):
        host = meta.get("host") or meta.get("domain")
        netloc = meta.get("netloc")
        if host and ":" in host and not host.startswith("["):
            host = f"[{host}]"
            if netloc and not netloc.startswith("["):
                netloc = f"{host}:{meta['port']}" if meta.get("port") else host
        target = meta.get("url") or netloc or host
        markdown = payload.get("content")
        if not isinstance(target, str) or not target.strip() or not isinstance(markdown, str) or not markdown.strip():
            raise ValueError("Missing finding target or Markdown")
        parsed = urlsplit(target if "://" in target else f"//{target}")
        if (
            not parsed.hostname
            or any(c.isspace() for c in target)
            or (parsed.scheme and parsed.scheme not in {"http", "https"})
            or (not parsed.scheme and (parsed.path or parsed.query or parsed.fragment))
        ):
            raise ValueError("Invalid finding target")
        _ = parsed.port
        title = meta.get("title", "")
        if not isinstance(title, str):
            raise ValueError("Invalid finding title")
        record = {"target": target, "title": title, "markdown": markdown}
        self.db.execute(
            "INSERT INTO findings VALUES (?,?,?)",
            (
                identifier,
                canonical(record),
                canonical(
                    {"id": payload.get("id", identifier), "point_id": identifier, "timestamp": meta.get("timestamp")}
                ),
            ),
        )
        counts = self.report["source_records"]
        counts["finding"] = counts.get("finding", 0) + 1

    def emit(self, record):
        stamp = datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00"))
        stamp = stamp.replace(tzinfo=timezone.utc) if stamp.tzinfo is None else stamp
        result = self.db.execute(
            "INSERT OR IGNORE INTO output VALUES (?,?,?,?)",
            (digest(record), stamp.astimezone(timezone.utc).isoformat(), canonical(record), group_key(record)),
        )
        if not result.rowcount:
            self.report["duplicates"] += 1

    def inputs(self, group, kinds):
        placeholders = ",".join("?" for _ in kinds)
        for kind, serialized, body_hash in self.db.execute(
            f"SELECT kind,record,hash FROM inputs WHERE grp=? AND kind IN ({placeholders}) ORDER BY kind,rowid",
            (group, *kinds),
        ):
            yield kind, json.loads(serialized), body_hash

    def reconcile(self):
        for (group,) in self.db.execute("SELECT DISTINCT grp FROM inputs ORDER BY grp"):
            counts = dict(self.db.execute("SELECT kind,count(*) FROM inputs WHERE grp=? GROUP BY kind", (group,)))
            for _, record, _ in self.inputs(group, ("graph",)):
                self.emit(record)
            for _, record, body_hash in self.inputs(group, ("content",)):
                # Compare raw digests when Qdrant contains a normalized representation.
                matched = any(
                    compatible_headers(raw, record)
                    and (
                        raw["response"].get("body") == record["response"].get("body")
                        or (
                            body_hash
                            and hashlib.sha256(
                                (raw["response"].get("body") or "").encode("utf-8", errors="ignore")
                            ).hexdigest()
                            == body_hash
                        )
                    )
                    for _, raw, _ in self.inputs(group, ("graph",))
                )
                if matched:
                    self.report["duplicates"] += 1
                    continue
                if (
                    counts.get("content") == 1
                    and counts.get("forms") == 1
                    and not counts.get("graph")
                    and not counts.get("backfill")
                    and all(compatible_headers(record, network) for _, network, _ in self.inputs(group, ("network",)))
                ):
                    _, form, _ = next(self.inputs(group, ("forms",)))
                    if compatible_headers(form, record, unknown=True):
                        record["response"]["forms"] = form["response"]["forms"]
                self.emit(record)
            for kind, record, _ in self.inputs(group, ("backfill", "network", "forms")):
                if any(
                    compatible_headers(record, item, unknown=kind in {"forms", "backfill"})
                    and partial_match(record, item)
                    for (serialized,) in self.db.execute("SELECT record FROM output WHERE grp=?", (group,))
                    for item in (json.loads(serialized),)
                ):
                    self.report["duplicates"] += 1
                else:
                    self.emit(record)
            remaining = self.db.execute("SELECT count(*) FROM output WHERE grp=?", (group,)).fetchone()[0]
            if counts.get("content", 0) > 1 or (counts.get("forms", 0) and remaining > 1):
                self.report["ambiguous_groups"] += 1

    def write(self, directory):
        self.reconcile()
        for filename, query in (
            ("index.jsonl", "SELECT record FROM output ORDER BY stamp,hash"),
            ("findings.jsonl", "SELECT record FROM findings ORDER BY id"),
        ):
            with open(directory / filename, "x", encoding="utf-8", opener=private_open) as stream:
                for (record,) in self.db.execute(query):
                    stream.write(f"{record}\n")
        self.report["output_records"] = {
            "index": self.db.execute("SELECT count(*) FROM output").fetchone()[0],
            "findings": self.db.execute("SELECT count(*) FROM findings").fetchone()[0],
        }
        # Stream potentially large provenance/issue lists rather than collecting them in RAM.
        with open(directory / "export-report.json", "x", encoding="utf-8", opener=private_open) as stream:
            stream.write(canonical(self.report)[:-1])
            for name, query in (
                ("issues", "SELECT record FROM issues"),
                ("finding_provenance", "SELECT provenance FROM findings ORDER BY id"),
            ):
                stream.write(f',"{name}":[')
                separator = ""
                for (record,) in self.db.execute(query):
                    stream.write(f"{separator}{record}")
                    separator = ","
                stream.write("]")
            stream.write("}\n")


def partial_match(partial, full):
    if partial["request"].get("body") not in (None, full["request"].get("body")):
        return False
    return all(
        value is None or full["response"].get(key) == value
        for key, value in partial["response"].items()
        if key not in {"headers"}
    )


def private_open(path, flags):
    return os.open(path, flags, 0o600)


def export(root, output, *, qdrant_url=None, graph_only=False):
    root, output = Path(root).resolve(), Path(output).absolute()
    if output.exists():
        raise FileExistsError("Output directory already exists")
    report = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "data_dir": str(root),
        "source_records": {},
        "skipped_records": 0,
        "duplicates": 0,
        "ambiguous_groups": 0,
        "missing_collections": [],
        "warnings": [],
        "limitations": [
            "Recovery export, not an exact database backup",
            "Qdrant bodies may be normalized; request and binary bodies may be unavailable",
            "Finding timestamps, embeddings and graph publications change on reingestion",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".ingestion-export-", dir=output.parent) as temporary:
        workspace = Path(temporary)
        published = workspace / "result"
        published.mkdir(mode=0o700)
        exporter = Exporter(workspace, report)
        try:
            exporter.graph(root)
            if not graph_only:
                url = endpoint(root, qdrant_url)
                # Store no URL credentials/query strings in the report.
                parsed = urlsplit(url)
                report["qdrant"] = {
                    "host": parsed.hostname,
                    "port": parsed.port,
                    "consistency": "Live non-atomic scroll; pause ingestion for stable results",
                }
                with closing(open_qdrant(url=url, timeout=30)) as client:
                    exporter.qdrant(client)
            report["completed_at"] = datetime.now(timezone.utc).isoformat()
            exporter.write(published)
            # mkdir reserves the destination and refuses races with other exporters.
            output.mkdir(mode=0o700)
            try:
                os.replace(published, output)
            except BaseException:
                output.rmdir()
                raise
        finally:
            exporter.db.close()
    return 2 if report["skipped_records"] else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    add_data_dir_argument(parser)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--qdrant-url", help="Existing Qdrant HTTP(S) endpoint")
    parser.add_argument("--graph-only", action="store_true", help="Recover graph artifacts without Qdrant")
    args = parser.parse_args(argv)
    try:
        return export(
            resolve_data_dir(args.data_dir), args.output_dir, qdrant_url=args.qdrant_url, graph_only=args.graph_only
        )
    except (OSError, ValueError, sqlite3.Error, TimeoutError, subprocess.SubprocessError):
        print("Export failed; check source availability and output path. No export was published.", file=sys.stderr)
        return 1
    except Exception:
        # Qdrant transport exceptions can expose URLs or payloads; keep stderr bounded and redacted.
        print("Export failed while reading sources. No export was published.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
