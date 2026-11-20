"""Persist discovery before choosing a bounded Neo4j projection."""

from shyhurricane.graph.archive_checkpoint import ArchiveCursor
from shyhurricane.graph.model import identity, web_url
from shyhurricane.graph.parser_diagnostics import measured


def markup_emitter(artifacts, event, url):
    unit = artifacts.manifest.unit(event["id"], url)
    base = url
    seen = 0
    chunks = []

    def emit(record):
        nonlocal base, seen
        attrs, tag = record["attributes"], record["tag"]
        if "source" in record:
            filename = f"{url}#deferred-script={record['locator']}"
            path = artifacts.write(
                identity("deferred-source", event["id"], filename),
                {
                    "source": record["source"],
                    "filename": record["locator"],
                    "contexts": [{"id": event["id"], "url": url, "base": base}],
                },
            )
            artifacts.manifest.unit(
                event["id"],
                filename,
                discovery="pending",
                flow="pending",
                artifact=path,
                error="Inline script analysis deferred by markup budget",
            )
            return
        if seen % 1000 == 0:
            path = artifacts.write(
                identity("markup-shard", event["id"], seen),
                {
                    "markup_capture": event["id"],
                    "markup_offset": seen,
                    "markup_limit": 1000,
                },
            )
            name = f"{url}#markup-shard={seen // 1000}"
            artifacts.manifest.unit(event["id"], name, artifact=path)
            chunks.append((name, path))
        seen += 1
        if tag == "base" and attrs.get("href"):
            base = web_url(attrs["href"], url) or base
        location = f"{record['line']}:{record['column']}"
        kind = "field" if tag in {"input", "select", "textarea"} else "form" if tag == "form" else "element"
        artifacts.manifest.fact(
            unit,
            event["id"],
            kind,
            {
                "id": identity("element", identity(event["id"], record["locator"])),
                "url": url,
                "location": location,
                "name": attrs.get("name") or attrs.get("id") or tag,
                "role": "source" if kind == "field" else "",
                **record,
            },
        )
        references = []
        for attr, value in attrs.items():
            if attr in {"src", "href", "xlink:href", "action", "formaction"} and isinstance(value, str):
                target = web_url(value, base)
                if target:
                    method = attrs.get("method", "GET").upper() if attr in {"action", "formaction"} else "GET"
                    artifacts.manifest.fact(
                        unit,
                        event["id"],
                        "resource",
                        {
                            "id": identity("resource", f"{method} {target}"),
                            "url": target,
                            "method": method,
                            "capture_status": "referenced",
                            "location": location,
                        },
                    )
                    references.append(target)
                    if tag in {"script", "link", "image", "use"} or attr == "src":
                        artifacts.manifest.dependency(event["id"], target, "LOADS")
        artifacts.references(event["id"], references)

    def finish():
        for name, path in chunks:
            artifacts.manifest.unit(event["id"], name, discovery="complete", flow="complete", artifact=path)

    emit.finish = finish
    return emit


@measured("discovery-archive")
def archive_ir(artifacts, event, url, filename, result, *, contexts=()):
    return _archive_ir(artifacts, event, url, filename, result, contexts=contexts)


def _archive_ir(artifacts, event, url, filename, result, *, contexts=()):
    """Archive the complete IR even when its materialized summary omits facts."""
    raw = result.get("archive", result)
    cursor = ArchiveCursor(artifacts, event, url, filename, raw, contexts)
    if cursor.complete:
        return artifacts.connection.execute(
            "SELECT id FROM graph_manifest_units WHERE capture_id=? AND source_path=?",
            (event["id"], filename),
        ).fetchone()[0]
    path = cursor.ir
    gaps = raw.get("gaps", [])
    parse_failed = any("Parse failed" in gap for gap in gaps)
    partial = any("budget" in gap.lower() for gap in gaps)
    unit = artifacts.manifest.unit(
        event["id"],
        filename,
        discovery="pending",
        flow="pending",
        artifact=path,
        error="; ".join(gaps),
    )
    artifacts.manifest.contexts(unit, contexts)

    def write_nodes(selected):
        artifacts.manifest.facts(unit, event["id"], [
            (node.get("kind", "symbol"), {
                **node,
                "url": url,
                "source_path": filename,
                "source_sha256": raw.get("source_sha256"),
                "id": identity(node.get("kind", "symbol"), identity(event["id"], filename, node["id"])),
            })
            for node in selected
        ])


    cursor.run(0, raw.get("nodes", []), write_nodes)

    def write_references(selected):
        for reference in selected:
            target = web_url(reference["url"], url)
            artifacts.manifest.fact(
                unit,
                event["id"],
                "reference",
                {
                    **reference,
                    "reference_url": reference["url"],
                    "url": url,
                    "target_url": target,
                    "source_path": filename,
                },
            )
            if target and reference["kind"] == "IMPORTS":
                artifacts.references(event["id"], [target])
                artifacts.manifest.dependency(event["id"], target, "IMPORTS")
            targets = (
                {target}
                if reference["url"].startswith(("http://", "https://")) or reference["kind"] == "IMPORTS"
                else {web_url(reference["url"], context["base"]) for context in contexts}
            )
            for destination in sorted(value for value in targets if value):
                method = reference.get("method", "GET")
                artifacts.manifest.fact(
                    unit,
                    event["id"],
                    "resource",
                    {
                        "id": identity("resource", f"{method} {destination}"),
                        "url": destination,
                        "method": method,
                        "capture_status": "referenced",
                    },
                )
                if reference["kind"] == "LOADS":
                    artifacts.references(event["id"], [destination])
                    artifacts.manifest.dependency(event["id"], destination, "LOADS")

    cursor.run(1, raw.get("references", []), write_references, batch_size=1)
    # Detail shards share logical node identities. Cross-shard edges retain both endpoints.
    nodes = {node["id"]: node for node in raw.get("nodes", [])}
    edges = raw.get("edges", [])

    def write_edges(offsets):
        for offset in offsets:
            shard = {
                "filename": filename,
                "ir_artifact": path,
                "edge_offset": offset,
                "edge_limit": 2000,
                "contexts": list(contexts) if len(contexts) <= 100 else [],
                "requires_context_shards": len(contexts) > 100,
            }
            shard_path = artifacts.write(identity("detail-shard", filename, shard), shard)
            source_path = f"{filename}#flow-shard={offset // 2000}"
            child = artifacts.manifest.unit(
                event["id"],
                source_path,
                discovery="complete",
                flow="partial" if partial else "complete",
                artifact=shard_path,
            )
            artifacts.manifest.parent(child, unit)
            context_shards(artifacts, event, source_path, shard_path, contexts)

    cursor.run(2, range(0, len(edges), 2000), write_edges, batch_size=1)
    covered = {edge[side] for edge in edges for side in ("source", "target")}
    isolated = sorted(set(nodes) - covered)

    def write_isolated(offsets):
        for offset in offsets:
            shard = {
                "filename": filename,
                "ir_artifact": path,
                "node_ids": isolated[offset : offset + 2000],
                "contexts": list(contexts) if len(contexts) <= 100 else [],
                "requires_context_shards": len(contexts) > 100,
            }
            shard_path = artifacts.write(identity("detail-shard", filename, shard), shard)
            source_path = f"{filename}#node-shard={offset // 2000}"
            child = artifacts.manifest.unit(
                event["id"],
                source_path,
                discovery="complete",
                flow="partial" if partial else "complete",
                artifact=shard_path,
            )
            artifacts.manifest.parent(child, unit)
            context_shards(artifacts, event, source_path, shard_path, contexts)

    cursor.run(3, range(0, len(isolated), 2000), write_isolated, batch_size=1)
    with artifacts.manifest.batch(atomic=True):
        artifacts.manifest.unit(
            event["id"],
            filename,
            discovery="partial" if parse_failed else "complete",
            flow="partial" if parse_failed or partial else "complete",
            artifact=path,
            error="; ".join(gaps),
        )
        cursor.finish()
    return unit


def context_shards(artifacts, event, source_path, shard_path, contexts):
    if len(contexts) <= 100:
        return
    for offset in range(0, len(contexts), 100):
        value = {"ir_artifact": shard_path, "contexts": list(contexts[offset : offset + 100])}
        path = artifacts.write(identity("detail-context-shard", shard_path, value), value)
        child = artifacts.manifest.unit(
            event["id"],
            f"{source_path}#context-shard={offset // 100}",
            discovery="complete",
            flow="complete",
            artifact=path,
        )
        artifacts.manifest.contexts(child, contexts[offset : offset + 100])
        from shyhurricane.graph.policy import ANALYZER_VERSION

        artifacts.manifest.parent(child, identity("analysis-unit-v2", ANALYZER_VERSION, event["id"], source_path))
