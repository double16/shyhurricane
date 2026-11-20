"""Resolve bounded detail descriptors without retaining duplicate IR payload copies."""


def resolve(artifacts, value):
    layers, seen = [], set()
    while "ir_artifact" in value:
        reference = value["ir_artifact"]
        if reference in seen or len(layers) >= 8:
            raise ValueError("Invalid recursive analysis descriptor")
        seen.add(reference)
        layers.append(value)
        value = artifacts.read(reference)
    for layer in reversed(layers):
        if "edge_offset" in layer:
            offset, count = layer["edge_offset"], layer["edge_limit"]
            if not isinstance(offset, int) or offset < 0 or not isinstance(count, int) or not 0 <= count <= 2000:
                raise ValueError("Invalid analysis edge range")
            edges = value.get("edges", [])[offset:offset + count]
            ids = {edge[side] for edge in edges for side in ("source", "target")}
            nodes = {node["id"]: node for node in value.get("nodes", [])}
            value = {**value, "nodes": [nodes[key] for key in sorted(ids) if key in nodes],
                     "edges": edges, "references": [], "analysis": {"mode": "full"}}
        if "node_ids" in layer:
            selected = layer["node_ids"]
            if not isinstance(selected, list) or len(selected) > 2000:
                raise ValueError("Invalid analysis node selection")
            nodes = {node["id"]: node for node in value.get("nodes", [])}
            value = {**value, "nodes": [nodes[key] for key in selected if key in nodes],
                     "edges": [], "references": [], "analysis": {"mode": "full"}}
        if "filename" in layer:
            value["filename"] = layer["filename"]
        if "contexts" in layer:
            value["contexts"] = layer["contexts"]
            value["requires_context_shards"] = layer.get("requires_context_shards", False)
    return value
