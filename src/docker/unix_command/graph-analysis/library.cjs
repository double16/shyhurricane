/* Only exact, inspected standalone distributions qualify. Names and banners are insufficient. */
const { createHash } = require("node:crypto");
const DISTRIBUTIONS = new Map([
  ["f76dd498a673f19070ba71cb25c10f886b12ae3fb0fe2da7ee2ad97bb2b7c655", "AngularJS 1.7.7"],
  ["3691c923ea593c1f7b941443ee06a35ca0c3fdff54c9eaeb276fa4c42289ded5", "React development"],
  ["2e10ae11b803fd7adf1ba2fa497d97797b803efdcd54de28967555ea1916cb54", "React DOM development"],
]);
function recognize(source, distributions = DISTRIBUTIONS) {
  return distributions.get(createHash("sha256").update(source).digest("hex")) || null;
}
function summarize(result, library) {
  const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
  const nodes = [...result.nodes].sort((a, b) => compare(a.id, b.id));
  const seeds = nodes.filter((n) => n.role || n.import_url || n.export_name || n.selector);
  const selected = new Set(seeds.slice(0, 500).map((n) => n.id));
  const adjacency = new Map();
  const valid = new Set(nodes.map((n) => n.id));
  const edges = result.edges.filter((e) => valid.has(e.source) && valid.has(e.target))
    .sort((a, b) => compare(`${a.source}:${a.target}:${a.kind}`, `${b.source}:${b.target}:${b.kind}`));
  for (const edge of edges) {
    if (!adjacency.has(edge.source)) adjacency.set(edge.source, []);
    adjacency.get(edge.source).push(edge);
  }
  const retained = new Set();
  let work = 0;
  let limited = seeds.length > 500;
  // Breadth-first traversal retains shortest directed paths; intermediates are never contracted.
  for (const seed of seeds.slice(0, 500)) {
    const queue = [{ id: seed.id, path: [] }];
    const seen = new Set([seed.id]);
    for (let cursor = 0; cursor < queue.length; cursor += 1) {
      const item = queue[cursor];
      if (item.path.length >= 16) { limited = true; continue; }
      for (const edge of adjacency.get(item.id) || []) {
        work += 1;
        if (work > 100000) { limited = true; break; }
        if (seen.has(edge.target)) continue;
        seen.add(edge.target);
        const path = [...item.path, edge];
        if (selected.has(edge.target)) {
          const additions = new Set(path.flatMap((e) => [e.source, e.target]).filter((id) => !selected.has(id)));
          const newEdges = path.filter((e) => !retained.has(e));
          if (selected.size + additions.size <= 500 && retained.size + newEdges.length <= 500) {
            for (const id of additions) selected.add(id);
            for (const e of path) retained.add(e);
          } else limited = true;
        }
        queue.push({ id: edge.target, path });
      }
      if (work > 100000) break;
    }
    if (work > 100000) break;
  }
  const references = result.references.slice(0, 50).map((reference) => {
    if (!reference.source || selected.has(reference.source)) return reference;
    if (selected.size < 500 && valid.has(reference.source)) {
      selected.add(reference.source);
      return reference;
    }
    limited = true;
    return null;
  }).filter(Boolean);
  const keptNodes = nodes.filter((n) => selected.has(n.id));
  const keptEdges = edges.filter((e) => retained.has(e));
  return { ...result, nodes: keptNodes, edges: keptEdges, references,
    analysis: { mode: "summary", library, retained_nodes: keptNodes.length,
      retained_edges: keptEdges.length, omitted_nodes: nodes.length - keptNodes.length,
      omitted_edges: result.edges.length - keptEdges.length,
      omitted_references: result.references.length - references.length,
      budget_limited: limited || result.references.length > 50 || result.gaps.some((gap) => /budget reached/.test(gap)) },
    gaps: [...result.gaps, `Library security summary: ${library}; unrelated internals omitted; absence is not proof`,
      ...(limited || result.references.length > 50 ? ["Library security summary budget reached"] : [])] };
}
module.exports = { recognize, summarize, DISTRIBUTIONS };
