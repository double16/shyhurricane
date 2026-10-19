/* Bounded compression of generated graphs; source names and versions are irrelevant. */
const NODE_THRESHOLD = 2000;
const EDGE_THRESHOLD = 4000;
const FLOW_KINDS = new Set([
  "FLOWS_TO", "CALL_ARGUMENT", "RETURNS_TO", "READS_FROM", "WRITES_TO", "SUBMITS_TO", "REQUESTS",
]);
const SUMMARY_NOTICE = "Intermediate operations omitted; static reachability does not prove runtime execution or sanitization";
const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
const category = (node, origins) => {
  if (node.role) return "security";
  if (node.import_url || node.export_name || node.callback_boundary) return "boundary";
  if (node.selector) return "dom";
  if (origins.has(node.id)) return "reference";
  return "internal";
};
const priority = { security: 0, boundary: 1, dom: 2, reference: 3, internal: 4 };

function summarize(result) {
  const origins = new Set(result.references.map((reference) => reference.source));
  const nodes = [...result.nodes].sort((a, b) =>
    priority[category(a, origins)] - priority[category(b, origins)] || compare(a.id, b.id));
  const seeds = nodes.filter((node) => category(node, origins) !== "internal");
  const selected = new Set(seeds.slice(0, 500).map((node) => node.id));
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const edges = result.edges.filter((edge) => byId.has(edge.source) && byId.has(edge.target))
    .sort((a, b) => compare(JSON.stringify(a), JSON.stringify(b)));
  const adjacency = new Map();
  for (const edge of edges) {
    if (!FLOW_KINDS.has(edge.kind)) continue;
    if (!adjacency.has(edge.source)) adjacency.set(edge.source, []);
    adjacency.get(edge.source).push(edge);
  }
  // Direct endpoint edges retain their original kinds, rules, and evidence.
  const direct = edges.filter((edge) => selected.has(edge.source) && selected.has(edge.target));
  const keptEdges = direct.slice(0, 500);
  let relationshipLimited = direct.length > 500;
  let traversalLimited = false;
  let work = 0;
  for (const seed of seeds.slice(0, 500)) {
    const queue = [{ id: seed.id, hops: 0, witness: [] }];
    const seen = new Set([seed.id]);
    for (let cursor = 0; cursor < queue.length && !traversalLimited; cursor += 1) {
      const item = queue[cursor];
      for (const edge of adjacency.get(item.id) || []) {
        if (work >= 100000) { traversalLimited = true; break; }
        work += 1;
        if (seen.has(edge.target)) continue;
        seen.add(edge.target);
        const hops = item.hops + 1;
        const sample = `${edge.source} -> ${edge.target} (${edge.kind}) @ ${edge.location || ""}`.slice(0, 300);
        // Keep the first four and last four edges without copying full paths.
        const witness = [...item.witness, sample];
        if (witness.length > 8) witness.splice(4, 1);
        if (selected.has(edge.target)) {
          if (hops > 1) {
            if (keptEdges.length < 500) keptEdges.push({
              source: seed.id, target: edge.target, kind: "SUMMARIZED_FLOW", rule: "js.size-summary",
              location: seed.location || "", snippet: SUMMARY_NOTICE, original_hops: hops,
              endpoint_locations: [seed.location || "", byId.get(edge.target).location || ""],
              witness, summary_notice: SUMMARY_NOTICE,
            });
            else relationshipLimited = true;
          }
          continue;
        }
        queue.push({ id: edge.target, hops, witness });
      }
    }
    if (traversalLimited) break;
  }
  const references = result.references.filter((reference) => !reference.source || selected.has(reference.source))
    .sort((a, b) => compare(JSON.stringify(a), JSON.stringify(b))).slice(0, 50);
  const omittedEndpoints = { security: 0, boundary: 0, dom: 0, reference: 0 };
  for (const node of seeds.slice(500)) omittedEndpoints[category(node, origins)] += 1;
  const analysisLimited = result.gaps.some((gap) => /budget reached/.test(gap));
  const endpointLimited = seeds.length > 500;
  const referenceLimited = references.length < result.references.length;
  const limited = analysisLimited || endpointLimited || relationshipLimited || traversalLimited || referenceLimited;
  const directRetained = keptEdges.filter((edge) => edge.kind !== "SUMMARIZED_FLOW").length;
  return { ...result, nodes: nodes.filter((node) => selected.has(node.id)), edges: keptEdges, references,
    analysis: { mode: "summary", trigger: "graph_size", node_threshold: NODE_THRESHOLD, edge_threshold: EDGE_THRESHOLD,
      input_nodes: nodes.length, input_edges: result.edges.length, input_references: result.references.length,
      retained_nodes: selected.size, retained_edges: keptEdges.length, retained_references: references.length,
      summarized_edges: keptEdges.length - directRetained, omitted_nodes: nodes.length - selected.size,
      omitted_edges: result.edges.length - directRetained, omitted_references: result.references.length - references.length,
      omitted_endpoints: omittedEndpoints, analysis_limited: analysisLimited, endpoint_limited: endpointLimited,
      relationship_limited: relationshipLimited, traversal_limited: traversalLimited, reference_limited: referenceLimited,
      publication_limited: false, traversal_steps: work, budget_limited: limited },
    gaps: [...result.gaps, `Large-script graph summary: ${SUMMARY_NOTICE}; absence is not proof`,
      ...(limited ? ["Large-script graph summary budget reached"] : [])] };
}
function compress(result, mode) {
  return mode === "summary" && (result.nodes.length > NODE_THRESHOLD || result.edges.length > EDGE_THRESHOLD)
    ? summarize(result) : result;
}
module.exports = { compress, summarize, NODE_THRESHOLD, EDGE_THRESHOLD };
