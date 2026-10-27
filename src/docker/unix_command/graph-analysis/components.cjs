/* Iterative strongly connected components; no recursion proportional to captured code size. */
function components(nodes, edges) {
  const ids = new Set(nodes.map((node) => node.id));
  const forward = new Map([...ids].map((id) => [id, []]));
  const backward = new Map([...ids].map((id) => [id, []]));
  for (const edge of edges) if (ids.has(edge.source) && ids.has(edge.target)) {
    forward.get(edge.source).push(edge.target);
    backward.get(edge.target).push(edge.source);
  }
  const seen = new Set(); const ordered = [];
  for (const start of ids) {
    if (seen.has(start)) continue;
    const stack = [[start, false]];
    while (stack.length) {
      const [id, done] = stack.pop();
      if (done) { ordered.push(id); continue; }
      if (seen.has(id)) continue;
      seen.add(id); stack.push([id, true]);
      for (const next of forward.get(id)) if (!seen.has(next)) stack.push([next, false]);
    }
  }
  const membership = new Map(); const groups = [];
  for (const start of ordered.reverse()) {
    if (membership.has(start)) continue;
    const number = groups.length; const group = []; const pending = [start];
    while (pending.length) {
      const id = pending.pop();
      if (membership.has(id)) continue;
      membership.set(id, number); group.push(id);
      for (const previous of backward.get(id)) if (!membership.has(previous)) pending.push(previous);
    }
    groups.push(group.sort());
  }
  const dag = new Map();
  for (const edge of edges) {
    const source = membership.get(edge.source); const target = membership.get(edge.target);
    if (source !== undefined && target !== undefined && source !== target) {
      dag.set(`${source}:${target}`, { source, target });
    }
  }
  return { groups, edges: [...dag.values()] };
}
module.exports = { components };
