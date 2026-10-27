const test = require("node:test");
const assert = require("node:assert/strict");
const { summarize, compress, NODE_THRESHOLD, EDGE_THRESHOLD } = require("../library.cjs");
const { analyze } = require("../analyze.cjs");
const node = (id, role = "") => ({ id, role, name: id, location: `${id}:0` });
const edge = (source, target, kind = "FLOWS_TO") => ({ source, target, kind, location: "1:0", snippet: "original" });
const result = (nodes = [], edges = [], references = [], gaps = []) => ({ nodes, edges, references, gaps });
const padding = Array.from({ length: NODE_THRESHOLD }, (_, index) => node(`unused${index}`));

function reachability(graph, endpoints) {
  const adjacency = new Map(graph.nodes.map((item) => [item.id, []]));
  for (const item of graph.edges) {
    if (["FLOWS_TO", "CALL_ARGUMENT", "RETURNS_TO", "READS_FROM", "WRITES_TO", "SUBMITS_TO", "REQUESTS", "SUMMARIZED_FLOW"].includes(item.kind)) {
      adjacency.get(item.source)?.push(item.target);
    }
  }
  const pairs = [];
  for (const start of endpoints) {
    const seen = new Set([start]);
    const queue = [start];
    for (let cursor = 0; cursor < queue.length; cursor += 1) {
      for (const target of adjacency.get(queue[cursor]) || []) {
        if (!seen.has(target)) { seen.add(target); queue.push(target); }
      }
    }
    for (const end of endpoints) if (start !== end && seen.has(end)) pairs.push(`${start}:${end}`);
  }
  return pairs.sort();
}

test("graph thresholds are strict and full mode bypasses compression", () => {
  const small = result(padding);
  assert.equal(compress(small, "summary"), small);
  const large = result([...padding, node("s", "source")]);
  assert.equal(compress(large, "summary").analysis.trigger, "graph_size");
  assert.equal(compress(large, "full"), large);
  const dense = result([node("s", "source"), node("t", "sink")],
    Array.from({ length: EDGE_THRESHOLD }, () => edge("s", "t")));
  assert.equal(compress(dense, "summary"), dense);
  assert.equal(compress({ ...dense, edges: [...dense.edges, edge("s", "t")] }, "summary").analysis.mode, "summary");
  assert.equal(summarize(result()).nodes.length, 0);
});

test("long internal paths become evidenced summary edges; direct edges are unchanged", () => {
  const nodes = Array.from({ length: 101 }, (_, index) => node(`n${index}`, index === 0 ? "source" : index === 100 ? "sink" : ""));
  const edges = nodes.slice(1).map((item, index) => edge(nodes[index].id, item.id));
  edges.push(edge("missing", "n100"), edge("n100", "n0"), edge("n0", "n0"));
  const input = result([...nodes, node("unrelated")], edges);
  const output = summarize(input);
  assert.deepEqual(output.nodes.map((item) => item.id), ["n0", "n100"]);
  const summary = output.edges.find((item) => item.kind === "SUMMARIZED_FLOW");
  assert.equal(summary.original_hops, 100);
  assert.equal(summary.witness.length, 8);
  assert.ok(summary.witness[0].includes("n0 -> n1"));
  assert.ok(summary.witness.at(-1).includes("n99 -> n100"));
  assert.deepEqual(summary.endpoint_locations, ["n0:0", "n100:0"]);
  assert.match(summary.summary_notice, /does not prove runtime execution or sanitization/);
  assert.ok(output.edges.includes(edges.at(-2)));
  assert.equal(output.analysis.budget_limited, false);
  assert.equal(output.analysis.omitted_edges, 101);
  assert.deepEqual(reachability(input, ["n0", "n100"]), reachability(output, ["n0", "n100"]));
  assert.deepEqual(output, summarize({ ...input, nodes: [...input.nodes].reverse(), edges: [...input.edges].reverse() }));
});

test("compression preserves endpoint reachability for branching, cyclic and disconnected graphs", () => {
  for (let fixture = 0; fixture < 20; fixture += 1) {
    const nodes = Array.from({ length: 30 }, (_, index) => node(`n${index}`, index % 5 === 0 ? "source" : ""));
    const edges = [];
    for (let from = 0; from < 30; from += 1) for (let to = 0; to < 30; to += 1) {
      if (from !== to && (from * 31 + to * 17 + fixture * 13) % 23 === 0) edges.push(edge(`n${from}`, `n${to}`));
    }
    const input = result(nodes, edges);
    const output = summarize(input);
    const endpoints = output.nodes.map((item) => item.id);
    assert.deepEqual(reachability(output, endpoints), reachability(input, endpoints));
    assert.ok(output.edges.every((item) => endpoints.includes(item.source) && endpoints.includes(item.target)));
    assert.equal(output.analysis.budget_limited, false);
  }
  const input = result([node("s", "source"), node("m"), node("t", "sink"), node("isolated", "sink")],
    [edge("s", "m"), edge("m", "s"), edge("m", "t")]);
  const output = summarize(input);
  assert.deepEqual(reachability(output, ["s", "t", "isolated"]), ["s:t"]);
});

test("only flow edges are contracted; retained direct relationships keep their kinds", () => {
  const input = result([node("s", "source"), node("m"), node("t", "sink")],
    [edge("s", "m", "NAVIGATES_TO"), edge("m", "t"), edge("t", "s", "NAVIGATES_TO")]);
  const output = summarize(input);
  assert.deepEqual(output.edges, [input.edges[2]]);
});

test("endpoint selection prioritizes security, boundaries, DOM and reference origins", () => {
  const nodes = Array.from({ length: 498 }, (_, index) => node(`s${index}`, "sink"));
  nodes.push({ ...node("export"), export_name: "run" }, { ...node("import"), import_url: "./dependency" },
    { ...node("callback"), callback_boundary: true }, { ...node("dom"), selector: "#field" }, node("ref"));
  const output = summarize(result(nodes, [], [{ source: "ref", url: "/lost" }]));
  assert.equal(output.nodes.length, 500);
  assert.ok(output.nodes.some((item) => item.id === "callback"));
  assert.ok(output.nodes.some((item) => item.id === "export"));
  assert.deepEqual(output.analysis.omitted_endpoints, { security: 3, boundary: 0, dom: 0, reference: 0 });
  assert.equal(output.analysis.endpoint_limited, true);
  assert.equal(output.analysis.reference_limited, false);
  assert.equal(output.references.length, 1);
  const security = summarize(result(Array.from({ length: 502 }, (_, index) => node(`s${index}`, "source"))));
  assert.equal(security.analysis.omitted_endpoints.security, 2);
});

test("reference caps, missing origins and original analysis limits are explicit", () => {
  const references = Array.from({ length: 51 }, (_, index) => ({ source: "r", url: `/${index}` }));
  references.push({ url: "/global" }, { source: "missing", url: "/invalid" });
  const output = summarize(result([node("r")], [], references, ["JavaScript edge budget reached"]));
  assert.equal(output.references.length, 53);
  assert.equal(output.analysis.omitted_references, 0);
  assert.equal(output.analysis.analysis_limited, true);
  assert.equal(output.analysis.traversal_limited, false);
  assert.equal(output.analysis.publication_limited, false);
  assert.match(output.gaps.at(-1), /budget reached/);
  assert.ok(summarize(result([], [], [{ url: "/global" }])).references.length);
  const incompleteLocation = summarize(result([{ id: "s", role: "source" }, node("m"), { id: "t", role: "sink" }],
    [{ source: "s", target: "m", kind: "FLOWS_TO" }, edge("m", "t")]));
  assert.deepEqual(incompleteLocation.edges[0].endpoint_locations, ["", ""]);
});

test("direct, compressed and traversal budgets remain bounded", () => {
  const endpoints = Array.from({ length: 24 }, (_, index) => node(`s${index}`, "source"));
  const dense = endpoints.flatMap((from) => endpoints.filter((to) => to !== from).map((to) => edge(from.id, to.id)));
  let output = summarize(result(endpoints, dense));
  assert.equal(output.edges.length, 500);
  assert.equal(output.analysis.relationship_limited, true);
  const throughMiddle = endpoints.flatMap((item) => [edge(item.id, "middle"), edge("middle", item.id)]);
  output = summarize(result([...endpoints, node("middle")], throughMiddle));
  assert.equal(output.edges.length, 500);
  assert.equal(output.analysis.relationship_limited, true);
  assert.equal(output.analysis.summarized_edges, 500);
  const starts = Array.from({ length: 400 }, (_, index) => node(`s${index}`, "source"));
  const chain = Array.from({ length: 301 }, (_, index) => node(`c${index}`));
  const edges = [...starts.map((item) => edge(item.id, "c0")), ...chain.slice(1).map((item, index) => edge(`c${index}`, item.id))];
  output = summarize(result([...starts, ...chain], edges));
  assert.equal(output.analysis.traversal_limited, true);
  assert.equal(output.analysis.traversal_steps, 100000);
});

test("analyzer uses graph size across versions, filenames and source formatting", () => {
  const filler = Array.from({ length: 2050 }, (_, index) => `const unused${index}=${index};`).join("\n");
  for (const [filename, version, whitespace] of [["react.js", "18", "\n"], ["renamed.min.js", "19", ""]]) {
    const source = `/* React ${version} */${whitespace}${filler.replaceAll("\n", whitespace)}${whitespace}eval(location.hash);`;
    const output = analyze(source, filename);
    assert.equal(output.analysis.mode, "summary");
    assert.equal(output.analysis.trigger, "graph_size");
    assert.ok(output.nodes.some((item) => item.role === "source"));
    assert.ok(output.nodes.some((item) => item.role === "sink"));
    assert.equal(analyze(source, filename, "full").analysis.mode, "full");
  }
  assert.equal(analyze("eval(location.hash)", "react.js").analysis.mode, "full");
  assert.throws(() => analyze("", "x", "invalid"), /Invalid/);
  assert.match(analyze("const = ???").gaps[0], /Parse failed/);
});

test("exports and resolved callback boundaries are retained without a hash registry", () => {
  const filler = Array.from({ length: 2050 }, (_, index) => `const unused${index}=${index};`).join("");
  const source = `${filler}function render(value){return value;}
    exports.render=render; globalThis.Widget=exports; window.Widget=exports; module.exports=render;
    Promise.resolve(location.hash).then(value=>value); unknown(value=>value);`;
  const output = analyze(source, "mixed-bundle.js");
  assert.equal(output.analysis.mode, "summary");
  for (const name of ["exports.render", "globalThis.Widget", "window.Widget", "module.exports"]) {
    assert.ok(output.nodes.some((item) => item.export_names?.includes(name)));
  }
  assert.ok(output.nodes.some((item) => item.callback_boundary && item.kind === "return"));
  assert.ok(output.nodes.some((item) => item.callback_boundary && item.kind === "symbol"));
  assert.ok(output.gaps.some((gap) => /runtime dispatch is unproven/.test(gap)));
});


test("summary-mode initial analysis limits remain explicit", () => {
  const source = Array.from({ length: 50100 }, (_, index) => `const unused${index}=${index};`).join("");
  const output = analyze(source);
  assert.equal(output.analysis.mode, "summary");
  assert.equal(output.analysis.analysis_limited, false);
  assert.ok(output.analysis.input_nodes > 50000);
  assert.equal(output.archive.nodes.length, output.analysis.input_nodes);
  assert.ok(!output.gaps.some((gap) => /JavaScript node budget reached/.test(gap)));
});

test("representative script fixtures retain endpoint reachability while reducing graph size", (context) => {
  const fs = require("node:fs");
  const filler = Array.from({ length: 2050 }, (_, index) => `const unused${index}=${index};`).join("");
  const fixtures = [
    ["forms", fs.readFileSync(`${__dirname}/dataFlow.js`, "utf8")],
    ["mixed bundle", `function identity(value){return value;} exports.identity=identity;
      Promise.resolve(location.hash).then(identity).then(value=>eval(value));
      function constant(ignored){return "safe";} eval(constant(location.hash));`],
    ["DOM and network", `const input=document.querySelector('#name');
      input.addEventListener('input',event=>fetch('/save',{method:'POST',body:event.target.value}));
      document.querySelector('#out').innerHTML=location.hash;`],
  ];
  for (const [name, source] of fixtures) {
    const full = analyze(filler + source, `${name}.js`, "full");
    const summary = analyze(filler + source, `${name}.js`);
    const endpoints = summary.nodes.map((item) => item.id);
    assert.equal(summary.analysis.budget_limited, false);
    assert.deepEqual(reachability(summary, endpoints), reachability(full, endpoints));
    const securityNodes = full.nodes.filter((item) => item.role).map((item) => item.id);
    assert.ok(securityNodes.every((id) => endpoints.includes(id)));
    assert.ok(summary.nodes.length < full.nodes.length / 10);
    context.diagnostic(`${name}: ${full.nodes.length} -> ${summary.nodes.length} nodes; ${securityNodes.length}/${securityNodes.length} security endpoints and all endpoint reachability retained`);
  }
});

test("source and boundary classes survive sink saturation and all references remain archived", () => {
  const sinks = Array.from({length: 501}, (_, index) => node(`sink${index}`, "sink"));
  const references = Array.from({length: 60}, (_, index) => ({source: "input", kind: "REQUESTS", url: `/api/${index}`}));
  const full = result([node("input", "source"), { ...node("boundary"), export_name: "handler" }, ...sinks, ...padding],
    [edge("input", "sink0")], references);
  const summary = summarize(full);
  assert.ok(summary.nodes.some(item => item.id === "input"));
  assert.ok(summary.nodes.some(item => item.id === "boundary"));
  assert.equal(summary.references.length, 60);
  assert.equal(summary.archive.nodes.length, full.nodes.length);
  assert.equal(summary.analysis.endpoint_limited, true);
});

test("benign declaration padding cannot hide a late source, sink, or request", () => {
  const filler = Array.from({length: 10050}, (_, index) => `const benign${index}=${index};`).join("");
  const source = filler + 'const input=location.hash; eval(input); fetch("/tail",{body:input});';
  for (const mode of ["summary", "full"]) {
    const graph = analyze(source, "fixture.js", mode);
    assert.ok(graph.nodes.some(item => item.role === "source"));
    assert.ok(graph.nodes.some(item => item.role === "sink"));
    assert.ok(graph.references.some(item => item.url === "/tail"));
  }
});

test("persistent storage remains an explicit cross-document boundary in summaries", () => {
  const storage = {...node("storage"), kind: "storage"};
  const full = result([node("input", "source"), storage, node("output", "sink"), ...padding],
    [edge("input", "storage", "WRITES_TO"), edge("storage", "output", "READS_FROM")]);
  const graph = summarize(full);
  assert.ok(graph.nodes.some(item => item.id === "storage"));
  assert.deepEqual(reachability(graph, ["input", "storage", "output"]),
    reachability(full, ["input", "storage", "output"]));
});
