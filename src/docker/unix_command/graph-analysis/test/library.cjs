const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { recognize, summarize, DISTRIBUTIONS } = require("../library.cjs");
const { analyze } = require("../analyze.cjs");
const node = (id, role = "") => ({ id, role, name: id });
const edge = (source, target) => ({ source, target, kind: "FLOWS_TO", location: "1:0", snippet: "original" });
const result = (nodes, edges = [], references = [], gaps = []) => ({ nodes, edges, references, gaps });
test("recognition requires the entire verified source, regardless of filename", () => {
  const source = "trusted standalone fixture";
  const registry = new Map([[createHash("sha256").update(source).digest("hex"), "Fixture"]]);
  assert.equal(recognize(source, registry), "Fixture");
  assert.equal(recognize(`${source}; applicationCode()`, registry), null);
  assert.equal(recognize("/* @license React */ eval(location.hash)"), null);
  assert.equal(DISTRIBUTIONS.size, 3);
  for (const filename of ["angular.js", "vendor.js", "react-dom.development.js"]) {
    const output = analyze("eval(location.hash)", filename);
    assert.equal(output.analysis.mode, "full");
    assert.equal(output.analysis.library, null);
  }
  assert.throws(() => analyze("", "x", "invalid"), /Invalid/);
});
test("summary preserves directed original security paths and drops unrelated internals", () => {
  const input = result([node("s", "source"), node("m"), node("t", "sink"), node("unrelated")],
    [edge("s", "m"), edge("m", "t"), edge("missing", "t")]);
  const output = summarize(input, "Fixture");
  assert.deepEqual(output.nodes.map((n) => n.id), ["m", "s", "t"]);
  assert.equal(output.edges.length, 2);
  assert.ok(output.edges.every((e) => input.edges.includes(e) && e.snippet === "original"));
  assert.equal(output.analysis.omitted_nodes, 1);
  assert.deepEqual(output, summarize({ ...input, nodes: [...input.nodes].reverse(), edges: [...input.edges].reverse() }, "Fixture"));
  assert.equal(summarize(result([]), "Empty").nodes.length, 0);
});
test("integration seeds and reference sources survive; budgets are explicit", () => {
  const nodes = [node("i"), node("e"), node("d"), node("r")];
  Object.assign(nodes[0], { import_url: "./module" });
  Object.assign(nodes[1], { export_name: "public" });
  Object.assign(nodes[2], { selector: "#input" });
  let output = summarize(result(nodes, [], [{ source: "r", url: "/a" }, { url: "/b" }]), "Fixture");
  assert.equal(output.nodes.length, 4);
  assert.equal(output.references.length, 2);
  const many = Array.from({ length: 502 }, (_, i) => node(`${i}`.padStart(4, "0"), "sink"));
  output = summarize(result(many, [], Array.from({ length: 51 }, () => ({ source: "unknown" })), ["JavaScript node budget reached"]), "Fixture");
  assert.equal(output.nodes.length, 500);
  assert.equal(output.references.length, 0);
  assert.equal(output.analysis.budget_limited, true);
  assert.equal(output.analysis.omitted_references, 51);
  assert.ok(output.gaps.includes("Library security summary budget reached"));
});
test("depth, node, edge and traversal limits bound summary expansion", () => {
  let nodes = Array.from({ length: 19 }, (_, i) => node(`n${i}`, i === 0 ? "source" : i === 18 ? "sink" : ""));
  let edges = nodes.slice(1).map((n, i) => edge(nodes[i].id, n.id));
  let output = summarize(result(nodes, edges), "Depth");
  assert.equal(output.analysis.budget_limited, true);
  assert.equal(output.edges.length, 0);
  nodes = Array.from({ length: 501 }, (_, i) => node(`${i}`.padStart(4, "0"), i < 499 ? "source" : ""));
  edges = [edge("0000", "0499"), edge("0499", "0500"), edge("0500", "0001")];
  output = summarize(result(nodes, edges), "Nodes");
  assert.equal(output.analysis.budget_limited, true);
  assert.ok(output.nodes.length <= 500);
  nodes = Array.from({ length: 120 }, (_, i) => node(`n${i}`, "source"));
  edges = nodes.flatMap((a) => nodes.filter((b) => a !== b).map((b) => edge(a.id, b.id)));
  output = summarize(result(nodes, edges), "Work");
  assert.ok(output.edges.length <= 500);
  assert.equal(output.analysis.budget_limited, true);
});
test("recognized UMD distributions preserve exported integration boundaries", () => {
  const source = "function render(value){return value;} exports.render=render; globalThis.React=exports;";
  const digest = createHash("sha256").update(source).digest("hex");
  DISTRIBUTIONS.set(digest, "Fixture UMD");
  try {
    const output = analyze(source, "renamed.js");
    assert.equal(output.analysis.mode, "summary");
    assert.ok(output.nodes.some((n) => n.export_name === "exports.render"));
    assert.ok(output.nodes.some((n) => n.export_name === "globalThis.React"));
    assert.equal(analyze(source, "renamed.js", "full").analysis.mode, "full");
  } finally { DISTRIBUTIONS.delete(digest); }
});
