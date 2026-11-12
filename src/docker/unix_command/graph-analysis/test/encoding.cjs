const { test } = require("node:test");
const assert = require("node:assert/strict");
const parser = require("@babel/parser");
const { prepareSource } = require("../encoding.cjs");
const parse = (source) => parser.parse(source, { errorRecovery: true });
const corrupt = (source) => Buffer.from(source, "utf8").toString("latin1");
test("repair is strict and parse gated", () => {
  const source = "const À = 1;";
  const result = prepareSource(corrupt(source), parse);
  assert.equal(result.source, source);
  assert.equal(result.transformation, "latin1-to-utf8-v1");
  assert.equal(prepareSource(source, parse).source, source);
  for (const text of ["const = ;", "const \x80 = 1;", "const \x80 = '界';", corrupt("const À = ;"), corrupt("let À; let À;")]) {
    assert.throws(() => prepareSource(text, parse));
  }
});
test("unchanged and non-roundtrippable repairs are rejected", () => {
  const fail = () => { throw Object.assign(new Error(), { reasonCode: "InvalidOrUnexpectedToken" }); };
  assert.throws(() => prepareSource("ascii", fail));
  assert.throws(() => prepareSource("\ufeff", fail));
});
test("CLI prepares repaired source without evaluating captured code", () => {
  const { spawnSync } = require("node:child_process");
  const path = require("node:path");
  const source = "const À = location.hash; fetch(À);";
  for (const text of [corrupt(source), source, "const = ;"]) {
    const result = spawnSync(process.execPath, [path.join(__dirname, "../analyze.cjs")], {
      input: JSON.stringify({ action: "prepare", source: text }), encoding: "utf8",
    });
    assert.equal(result.status, 0);
    const prepared = JSON.parse(result.stdout);
    assert.equal(prepared.source, text === corrupt(source) ? source : text);
    assert.equal(prepared.transformation, text === corrupt(source) ? "latin1-to-utf8-v1" : null);
  }
});
