const { test } = require("node:test");
const assert = require("node:assert/strict");
const { analyze } = require("../analyze.cjs");

test("literal registrations identify Webpack and Turbopack factories", () => {
  const webpack = analyze(`(self.webpackChunk_N_E=self.webpackChunk_N_E||[])
    .push([[1],{42:()=>{}, "43": function(){}, 44(){}, [key]:()=>{}, 45:17}]);`);
  assert.deepEqual(webpack.next_modules.map(({id, bundler}) => [id, bundler]),
    [[42,"webpack"],["43","webpack"],[44,"webpack"]]);

  const turbo = analyze(`(globalThis.TURBOPACK||(globalThis.TURBOPACK=[]))
    .push([document.currentScript, 42, 43, ()=>{}, 44, value, 45, function(){}]);`);
  assert.deepEqual(turbo.next_modules.map(({id}) => id), [42,43,45]);
});

test("ignores indirect registrations and bounds literal registrations", () => {
  const fake = analyze(`other.TURBOPACK.push([null,1,()=>{}]);
    globalThis.TURBOPACK["push"]([null,1,()=>{}]); globalThis.TURBOPACK.push(dynamic);
    self.webpackChunk_N_E.push([[1],{dynamic(){}}]);`);
  assert.equal(fake.next_modules, undefined);
  const factories = Array.from({length:1001}, (_, id) => `${id}:()=>{}`).join(",");
  const bounded = analyze(`self.webpackChunk_N_E.push([[1],{${factories}}]);`);
  assert.equal(bounded.next_modules.length, 1000);
  assert(bounded.gaps.includes("Next.js module registration budget reached"));
});

test("Next Pages manifest reads static routes and literal aliases", () => {
  const manifest = 'self.__BUILD_MANIFEST=(function(a){return {"/items/[id]":[a,,unknown,42],sortedPages:[]}})' +
    '("static/chunks/pages/items/[id].js"),self.__BUILD_MANIFEST_CB&&self.__BUILD_MANIFEST_CB()';
  assert.deepEqual(analyze(manifest).next_manifest_chunks, [
    ["/items/[id]", "static/chunks/pages/items/[id].js"],
  ]);
  assert.deepEqual(analyze('self.__BUILD_MANIFEST={"/":["static/chunks/home.js"]};').next_manifest_chunks,
    [["/", "static/chunks/home.js"]]);
  for (const value of [
    'makeManifest()', '(({x}) => ({"/":[x]}))({x:"ignored"})',
    '(function(){sideEffect();return {"/":["ignored"]}})()', '(() => dynamic)()',
    '{["/"]:["ignored"],"/dynamic":makeChunks(),...dynamic}',
  ]) assert.equal(analyze('self.__BUILD_MANIFEST=' + value).next_manifest_chunks, undefined);
});

test("Turbopack Pages bootstrap contributes literal otherChunks", () => {
  const manifest = 'self.__TURBOPACK_PAGE_BOOTSTRAP={' +
    '"/items/[id]":{"otherChunks":["static/chunks/item.js",dynamic],"runtimeModuleIds":[42]},' +
    '"/missing":{},"/invalid":["ignored"],"/dynamic":{[key]:["ignored"],otherChunks:compute()}}';
  assert.deepEqual(analyze(manifest).next_manifest_chunks, [
    ["/items/[id]", "static/chunks/item.js"],
  ]);
});
