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
