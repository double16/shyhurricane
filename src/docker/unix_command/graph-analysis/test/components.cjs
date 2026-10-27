const { test } = require('node:test');
const assert = require('node:assert/strict');
const { components } = require('../components.cjs');

test('components retain cycles, isolates, and a directed acyclic quotient', () => {
  const result = components(['a','b','c','d'].map(id => ({id})), [
    {source:'a',target:'b'}, {source:'b',target:'a'}, {source:'b',target:'c'},
    {source:'a',target:'missing'}, {source:'missing',target:'c'},
  ]);
  assert.ok(result.groups.some(group => group.join() === 'a,b'));
  assert.ok(result.groups.some(group => group.join() === 'd'));
  assert.equal(result.edges.length, 1);
  assert.notEqual(result.edges[0].source, result.edges[0].target);
  assert.deepEqual(components([], []), {groups:[],edges:[]});
});

test('long chains use iterative traversal and every node belongs to exactly one component', () => {
  const nodes = Array.from({length:20000}, (_,id) => ({id}));
  const edges = nodes.slice(1).map(({id}) => ({source:id-1,target:id}));
  const result = components(nodes, edges);
  assert.equal(result.groups.length, nodes.length);
  assert.equal(result.edges.length, edges.length);
});
