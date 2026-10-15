const { test } = require("node:test");
const assert = require("node:assert/strict");
const { analyze } = require("../analyze.cjs");

const reachable = (result, source, sink) => {
  const pending = result.nodes.filter(source).map((node) => node.id);
  const targets = new Set(result.nodes.filter(sink).map((node) => node.id));
  const visited = new Set();
  while (pending.length) {
    const current = pending.pop();
    if (targets.has(current)) return true;
    if (visited.has(current)) continue;
    visited.add(current);
    for (const edge of result.edges) if (edge.source === current) pending.push(edge.target);
  }
  return false;
};

test("data flows through parameters, returns, promises, and DOM writes", () => {
  const result = analyze(`const input = location.hash;
    function convert(value) { return decodeURIComponent(value); }
    const output = convert(input); document.body.innerHTML = output;
    fetch('/api', {method:'POST', body:input}).then(response => response.json()).then(data => eval(data));`);
  assert(reachable(result, (n) => n.name === "location.hash", (n) => n.name === "document.body.innerHTML"));
  assert(result.references.some((r) => r.url === "/api" && r.method === "POST"));
  assert(result.edges.some((edge) => edge.kind === "RETURNS_TO"));
  assert(result.edges.some((edge) => edge.rule === "js.callback"));
});

test("lexical shadowing does not join unrelated values", () => {
  const result = analyze(`const value = location.hash;
    function safe() { const value = 'constant'; document.body.innerHTML = value; } safe();`);
  assert(!reachable(result, (n) => n.name === "location.hash", (n) => n.role === "sink"));
  assert.equal(result.nodes.filter((n) => n.name === "value").length, 2);
});

test("calls before declarations and imported call interfaces resolve", () => {
  const result = analyze(`import send from './send.js'; import {render as output} from './view.js';
    const x = transform(location.search); send(x); output(x);
    export function transform(value) { return value; }
    export const base = '/api'; export {base as api}; export default transform;`);
  assert(result.nodes.some((n) => n.imported_name === "default" && n.parameter_index === 0));
  assert(result.nodes.some((n) => n.imported_name === "render" && n.return_value));
  assert(result.nodes.some((n) => n.export_name === "transform" && n.return_value));
  assert(result.references.some((r) => r.kind === "IMPORTS"));
});

test("Vite generated imports and dynamic unresolved globs retain boundaries", () => {
  const result = analyze(`const parts = {'./one.js': () => import('./one-123.js')};
    import.meta.glob('./views/*.vue'); import(dynamicPath); require('./shared.js');
    new Worker('/worker.js'); navigator.serviceWorker.register('/sw.js');`);
  assert(result.references.some((r) => r.url === "./one-123.js"));
  assert(result.references.some((r) => r.kind === "REGISTERS_WORKER"));
  assert(result.gaps.some((gap) => gap.includes("glob")));
  assert(result.gaps.some((gap) => gap.includes("Unresolved imports")));
});

test("React state, routes, forms, and HTML sinks", () => {
  const result = analyze(`const [name, setName] = useState(''); setName(location.hash);
    const Page = () => <><Link to='/profile'/><form action='/save'/>
      <div dangerouslySetInnerHTML={{__html:name}}/><iframe srcDoc={name}/></>;
    router.push('/next'); const route = {path:'/users',redirect:'/home'};` , "page.jsx");
  assert(reachable(result, (n) => n.name === "location.hash", (n) => n.name === "dangerouslySetInnerHTML"));
  assert(result.references.some((r) => r.kind === "SUBMITS_TO" && r.url === "/save"));
  assert(result.references.some((r) => r.kind === "DECLARES_ROUTE"));
});

test("Vue and Nuxt template bindings and clients", () => {
  const result = analyze(`<script lang="ts">let name: string = ''; const api = '/api';
    navigateTo('/home'); $fetch(api);</script>
    <template><input v-model="name"/><div v-html="name"/><NuxtLink to="/account"/>
    <RouterLink :to="'/profile'"/><form :action="destination"/></template>`, "page.vue");
  assert(reachable(result, (n) => n.kind === "field", (n) => n.role === "sink"));
  assert(result.references.some((r) => r.url === "/profile"));
  assert(result.references.some((r) => r.url === "/api"));
  assert(result.gaps.some((gap) => gap.includes("submits_to")));
});

test("Angular delivered templates and HttpClient", () => {
  const result = analyze(`@Component({template:'<a routerLink="/profile"></a><div [innerHTML]="value"></div>'})
    class Page { value = location.hash; go(){this.router.navigateByUrl('/account');this.http.post('/api', this.value)} }`, "page.ts");
  assert(result.references.some((r) => r.url === "/profile"));
  assert(result.references.some((r) => r.url === "/account"));
  assert(result.references.some((r) => r.url === "/api" && r.method === "POST"));
});

test("Svelte delivered component bindings and SvelteKit navigation", () => {
  const result = analyze(`<script>let name = ''; goto('/account');</script>
    <input bind:value={name}/><a href="/home">home</a><form action="/save"/>`, "page.svelte");
  assert(result.nodes.some((n) => n.role === "source"));
  assert(result.references.some((r) => r.url === "/account"));
  assert(result.references.some((r) => r.url === "/save"));
});

test("constant folding, computed properties, request clients, storage and messaging", () => {
  const result = analyze(`const root='/a'; const url = root + '/b';
    xhr.open('PUT', url); $.ajax({url:'/ajax'}); axios.get('/read');
    new WebSocket('wss://example.test/socket'); new EventSource('/events');
    navigator.sendBeacon('/beacon', document.cookie); localStorage.setItem('x', location.hash);
    window.postMessage(location.search, '*'); window.location.href='/next';
    const {a, b: renamed} = object; const [first, second] = values;
    const getter = (x='default') => x; const data = object?.['field'];
    let copy; copy = data ? first : renamed; eval(copy);`);
  assert(result.references.some((r) => r.url === "/a/b" && r.method === "PUT"));
  assert(result.references.some((r) => r.url === "/ajax"));
  assert(result.references.some((r) => r.url === "wss://example.test/socket"));
  assert(result.nodes.some((n) => n.role === "sink" && n.name === "window.postMessage"));
  assert(analyze("fetch(`/x/${'a'}`)").references.some((r) => r.url === "/x/a"));
});

test("invalid input, parse recovery, typescript, and analysis budgets report gaps", () => {
  assert(analyze("const = ;").gaps[0].includes("Parse failed"));
  assert(analyze("let a; let a;").gaps.some((gap) => gap.includes("Parse recovery")));
  assert.equal(analyze("const value: string = 'x'", "a.ts").gaps.length, 0);
  const many = Array.from({length:11000}, (_, i) => `const value${i}=location.hash;`).join("\n");
  assert(analyze(many).gaps.some((gap) => gap.includes("budget")));
});

test("virtual framework source filenames retain typescript and DOM selector provenance", () => {
  const result = analyze("const value: string = document.getElementById('name').value; eval(value);", "App.vue?vue&type=script&lang=ts");
  assert(result.nodes.some((node) => node.selector === "#name"));
  assert(result.nodes.some((node) => node.role === "source" && node.location !== "1:0"));
  assert(!result.gaps.some((gap) => gap.includes("Parse failed")));
  assert(analyze("document.querySelector(dynamicSelector)").gaps.some((gap) => gap.includes("Dynamic DOM")));
  assert(analyze("createServerReference('id')").gaps.some((gap) => gap.includes("backend")));
  assert(!analyze("const items=[];items.push('/not-a-route')").references.some((item) => item.kind === "NAVIGATES_TO"));
});
