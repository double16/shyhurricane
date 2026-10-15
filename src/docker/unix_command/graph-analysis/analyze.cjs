/* Parse captured artifacts only. No target code is evaluated or imported. */
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;

const { recognize, summarize } = require("./library.cjs");

function analyze(source, filename = "source.js", mode = "summary") {
  if (!["summary", "full"].includes(mode)) throw new Error("Invalid library analysis mode");
  const library = recognize(source);
  const LIMIT = library && mode === "summary" ? 50000 : 10000;
  const nodes = new Map();
  const edges = new Map();
  const references = [];
  const gaps = new Set();
  const functions = new Map();
  const calls = [];
  const states = new Map();
  const exports = [];
  const templates = [];
  const cleanFilename = filename.split(/[?#]/)[0];
  if (/\.(?:vue|svelte)$/.test(cleanFilename) && source.trimStart().startsWith("<")) {
    templates.push(source);
    const original = source;
    source = source.replace(/[^\n]/g, " ");
    for (const match of original.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)) {
      const start = match.index + match[0].indexOf(">") + 1;
      source = source.slice(0, start) + match[1] + source.slice(start + match[1].length);
    }
  }
  let currentPath;
  const location = (node) => `${node?.loc?.start.line || 1}:${node?.loc?.start.column || 0}`;
  const make = (node, name, kind = "symbol", role = "") => {
    const id = `${kind}:${node?.start ?? 0}:${name}`;
    if (nodes.size >= LIMIT) {
      gaps.add("JavaScript node budget reached");
      return id;
    }
    if (!nodes.has(id)) nodes.set(id, { id, name, kind, role, location: location(node) });
    else if (role) nodes.get(id).role = role;
    return id;
  };
  const edge = (from, to, node, kind = "FLOWS_TO", rule = "js.def-use") => {
    if (!from || !to || from === to) return;
    if (edges.size >= LIMIT * 2) {
      gaps.add("JavaScript edge budget reached");
      return;
    }
    const id = `${from}:${to}:${kind}`;
    edges.set(id, { source: from, target: to, kind, rule, location: location(node),
      snippet: source.slice(node?.start || 0, Math.min(node?.end || 0, (node?.start || 0) + 300)) });
  };
  const nameOf = (node) => {
    if (!node) return "";
    if (node.type === "Identifier") return node.name;
    if (node.type === "StringLiteral") return node.value;
    if (["MemberExpression", "OptionalMemberExpression"].includes(node.type)) {
      return `${nameOf(node.object)}.${node.computed ? constant(node.property) ?? "?" : nameOf(node.property)}`;
    }
    return "";
  };
  const bindingId = (node, scope) => {
    const binding = scope?.getBinding(node.name);
    return make(binding?.identifier || { start: 0, loc: node.loc }, node.name);
  };
  function constant(node, scope = currentPath?.scope, seen = new Set()) {
    if (!node) return undefined;
    if (["StringLiteral", "NumericLiteral", "BooleanLiteral"].includes(node.type)) return node.value;
    if (node.type === "TemplateLiteral") {
      let result = node.quasis[0].value.cooked;
      for (let i = 0; i < node.expressions.length; i += 1) {
        const value = constant(node.expressions[i], scope, new Set(seen));
        if (value === undefined) return undefined;
        result += value + node.quasis[i + 1].value.cooked;
      }
      return result;
    }
    if (node.type === "BinaryExpression" && node.operator === "+") {
      const left = constant(node.left, scope, new Set(seen));
      const right = constant(node.right, scope, new Set(seen));
      return left !== undefined && right !== undefined ? left + right : undefined;
    }
    if (node.type === "Identifier") {
      const binding = scope?.getBinding(node.name);
      if (binding?.constant && !seen.has(binding)) {
        seen.add(binding);
        return constant(binding.path.node.init, binding.path.scope, seen);
      }
    }
    return undefined;
  }
  const sourcePattern = /^(?:window\.)?(?:location\.(?:search|hash|href)|document\.cookie|(?:localStorage|sessionStorage)\.getItem|.*(?:target|currentTarget)\.value|.*\.data|xhr\.response(?:Text|XML)?)$/;
  const sinkPattern = /(?:^|\.)(?:eval|Function|setTimeout|setInterval|write|writeln|insertAdjacentHTML|postMessage|send|sendBeacon|setItem)$/;
  const navigationPattern = /(?:^|\.)(?:navigate|navigateByUrl|goto|navigateTo)$|(?:router|location)\.(?:push|replace|assign)$/;
  const inputPattern = /(?:\.value$|\.get$|\.json$|\.text$)/;

  const values = (node, scope) => {
    if (!node) return [];
    if (node.type === "Identifier") return [bindingId(node, scope)];
    if (["CallExpression", "NewExpression", "OptionalCallExpression"].includes(node.type)) {
      return [make(node, nameOf(node.callee) || "call", "call")];
    }
    if (["MemberExpression", "OptionalMemberExpression"].includes(node.type)) {
      const name = nameOf(node);
      let root = node.object;
      while (root?.object) root = root.object;
      const declaration = root?.type === "Identifier" ? scope?.getBinding(root.name)?.identifier : undefined;
      const id = make(declaration || { start: 0, loc: node.loc }, name, "value", sourcePattern.test(name) || inputPattern.test(name) ? "source" : "");
      for (const value of values(node.object, scope)) edge(value, id, node, "READS_FROM");
      return [id];
    }
    if (["StringLiteral", "NumericLiteral", "BooleanLiteral", "NullLiteral"].includes(node.type)) return [];
    const result = [];
    for (const key of ["left", "right", "argument", "test", "consequent", "alternate", "value"]) {
      if (node[key]?.type) result.push(...values(node[key], scope));
    }
    for (const key of ["expressions", "elements", "properties"]) {
      for (const child of node[key] || []) result.push(...values(child, scope));
    }
    return [...new Set(result)];
  };
  const targets = (node, scope) => {
    if (!node) return [];
    if (node.type === "Identifier") return [bindingId(node, scope)];
    if (["ObjectPattern", "ArrayPattern"].includes(node.type)) {
      return (node.properties || node.elements).flatMap((item) => targets(item?.value || item?.argument || item, scope));
    }
    if (node.type === "AssignmentPattern") return targets(node.left, scope);
    return values(node, scope);
  };
  const reference = (url, kind, node, from, method = "GET", rule = "js.reference") => {
    if (typeof url === "string" && url) references.push({ url, kind, source: from, method, rule, location: location(node) });
    else gaps.add(`Unresolved ${kind.toLowerCase()} at ${location(node)}`);
  };

  let ast;
  try {
    const plugins = ["jsx", "decorators-legacy", "importAttributes"];
    if (/\.(?:ts|tsx)$/.test(cleanFilename) || /(?:lang[.=]|lang=)ts/.test(filename) || /<script[^>]+lang=["']ts["']/.test(templates[0] || "")) plugins.push("typescript");
    ast = parser.parse(source, { sourceType: "unambiguous", errorRecovery: true, plugins });
    for (const error of ast.errors) gaps.add(`Parse recovery: ${error.reasonCode}`);
  } catch (error) {
    return { nodes: [], edges: [], references: [], exports: [], gaps: [`Parse failed: ${error.reasonCode || error.name}`] };
  }

  try { traverse(ast, {
    enter(path) {
      currentPath = path;
      if (nodes.size >= LIMIT - 100) { gaps.add("JavaScript node budget reached"); path.stop(); }
    },
    Function(path) {
      const node = path.node;
      const identifier = node.id || (path.parentPath.isVariableDeclarator() ? path.parentPath.node.id : node);
      const id = identifier.type === "Identifier" ? bindingId(identifier, path.parentPath.scope) : make(node, "callback");
      const params = node.params.flatMap((param) => targets(param, path.scope));
      functions.set(id, { id, params, returns: make(node, "return", "return"), node, scope: path.scope });
    },
    ImportDeclaration(path) {
      const node = path.node;
      reference(node.source.value, "IMPORTS", node);
      for (const specifier of node.specifiers) {
        const id = bindingId(specifier.local, path.scope);
        nodes.get(id).import_url = node.source.value;
        nodes.get(id).imported_name = specifier.imported?.name || (specifier.type === "ImportDefaultSpecifier" ? "default" : "*");
      }
    },
    ExportNamedDeclaration(path) {
      const node = path.node;
      const declaration = node.declaration;
      if (declaration?.id) exports.push({ name: declaration.id.name, id: bindingId(declaration.id, path.scope) });
      for (const item of declaration?.declarations || []) {
        if (item.id.type === "Identifier") exports.push({ name: item.id.name, id: bindingId(item.id, path.scope) });
      }
      for (const item of node.specifiers) {
        exports.push({ name: item.exported.name, id: bindingId(item.local, path.scope) });
      }
      if (node.source) reference(node.source.value, "IMPORTS", node);
    },
    ExportDefaultDeclaration(path) {
      const node = path.node.declaration;
      const id = node.type === "Identifier" ? bindingId(node, path.scope) : make(node, "default");
      exports.push({ name: "default", id });
    },
    VariableDeclarator(path) {
      const node = path.node;
      for (const target of targets(node.id, path.scope)) {
        for (const value of values(node.init, path.scope)) edge(value, target, node);
      }
      if (node.id.type === "ArrayPattern" && /(?:^|\.)(?:useState|useReducer)$/.test(nameOf(node.init?.callee))) {
        const [state, setter] = node.id.elements;
        if (state?.type === "Identifier" && setter?.type === "Identifier") {
          states.set(bindingId(setter, path.scope), bindingId(state, path.scope));
        }
      }
    },
    AssignmentExpression(path) {
      const node = path.node;
      const left = nameOf(node.left);
      const sink = /\.(?:innerHTML|outerHTML|srcdoc)$/.test(left);
      const navigation = /(?:^|\.)(?:location|location\.href)$/.test(left);
      const target = sink || navigation ? make(node.left, left, "sink", "sink") : targets(node.left, path.scope)[0];
      for (const value of values(node.right, path.scope)) edge(value, target, node, "WRITES_TO");
      if (library && mode === "summary" && nodes.has(target) &&
          /^(?:exports\.|module\.exports)|(?:^|\.)(?:angular|React|ReactDOM)$/.test(left)) {
        exports.push({ name: left, id: target });
        if (node.right.type === "Identifier") exports.push({ name: left, id: bindingId(node.right, path.scope) });
      }
      if (navigation) reference(constant(node.right, path.scope), "NAVIGATES_TO", node, target);
    },
    ClassProperty(path) {
      const node = path.node;
      const id = make({ start: 0 }, `this.${nameOf(node.key)}`, "value");
      for (const value of values(node.value, path.scope)) edge(value, id, node);
    },
    ReturnStatement(path) {
      const fn = path.getFunctionParent();
      const summary = [...functions.values()].find((item) => item.node === fn?.node);
      if (summary) for (const value of values(path.node.argument, path.scope)) edge(value, summary.returns, path.node);
    },
    "CallExpression|NewExpression|OptionalCallExpression"(path) {
      const node = path.node;
      const name = nameOf(node.callee);
      const callee = node.callee.type === "Identifier" ? bindingId(node.callee, path.scope) : null;
      const call = make(node, name || "call", "call", sinkPattern.test(name) ? "sink" : "");
      const args = node.arguments || [];
      const inputs = args.map((arg) => values(arg, path.scope));
      calls.push({ node, callee, call, inputs });
      for (const input of inputs.flat()) edge(input, call, node, "CALL_ARGUMENT");
      if (node.callee.object) for (const input of values(node.callee.object, path.scope)) edge(input, call, node, "READS_FROM");
      if (sourcePattern.test(name) || /(?:\.getItem$|\.json$|\.text$|\.get$)/.test(name)) nodes.get(call).role = "source";
      if (/\.(?:querySelector|getElementById)$/.test(name)) {
        const selector = constant(args[0], path.scope);
        if (typeof selector === "string") nodes.get(call).selector = name.endsWith("getElementById") ? `#${selector}` : selector;
        else gaps.add("Dynamic DOM selector cannot be bound to captured HTML");
      }
      if (/createServerReference|createServerAction|\$\$ACTION/.test(name)) {
        nodes.get(call).role = "sink";
        gaps.add("Client-visible server action boundary; backend implementation unavailable");
      }
      if (["fetch", "$fetch", "useFetch"].includes(name) || /(?:^|\.)(?:axios|http|httpClient|\$http)\.(?:get|post|put|patch|delete|request)$/.test(name)
          || /(?:^\$\.ajax$|xhr\.open$)/.test(name)
          || ["WebSocket", "EventSource"].includes(name) || name.endsWith(".sendBeacon")) {
        const xhr = name.endsWith(".open");
        const options = args[1]?.properties || [];
        const methodNode = options.find((item) => nameOf(item.key) === "method");
        const method = xhr ? constant(args[0], path.scope) : constant(methodNode?.value, path.scope)
          || name.match(/\.(get|post|put|patch|delete)$/)?.[1]?.toUpperCase() || "GET";
        const url = constant(args[xhr ? 1 : 0], path.scope);
        if (name.endsWith(".ajax") && args[0]?.type === "ObjectExpression") {
          const option = args[0].properties.find((item) => nameOf(item.key) === "url");
          reference(constant(option?.value, path.scope), "REQUESTS", node, call, method, "js.http-client");
        } else if (name !== "URLSearchParams.get" && !/Storage\.get/.test(name)) {
          reference(url, "REQUESTS", node, call, method, "js.http-client");
        }
        nodes.get(call).role = "sink";
      }
      if (navigationPattern.test(name)) reference(constant(args[0], path.scope), "NAVIGATES_TO", node, call);
      if (name === "require" || node.callee.type === "Import") reference(constant(args[0], path.scope), "IMPORTS", node, call);
      if (/\.register$/.test(name) && name.includes("serviceWorker")) reference(constant(args[0], path.scope), "REGISTERS_WORKER", node, call);
      if (name === "Worker" || name === "SharedWorker") reference(constant(args[0], path.scope), "LOADS", node, call);
      if (name === "URL" && nameOf(args[1]) === "") reference(constant(args[0], path.scope), "RESOURCE_LINK", node, call);
      if (/\.glob$/.test(name)) gaps.add("Unexpanded import.meta.glob requires supplied transformed imports");
      if (/^(?:localStorage|sessionStorage)\.(?:getItem|setItem)$/.test(name)) {
        const key = constant(args[0], path.scope);
        if (typeof key === "string") {
          const storage = make({ start: 0 }, `${name.split('.')[0]}:${key}`, "storage");
          if (name.endsWith("getItem")) edge(storage, call, node, "READS_FROM", "js.storage");
          else edge(call, storage, node, "WRITES_TO", "js.storage");
        } else gaps.add("Dynamic storage key cannot be linked across scripts");
      }
      if (/\.addEventListener$|\.then$|\.subscribe$/.test(name)) {
        for (const arg of args) {
          const fn = [...functions.values()].find((item) => item.node === arg);
          if (fn) for (const parameter of fn.params) edge(call, parameter, node, "CALL_ARGUMENT", "js.callback");
        }
      }
      if (/^(?:encodeURI|encodeURIComponent|decodeURI|decodeURIComponent|String|Number|JSON\.stringify|JSON\.parse)$/.test(name)) {
        nodes.get(call).transformation = name;
      }
    },
    ObjectProperty(path) {
      const node = path.node;
      const key = nameOf(node.key);
      if (["path", "redirect", "redirectTo"].includes(key)) reference(constant(node.value, path.scope), "DECLARES_ROUTE", node);
      if (key === "template" && typeof constant(node.value, path.scope) === "string") templates.push(constant(node.value, path.scope));
    },
    JSXAttribute(path) {
      const node = path.node;
      const key = nameOf(node.name) || node.name.name;
      const value = node.value?.type === "JSXExpressionContainer" ? node.value.expression : node.value;
      if (["href", "to", "action", "formAction"].includes(key)) {
        reference(constant(value, path.scope), key.toLowerCase().includes("action") ? "SUBMITS_TO" : "NAVIGATES_TO", node);
      }
      if (["dangerouslySetInnerHTML", "srcDoc"].includes(key)) {
        const sink = make(node, key, "sink", "sink");
        for (const input of values(value, path.scope)) edge(input, sink, node, "WRITES_TO", "react.html");
      }
    },
  }); } catch (error) { gaps.add(`Traversal incomplete: ${error.name}`); }
  // Resolve calls after declarations, including declarations appearing after callers.
  for (const call of calls) {
    const summary = functions.get(call.callee);
    if (summary) {
      call.inputs.forEach((inputs, i) => inputs.forEach((input) => edge(input, summary.params[i], call.node, "CALL_ARGUMENT")));
      edge(summary.returns, call.call, call.node, "RETURNS_TO");
    }
    if (states.has(call.callee)) for (const input of call.inputs.flat()) edge(input, states.get(call.callee), call.node);
    if (/\.addEventListener$|\.then$|\.subscribe$/.test(nameOf(call.node.callee))) {
      for (const arg of call.node.arguments) {
        const fn = [...functions.values()].find((item) => item.node === arg);
        if (fn) for (const parameter of fn.params) edge(call.call, parameter, call.node, "CALL_ARGUMENT", "js.callback");
      }
    }
    const imported = nodes.get(call.callee);
    if (imported?.import_url) {
      call.inputs.forEach((inputs, index) => {
        const parameter = make(call.node, `${imported.imported_name}:argument:${index}`, "parameter");
        Object.assign(nodes.get(parameter), { import_url: imported.import_url, imported_name: imported.imported_name,
          parameter_index: index });
        for (const input of inputs) edge(input, parameter, call.node, "CALL_ARGUMENT");
      });
      Object.assign(nodes.get(call.call), { import_url: imported.import_url, imported_name: imported.imported_name,
        return_value: true });
    }
  }
  for (const item of exports) {
    if (!nodes.has(item.id)) continue;
    const tagExport = (node) => {
      node.export_names = [...new Set([...(node.export_names || []), item.name])];
      node.export_name = node.export_names[0];
    };
    tagExport(nodes.get(item.id));
    const summary = functions.get(item.id);
    if (summary) {
      summary.params.forEach((parameter, index) => {
        tagExport(nodes.get(parameter)); nodes.get(parameter).parameter_index = index;
      });
      tagExport(nodes.get(summary.returns)); nodes.get(summary.returns).return_value = true;
    }
  }
  for (const template of templates) {
    // Read framework template declarations without executing a compiler or evaluating expressions.
    const attributes = /([:@\w[\]().-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|\{([^}]+)\})/g;
    for (const match of template.matchAll(attributes)) {
      const key = match[1];
      const expression = match[2] ?? match[3] ?? match[4];
      const literal = expression.match(/^['"]([^'"]+)['"]$/)?.[1];
      const isNavigation = ["href", "to", ":to", "v-bind:to", "routerLink", "[routerLink]"].includes(key);
      if (isNavigation || ["action", ":action", "formaction"].includes(key)) {
        const plain = !key.startsWith(":") && !key.startsWith("[") && !key.startsWith("v-bind") && match[4] === undefined;
        reference(literal || (plain ? expression : undefined), isNavigation ? "NAVIGATES_TO" : "SUBMITS_TO",
          { start: match.index }, undefined, "GET", "framework.template");
      }
      if (["v-model", "bind:value", "[(ngModel)]"].includes(key)) {
        const input = make({ start: match.index }, key, "field", "source");
        for (const binding of nodes.values()) if ([expression, `this.${expression}`].includes(binding.name)) edge(input, binding.id, { start: match.index });
      }
      if (["v-html", "[innerHTML]"].includes(key)) {
        const sink = make({ start: match.index }, key, "sink", "sink");
        for (const binding of nodes.values()) if ([expression, `this.${expression}`].includes(binding.name)) edge(binding.id, sink, { start: match.index });
      }
    }
  }
  // Detect missing dynamic resolution without inventing a complete call graph.
  if (calls.some((item) => !item.callee || (!functions.has(item.callee) && !states.has(item.callee)))) {
    gaps.add("External/dynamic calls are conservative summaries; runtime dispatch is unproven");
  }
  const result = { nodes: [...nodes.values()], edges: [...edges.values()], references: references.slice(0, LIMIT),
    gaps: [...gaps], analysis: { mode: "full", library } };
  return library && mode === "summary" ? summarize(result, library) : result;
}

module.exports = { analyze };
if (require.main === module) {
  let input = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => { input += chunk; });
  process.stdin.on("end", () => {
    const request = JSON.parse(input);
    process.stdout.write(JSON.stringify(analyze(request.source, request.filename, request.mode)));
  });
}
