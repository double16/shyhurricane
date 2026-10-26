/* Parse captured artifacts only. No target code is evaluated or imported. */
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;

const { compress } = require("./library.cjs");

function analyze(source, filename = "source.js", mode = "summary") {
  if (!["summary", "full"].includes(mode)) throw new Error("Invalid library analysis mode");
  const LIMIT = 50000;
  const nodes = new Map();
  const edges = new Map();
  const references = [];
  const gaps = new Set();
  const functions = new Map();
  const functionNodes = new Map();
  const calls = [];
  const states = new Map();
  const exports = [];
  const aliases = [];
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
    // Chained calls share a start offset; include their end to keep distinct operations separate.
    const end = ["call", "result", "rejection"].includes(kind) && node?.end !== undefined ? `:${node.end}` : "";
    const id = `${kind}:${node?.start ?? 0}:${name}${end}`;
    if (!nodes.has(id)) nodes.set(id, { id, name, kind, role, location: location(node),
      snippet: node?.end === undefined ? "" : source.slice(node.start, Math.min(node.end, node.start + 300)) });
    else if (role) nodes.get(id).role = role;
    return id;
  };
  const edge = (from, to, node, kind = "FLOWS_TO", rule = "js.def-use") => {
    if (!from || !to || from === to) return;
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
  const sourcePattern = /^(?:window\.)?(?:location\.(?:search|hash|href)|document\.cookie|(?:localStorage|sessionStorage)\.getItem|.*(?:target|currentTarget)\.value|.*\.data)$/;
  const sinkPattern = /(?:^|\.)(?:eval|Function|setTimeout|setInterval|write|writeln|insertAdjacentHTML|postMessage|send|sendBeacon|setItem)$/;
  const navigationPattern = /(?:^|\.)(?:navigate|navigateByUrl|goto|navigateTo)$|(?:router|location)\.(?:push|replace|assign)$/;
  const inputPattern = /\.value$/;

  const values = (node, scope) => {
    if (!node) return [];
    if (node.type === "AwaitExpression") return values(node.argument, scope);
    if (node.type === "ThisExpression") return [make(node, "this", "value")];
    if (node.type === "Identifier") return [bindingId(node, scope)];
    if (["CallExpression", "NewExpression", "OptionalCallExpression"].includes(node.type)) {
      return [make(node, nameOf(node.callee) || "call", "result")];
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
    for (const key of ["left", "right", "argument", "consequent", "alternate", "value"]) {
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
      // Discovery is independent of materialization quotas; the parser worker enforces resource limits.
    },
    Function(path) {
      const node = path.node;
      const identifier = node.id || (path.parentPath.isVariableDeclarator() ? path.parentPath.node.id : node);
      const id = identifier.type === "Identifier" ? bindingId(identifier, path.parentPath.scope) : make(node, "callback");
      const params = node.params.flatMap((param) => targets(param, path.scope));
      const summary = { id, params, returns: make(node, "return", "return"),
        rejects: make(node, "throw", "rejection"), node, scope: path.scope, expressions: [] };
      functions.set(id, summary);
      functionNodes.set(node, summary);
      if (node.body.type !== "BlockStatement") {
        summary.expressions.push(node.body);
        for (const value of values(node.body, path.scope)) edge(value, summary.returns, node.body);
      }
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
        if (node.source) {
          const id = make(item, item.exported.name, "symbol");
          Object.assign(nodes.get(id), { import_url: node.source.value, imported_name: item.local.name,
            reexport_name: item.exported.name });
        } else exports.push({ name: item.exported.name, id: bindingId(item.local, path.scope) });
      }
      if (node.source) reference(node.source.value, "IMPORTS", node);
    },
    ExportDefaultDeclaration(path) {
      const node = path.node.declaration;
      const id = node.type === "Identifier" ? bindingId(node, path.scope) : make(node, "default");
      exports.push({ name: "default", id, start: node.start });
    },
    VariableDeclarator(path) {
      const node = path.node;
      if (node.id.type === "Identifier") aliases.push({ id: bindingId(node.id, path.scope), node: node.init, scope: path.scope });
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
      if (nodes.has(target) &&
          /^(?:exports\.|module\.exports(?:\.|$)|(?:globalThis|window|self)\.)/.test(left)) {
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
      const summary = functionNodes.get(fn?.node);
      if (summary) {
        summary.expressions.push(path.node.argument);
        for (const value of values(path.node.argument, path.scope)) edge(value, summary.returns, path.node);
      }
    },
    ThrowStatement(path) {
      const summary = functionNodes.get(path.getFunctionParent()?.node);
      if (summary) for (const value of values(path.node.argument, path.scope)) edge(value, summary.rejects, path.node);
    },
    "CallExpression|NewExpression|OptionalCallExpression"(path) {
      const node = path.node;
      const name = nameOf(node.callee);
      const callee = node.callee.type === "Identifier" ? bindingId(node.callee, path.scope) : null;
      const call = make(node, name || "call", "call", sinkPattern.test(name) ? "sink" : "");
      const args = node.arguments || [];
      const inputs = args.map((arg) => values(arg, path.scope));
      const result = make(node, name || "call", "result");
      calls.push({ node, callee, call, result, inputs, scope: path.scope });
      for (const input of inputs.flat()) edge(input, call, node, "CALL_ARGUMENT");
      if (node.callee.object) for (const input of values(node.callee.object, path.scope)) edge(input, call, node, "READS_FROM");
      if (sourcePattern.test(name)) nodes.get(result).role = "source";
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
  // Resolve lexical aliases without joining shadowed or reassigned bindings.
  const resolve = (node, scope, seen = new Set()) => {
    if (node?.type !== "Identifier") return { node, scope };
    const binding = scope?.getBinding(node.name);
    if (!binding || !binding.constant || seen.has(binding)) return { node, scope };
    seen.add(binding);
    if (binding.path.isVariableDeclarator()) return resolve(binding.path.node.init, binding.path.scope, seen);
    return { node: binding.path.node, scope: binding.path.scope };
  };
  const fnFor = (node, scope) => functionNodes.get(resolve(node, scope).node);
  const method = (node) => node?.computed ? constant(node.property) : node?.property?.name;
  const global = (node, scope, name) => nameOf(node) === name && !scope?.getBinding(name.split(".")[0]);
  const callbackReceivers = new Map();
  for (const call of calls) {
    if (method(call.node.callee) !== "then") continue;
    const fn = fnFor(call.node.arguments[0], call.scope);
    if (fn) {
      if (!callbackReceivers.has(fn.node)) callbackReceivers.set(fn.node, []);
      callbackReceivers.get(fn.node).push(call);
    }
  }
  let inferenceSteps = 0;
  const typeOf = (node, scope, seen = new Set()) => {
    if (!node || seen.has(node)) return "";
    if (++inferenceSteps > LIMIT * 20) { gaps.add("JavaScript type resolution budget reached"); return ""; }
    seen = new Set(seen).add(node);
    if (node.type === "Identifier") {
      const binding = scope?.getBinding(node.name);
      if (!binding) return "";
      if (binding.kind === "param") {
        const fn = binding.path.getFunctionParent();
        for (const call of callbackReceivers.get(fn?.node) || []) {
          const receiver = typeOf(call.node.callee.object, call.scope, seen);
          if (receiver === "promise:response") return "response";
        }
      }
      const resolved = resolve(node, scope);
      return resolved.node !== node ? typeOf(resolved.node, resolved.scope, seen) : "";
    }
    if (node.type === "AwaitExpression") return typeOf(node.argument, scope, seen).replace(/^promise:/, "");
    if (["CallExpression", "OptionalCallExpression", "NewExpression"].includes(node.type)) {
      const name = nameOf(node.callee), member = method(node.callee);
      if (global(node.callee, scope, "fetch")) return "promise:response";
      if (global(node.callee, scope, "XMLHttpRequest")) return "xhr";
      if (global(node.callee, scope, "FormData")) return "formdata";
      if (global(node.callee, scope, "URLSearchParams")) return "params";
      if (global(node.callee, scope, "Promise.resolve")) return `promise:${typeOf(node.arguments[0], scope, seen).replace(/^promise:/, "") || "value"}`;
      if (global(node.callee, scope, "Promise.reject")) return "promise:value";
      const receiver = typeOf(node.callee.object, scope, seen);
      if (receiver === "response" && ["text", "json", "blob", "arrayBuffer", "formData"].includes(member)) return "promise:value";
      if (receiver.startsWith("promise:") && ["then", "catch", "finally"].includes(member)) {
        if (member === "finally" || absentHandler(node.arguments[0], scope)) return receiver;
        const fn = fnFor(node.arguments[0], scope);
        const output = fn?.expressions.map((expression) => typeOf(expression, fn.scope, seen)).find(Boolean);
        if (member === "catch" && receiver === "promise:response") return receiver;
        return output?.startsWith("promise:") ? output : `promise:${output || "value"}`;
      }
      const fn = fnFor(node.callee, scope);
      if (fn) {
        const output = fn.expressions.map((expression) => typeOf(expression, fn.scope, seen)).find(Boolean) || "value";
        return fn.node.async && !output.startsWith("promise:") ? `promise:${output}` : output;
      }
    }
    return "";
  };
  const rejected = (node, scope, seen = new Set()) => {
    if (!node || seen.has(node)) return [];
    if (node.type === "AwaitExpression") return rejected(node.argument, scope, seen);
    seen.add(node);
    const resolved = resolve(node, scope);
    if (resolved.node !== node) return rejected(resolved.node, resolved.scope, seen);
    if (["CallExpression", "OptionalCallExpression"].includes(node.type)) return [make(node, "rejected", "rejection")];
    return [];
  };
  const importedFor = (node, scope) => {
    const resolved = resolve(node, scope);
    node = resolved.node; scope = resolved.scope;
    if (node?.type === "ImportSpecifier" || node?.type === "ImportDefaultSpecifier") {
      return nodes.get(bindingId(node.local, scope));
    }
    if (node?.type === "MemberExpression" && node.object.type === "Identifier") {
      const imported = nodes.get(bindingId(node.object, scope));
      if (imported?.imported_name === "*" && typeof method(node) === "string") {
        return { ...imported, imported_name: method(node) };
      }
    }
    if (node?.type === "Identifier") return nodes.get(bindingId(node, scope));
    return undefined;
  };
  const absentHandler = (node, scope) => !node || ["NullLiteral", "StringLiteral", "NumericLiteral", "BooleanLiteral"].includes(node.type)
    || global(node, scope, "undefined");
  const requestCalls = new Set(references.filter(item => item.kind === "REQUESTS").map(item => item.source));
  // Call invocation nodes retain arguments for sink evidence. Result nodes contain only return values.
  for (const call of calls) {
    const { node, scope, result } = call;
    const name = nameOf(node.callee), member = method(node.callee);
    const summary = fnFor(node.callee, scope);
    // Mark resolved callback boundaries without inventing invocation or dispatch edges.
    for (const argument of node.arguments) {
      const callback = fnFor(argument, scope);
      if (callback) for (const id of [...callback.params, callback.returns, callback.rejects]) {
        if (nodes.has(id)) nodes.get(id).callback_boundary = true;
      }
    }
    const receiverType = typeOf(node.callee.object, scope);
    const isPromise = receiverType.startsWith("promise:") && ["then", "catch", "finally"].includes(member);
    const isNetwork = global(node.callee, scope, "fetch") || receiverType === "xhr" && ["open", "send"].includes(member)
      || requestCalls.has(call.call);
    if (receiverType === "xhr" && member === "open" && name !== "xhr.open") {
      reference(constant(node.arguments[1], scope), "REQUESTS", node, call.call, constant(node.arguments[0], scope), "js.xhr");
    }
    const reader = receiverType === "response" && ["text", "json", "blob", "arrayBuffer", "formData"].includes(member);
    const imported = importedFor(node.callee, scope);
    if (summary) {
      call.inputs.forEach((inputs, i) => inputs.forEach((input) => edge(input, summary.params[i], node, "CALL_ARGUMENT")));
      edge(summary.returns, result, node, "RETURNS_TO");
      edge(summary.rejects, make(node, "rejected", "rejection"), node, "RETURNS_TO");
    } else if (isPromise) {
      const fulfillment = values(node.callee.object, scope);
      const failure = rejected(node.callee.object, scope);
      const outputFailure = make(node, "rejected", "rejection");
      const handlers = member === "then" ? [node.arguments[0], node.arguments[1]]
        : member === "catch" ? [null, node.arguments[0]] : [null, null];
      for (let index = 0; index < 2; index += 1) {
        const handler = fnFor(handlers[index], scope);
        const inputs = index === 0 ? fulfillment : failure;
        if (handler) {
          for (const input of inputs) edge(input, handler.params[0], node, "CALL_ARGUMENT", "js.callback");
          edge(handler.returns, result, node, "RETURNS_TO", "js.promise-return");
          edge(handler.rejects, outputFailure, node, "RETURNS_TO", "js.promise-rejection");
          for (const expression of handler.expressions) for (const value of rejected(expression, handler.scope)) {
            edge(value, outputFailure, node, "RETURNS_TO", "js.promise-rejection");
          }
        } else if (absentHandler(handlers[index], scope)) {
          for (const input of inputs) edge(input, index === 0 ? result : outputFailure, node, "FLOWS_TO", "js.promise-pass");
        } else gaps.add(`Unresolved Promise handler at ${location(node)}`);
      }
      if (member === "finally") {
        const handler = fnFor(node.arguments[0], scope);
        if (handler) {
          edge(handler.rejects, outputFailure, node, "RETURNS_TO", "js.promise-rejection");
          for (const expression of handler.expressions) for (const value of rejected(expression, handler.scope)) {
            edge(value, outputFailure, node, "RETURNS_TO", "js.promise-rejection");
          }
        } else if (!absentHandler(node.arguments[0], scope)) gaps.add(`Unresolved Promise handler at ${location(node)}`);
      }
    } else if (global(node.callee, scope, "Promise.resolve") || global(node.callee, scope, "Promise.reject")) {
      const target = name.endsWith("reject") ? make(node, "rejected", "rejection") : result;
      for (const input of call.inputs[0] || []) edge(input, target, node, "FLOWS_TO", "js.promise-value");
      if (name.endsWith("resolve")) for (const input of rejected(node.arguments[0], scope)) {
        edge(input, make(node, "rejected", "rejection"), node, "FLOWS_TO", "js.promise-rejection");
      }
    } else if (reader) {
      nodes.get(result).role = "source";
    } else if (!isNetwork && !imported?.import_url) {
      // Unknown calls remain conservative summaries, explicitly identified in analysis gaps.
      edge(call.call, result, node, "RETURNS_TO", "js.external-summary");
      if (["then", "catch", "finally"].includes(member)) gaps.add(`Unresolved Promise receiver at ${location(node)}`);
    }
    if (isNetwork) nodes.get(call.call).role = "sink";
    if (states.has(call.callee)) for (const input of call.inputs.flat()) edge(input, states.get(call.callee), node);
    if (["addEventListener", "subscribe"].includes(member)) {
      for (const arg of node.arguments) {
        const fn = fnFor(arg, scope);
        if (fn) edge(call.call, fn.params[0], node, "CALL_ARGUMENT", "js.callback");
      }
    }
    if (imported?.import_url && imported.imported_name !== "*") {
      call.inputs.forEach((inputs, index) => {
        const parameter = make(node, `${imported.imported_name}:argument:${index}`, "parameter");
        Object.assign(nodes.get(parameter), { import_url: imported.import_url, imported_name: imported.imported_name,
          parameter_index: index });
        for (const input of inputs) edge(input, parameter, node, "CALL_ARGUMENT");
      });
      Object.assign(nodes.get(result), { import_url: imported.import_url, imported_name: imported.imported_name,
        return_value: true });
    }
  }
  // Response properties are sources only on a statically recognized XHR instance.
  traverse(ast, {
    AwaitExpression(path) {
      const fn = functionNodes.get(path.getFunctionParent()?.node);
      if (fn) for (const value of rejected(path.node.argument, path.scope)) {
        edge(value, fn.rejects, path.node, "RETURNS_TO", "js.await-rejection");
      }
    },
    MemberExpression(path) {
      if (["response", "responseText", "responseXML"].includes(method(path.node)) && typeOf(path.node.object, path.scope) === "xhr") {
        for (const id of values(path.node, path.scope)) nodes.get(id).role = "source";
      }
    },
  });
  for (const call of calls) {
    if (typeOf(call.node, call.scope).startsWith("promise:")) {
      const fn = fnFor(call.node.callee, call.scope);
      if (fn) for (const expression of fn.expressions) for (const value of rejected(expression, fn.scope)) {
        edge(value, make(call.node, "rejected", "rejection"), call.node, "RETURNS_TO", "js.promise-rejection");
      }
    }
  }
  // Associate form expressions with their lexical submit handler, never with unrelated documents.
  const formHandlers = new Map();
  for (const call of calls) {
    if (method(call.node.callee) === "addEventListener" && constant(call.node.arguments[0], call.scope) === "submit") {
      const fn = fnFor(call.node.arguments[1], call.scope);
      if (fn) formHandlers.set(fn.node, { node: call.node.callee.object, scope: call.scope, fn });
    }
  }
  const formSelector = (node, scope, seen = new Set()) => {
    if (!node || seen.has(node)) return undefined;
    seen.add(node);
    const resolved = resolve(node, scope);
    if (resolved.node !== node) return formSelector(resolved.node, resolved.scope, seen);
    const enclosing = scope?.getFunctionParent()?.path;
    const handler = formHandlers.get(enclosing?.node);
    if (node.type === "ThisExpression" && handler && handler.fn.node.type !== "ArrowFunctionExpression") {
      return formSelector(handler.node, handler.scope, seen);
    }
    if (node.type === "MemberExpression" && method(node) === "currentTarget" && handler && node.object.type === "Identifier"
        && handler.fn.params[0] === bindingId(node.object, scope)) {
      return formSelector(handler.node, handler.scope, seen);
    }
    if (node.type === "CallExpression" && ["getElementById", "querySelector"].includes(method(node.callee))
        && global(node.callee.object, scope, "document")) {
      const selector = constant(node.arguments[0], scope);
      if (typeof selector === "string") return method(node.callee) === "getElementById" ? `#${selector}` : selector;
    }
    return undefined;
  };
  for (const call of calls) {
    const { node, scope } = call;
    const member = method(node.callee);
    if (global(node.callee, scope, "FormData")) {
      const selector = formSelector(node.arguments[0], scope);
      if (selector) Object.assign(nodes.get(call.result), { selector, form_data: true });
      else gaps.add(`Unresolved FormData form at ${location(node)}`);
    }
    if (member === "getAttribute" && ["action", "method"].includes(constant(node.arguments[0], scope))) {
      const selector = formSelector(node.callee.object, scope);
      if (selector) Object.assign(nodes.get(call.result), { selector, form_attribute: constant(node.arguments[0], scope) });
    }
    if (["get", "getAll"].includes(member) && typeOf(node.callee.object, scope) === "formdata") {
      const resolved = resolve(node.callee.object, scope);
      const selector = formSelector(resolved.node.arguments[0], resolved.scope);
      const field = constant(node.arguments[0], scope);
      // A named read depends on the selected field, not every field in the aggregate.
      for (const [id, item] of edges) {
        if (item.target === call.call && item.kind === "READS_FROM" || item.source === call.call && item.target === call.result) edges.delete(id);
      }
      if (selector && typeof field === "string") Object.assign(nodes.get(call.result), { selector, form_data: true, form_field: field });
      else gaps.add(`Unresolved FormData field at ${location(node)}`);
    }
  }
  const predecessors = new Map();
  for (const item of edges.values()) {
    if (!predecessors.has(item.target)) predecessors.set(item.target, []);
    predecessors.get(item.target).push(item.source);
  }
  const attributes = (seeds, attribute) => {
    const pending = [...seeds], seen = new Set(), found = new Set();
    while (pending.length && seen.size < LIMIT) {
      const id = pending.pop();
      if (seen.has(id)) continue;
      seen.add(id);
      const item = nodes.get(id);
      if (item?.form_attribute === attribute) found.add(item.selector);
      pending.push(...predecessors.get(id) || []);
    }
    if (pending.length) gaps.add("Form binding resolution budget reached");
    return found.size === 1 ? [...found][0] : undefined;
  };
  for (const call of calls) {
    if (!global(call.node.callee, call.scope, "fetch")) continue;
    const selector = attributes(call.inputs[0] || [], "action");
    const options = call.node.arguments[1]?.properties || [];
    const methodNode = options.find((item) => nameOf(item.key) === "method");
    const methodSelector = attributes(values(methodNode?.value, call.scope), "method");
    if (selector && selector === methodSelector) {
      Object.assign(nodes.get(call.call), { selector, form_request: true });
      gaps.delete(`Unresolved requests at ${location(call.node)}`);
    }
  }
  for (const alias of aliases) {
    const fn = fnFor(alias.node, alias.scope);
    if (fn) functions.set(alias.id, fn);
    const imported = importedFor(alias.node, alias.scope);
    if (imported?.import_url) Object.assign(nodes.get(alias.id), {
      import_url: imported.import_url, imported_name: imported.imported_name,
    });
  }
  for (const item of exports) {
    if (!nodes.has(item.id)) continue;
    const tagExport = (node) => {
      node.export_names = [...new Set([...(node.export_names || []), item.name])];
      node.export_name = node.export_names[0];
    };
    tagExport(nodes.get(item.id));
    const binding = nodes.get(item.id);
    const summary = functions.get(item.id) || [...functionNodes.values()].find((fn) => fn.node.start === item.start);
    if (binding.import_url) binding.reexport_name = item.name;
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
  const result = { nodes: [...nodes.values()], edges: [...edges.values()], references,
    gaps: [...gaps], analysis: { mode: "full" } };
  return compress(result, mode);
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
