/* Recognize literal module registrations without running the bundle. */
function member(node, object, property) {
  return node?.type === "MemberExpression" && !node.computed &&
    node.object.name === object && node.property.name === property;
}

function registry(node) {
  if (node?.type === "AssignmentExpression" && node.operator === "=") return registry(node.left);
  if (node?.type === "LogicalExpression" && node.operator === "||") return registry(node.left);
  if (member(node, "self", "webpackChunk_N_E")) return "webpack";
  if (member(node, "globalThis", "TURBOPACK")) return "turbopack";
  return "";
}

function factory(node) {
  return node?.type === "FunctionExpression" || node?.type === "ArrowFunctionExpression" ||
    node?.type === "ObjectMethod";
}

function identifier(node) {
  return node?.type === "StringLiteral" || node?.type === "NumericLiteral" ? node.value : null;
}

function nextBundleModules(ast, gaps) {
  const modules = [];
  function add(id, node, bundler) {
    if (id === null || !factory(node)) return;
    if (modules.length >= 1000) {
      gaps.add("Next.js module registration budget reached");
      return;
    }
    modules.push({ id, bundler, location: `${node.loc.start.line}:${node.loc.start.column}` });
  }
  for (const statement of ast.program.body) {
    const call = statement.expression;
    const callee = call?.callee;
    if (call?.type !== "CallExpression" || callee?.computed || callee?.property?.name !== "push") continue;
    const bundler = registry(callee.object);
    const items = call.arguments[0]?.elements;
    if (!bundler || !items) continue;
    if (bundler === "webpack") {
      for (const property of items[1]?.properties || []) {
        if (!property.computed) add(identifier(property.key), property.value || property, bundler);
      }
    } else {
      let ids = [];
      for (const item of items.slice(1)) {
        const id = identifier(item);
        if (id !== null) {
          ids.push(id);
        } else {
          for (const current of ids) add(current, item, bundler);
          ids = [];
        }
      }
    }
  }
  return modules;
}

function nextManifestChunks(ast) {
  const chunks = [];
  const expressions = ast.program.body.flatMap(({ expression }) =>
    expression?.type === "SequenceExpression" ? expression.expressions : [expression]);
  for (const expression of expressions) {
    if (expression?.type !== "AssignmentExpression" || expression.operator !== "=") continue;
    const bootstrap = member(expression.left, "self", "__TURBOPACK_PAGE_BOOTSTRAP");
    if (!bootstrap && !member(expression.left, "self", "__BUILD_MANIFEST")) continue;
    let object = expression.right;
    const aliases = new Map();
    if (!bootstrap && object.type === "CallExpression") {
      const { callee, arguments: args } = object;
      if (callee.type !== "FunctionExpression" && callee.type !== "ArrowFunctionExpression") continue;
      if (callee.params.some((param) => param.type !== "Identifier")) continue;
      callee.params.forEach((param, index) => aliases.set(param.name, identifier(args[index])));
      object = callee.body;
      if (object.type === "BlockStatement") {
        if (object.body.length !== 1 || object.body[0].type !== "ReturnStatement") continue;
        object = object.body[0].argument;
      }
    }
    if (object?.type !== "ObjectExpression") continue;
    for (const entry of object.properties) {
      if (entry.type !== "ObjectProperty" || entry.computed || entry.key.type !== "StringLiteral" ||
          !entry.key.value.startsWith("/")) continue;
      let assets = entry.value;
      if (bootstrap) {
        if (assets.type !== "ObjectExpression") continue;
        assets = assets.properties.find((property) => property.type === "ObjectProperty" && !property.computed &&
          (property.key.name || property.key.value) === "otherChunks")?.value;
      }
      if (assets?.type !== "ArrayExpression") continue;
      for (const item of assets.elements) {
        const chunk = item?.type === "Identifier" ? aliases.get(item.name) : identifier(item);
        if (typeof chunk === "string") chunks.push([entry.key.value, chunk]);
      }
    }
  }
  return chunks;
}

module.exports = { nextBundleModules, nextManifestChunks };
