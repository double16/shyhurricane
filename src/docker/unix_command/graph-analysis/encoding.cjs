/* Strict, parse-gated repair of UTF-8 decoded as Latin-1. Never executes source. */
function prepareSource(source, parse) {
  let original;
  try {
    return { source, ast: parse(source) };
  } catch (error) {
    original = error;
  }
  if (original.reasonCode !== "InvalidOrUnexpectedToken") throw original;
  if ([...source].some((char) => char.codePointAt(0) > 255)) throw original;
  let repaired;
  try {
    repaired = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(Buffer.from(source, "latin1"));
  } catch {
    throw original;
  }
  if (Buffer.from(repaired, "utf8").toString("latin1") !== source || repaired === source) throw original;
  let ast;
  try {
    ast = parse(repaired);
  } catch {
    throw original;
  }
  if (ast.errors.length) throw original;
  return { source: repaired, ast, transformation: "latin1-to-utf8-v1" };
}
module.exports = { prepareSource };
