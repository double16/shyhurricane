import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";

const { FIXTURE_CHROME, FIXTURE_PORT = "3930" } = process.env;
if (!FIXTURE_CHROME) throw new Error("Set FIXTURE_CHROME to the Chromium executable.");
const origin = `http://127.0.0.1:${FIXTURE_PORT}`;
const server = spawn(process.execPath, [
  fileURLToPath(new URL("./node_modules/next/dist/bin/next", import.meta.url)),
  "start", "--hostname", "127.0.0.1", "--port", FIXTURE_PORT,
], {
  cwd: fileURLToPath(new URL(".", import.meta.url)),
  env: { ...process.env, NEXT_TELEMETRY_DISABLED: "1" },
  stdio: ["ignore", 2, 2],
});
let browser;


try {
  let listening = false;
  for (let attempt = 0; attempt < 50 && server.exitCode === null; attempt++) {
    if (await fetch(origin).then(response => response.ok).catch(() => false)) {
      listening = true;
      break;
    }
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  if (!listening) throw new Error("The local fixture server did not become ready.");
  browser = await chromium.launch({ executablePath: FIXTURE_CHROME });
  const page = await browser.newPage();
  const captures = [];
  page.on("response", (response) => {
    if (new URL(response.url()).origin !== origin) return;
    const request = response.request();
    const timestamp = new Date().toISOString();
    captures.push((async () => {
      const responseBody = response.status() >= 300 && response.status() < 400 ? "" :
        await response.text().catch(error => {
          if (!error.message.includes("No resource with given identifier found")) throw error;
          process.stderr.write(`Response body unavailable for ${new URL(response.url()).pathname}\n`);
          return null;
        });
      const responseHeaders = await response.allHeaders();
      const requestHeaders = await request.allHeaders();
      return {
        url: response.url().replace(origin, "https://example.com"),
        method: request.method(),
        timestamp,
        request_headers: requestHeaders,
        response_headers: responseHeaders,
        response_code: response.status(),
        response_body: responseBody,
        request_body: request.postData(),
      };
    })().catch(error => ({ error })));
  });

  await page.goto(origin);
  await page.getByRole("button", { name: "Show details" }).click();
  await page.getByText("Lazy details").waitFor();
  const posted = () => page.waitForResponse(response => response.request().method() === "POST");
  await Promise.all([posted(), page.getByRole("button", { name: "Preview" }).click()]);
  await page.getByText("example", { exact: true }).waitFor();
  await page.locator("input[name=label]").fill("fixture");
  await Promise.all([posted(), page.getByRole("button", { name: "Save" }).click()]);
  await page.waitForLoadState("networkidle");
  await Promise.all(captures);
  await page.getByRole("link", { name: "Example item" }).click();
  await page.waitForURL("**/items/example");
  await page.waitForLoadState("networkidle");

  const recorded = await Promise.all(captures);
  if (!recorded.some(capture => capture.url === "https://example.com/" &&
      capture.method === "GET" && capture.response_body?.includes("Example item"))) {
    throw new Error("The initial App Router page body was not recorded.");
  }
  if (recorded.filter(capture => capture.method === "POST" && capture.response_body &&
      capture.request_headers["next-action"]).length !== 2) {
    throw new Error("Expected two complete Server Action exchanges.");
  }
  for (const capture of recorded) {
    if (capture.error) throw capture.error;
    for (const headers of [capture.request_headers, capture.response_headers]) {
      for (const name of ["origin", "referer", "location"]) {
        if (headers[name]) headers[name] = headers[name].replace(origin, "https://example.com");
      }
    }
    process.stdout.write(JSON.stringify(capture) + "\n");
  }
} finally {
  server.kill();
  await browser?.close();
}
