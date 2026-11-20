# Next.js browser capture fixture

This local app exercises a Pages Router dynamic route, an App Router page, a lazy client
component, and form and imperative Server Actions. Graph input comes from browser-recorded
HTTP exchanges. The app source provides fixture ground truth.

Run from the repository root with Node.js 20.9 or later and a local Chromium installation:

```sh
npm --prefix tests/fixtures/next-client ci --ignore-scripts
FIXTURE_CHROME=/path/to/chromium bash tests/fixtures/next-client/record-matrix.sh /tmp/next-captures
```

| Environment variable | Default | Description |
|----------------------|---------|-------------|
| `FIXTURE_CHROME` | Required | Path to a local Chromium executable |
| `FIXTURE_PORT` | `3930` | Loopback port for the fixture server |
| `FIXTURE_BROWSER_MAPS` | `0` | Build with browser source maps when set to `1`. The matrix runner sets both values. |

The runner builds Webpack and Turbopack with browser source maps off and on. Each JSONL file
contains browser observations in the graph capture format, with the fixture origin rewritten to
`https://example.com`. Chromium can discard a response body when navigation cancels a prefetch.
The recorder retains the exchange metadata and reports that case on stderr. It requires the
initial HTML and both action exchanges to have complete bodies.

Expected graph evidence includes the link to `/items/example`, dependencies on browser chunks,
and two observed action requests with distinct capture-local identities. An action request on
the same route does not establish a link to another capture or a client module.
