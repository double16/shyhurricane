## Critical rules the agent must follow before doing anything
- Read `README.md` and `CONTRIBUTING.md` before acting.
- Update `CHANGELOG.md` for user-facing changes. Categorize using `### Features` and `### Fixes`.

## Testing and contribution
- Always write unit tests and check that they pass for new and changed business logic.
- Changed and new code should have at least 80% code and branch coverage per file.
- Run unit tests for changes to executable behavior.
- Static prompt text and documentation-only changes are exempt from unit tests and coverage requirements.
  Do not add or run tests that merely assert prompt wording.
- Test both positive and negative scenarios.
- Keep tests in files based on component or functionality. Use existing test files if applicable.

## Explicit prohibitions what agents must NOT do
- Do not bump major versions of core dependencies without a dedicated PR and discussion.
- Do not rename files without a valid technical reason.
- Never include target information (domain, urls, ...) from deployments in tests, documentation
  or MCP instructions and prompts. Use "target.local" or "example.com" as example domains.

## Documentation
- Keep documentation up-to-date and accurate.
- Use clear language.
- Follow a consistent style and format for documentation.
- Use examples and diagrams to illustrate concepts.
- Keep general user documentation in README.md. In-depth documentation in docs/.
- Environment variables used for configuration must be documented in a table along-side similar variables.

## Storage architecture and expected load
- Prefer Neo4j for graph operations: relationships, traversal, searchable graph inventory, document membership,
  and graph coverage. Prefer SQLite for relational data: queues, scheduling, checkpoints, transactional ownership,
  publication obligations, and artifact metadata. Choose exceptions using measured workloads and document the reason.
- Keep payload storage separate from graph query semantics. Small compressed payloads may remain inline in SQLite;
  larger payloads should share packed segments. Avoid a file per fact or small artifact: filesystem entry overhead
  was a production bottleneck.
- Use the retained production-derived JavaScript IR case as a minimum large-input performance fixture:
  **171,175 nodes, 146,817 edges, and 70,862,815 bytes (approximately 67.6 MiB) of uncompressed JSON IR**.
  These counts describe one analyzed input, not the entire assessment, original JavaScript size, or physical
  Neo4j storage. An assessment can contain many such inputs, capture versions, contexts, and retained generations;
  do not treat these figures as an assessment-wide upper bound. A verified whole-assessment estimate is unavailable.
- Design writes, reads, retries, accounting, and cleanup for bounded batches and memory at this scale and above.
  Validate indexes and query plans with unrelated data present; avoid per-fact payload bookkeeping and full-catalog
  scans on normal request or maintenance paths. Include payload, index, WAL, transaction-log, and retention overhead
  when estimating disk requirements; serialized IR size alone is not a capacity estimate.
- See [graph storage implementation and validation](docs/graph-storage-implementation.md) for benchmark methodology,
  storage boundaries, and measured performance tradeoffs. Keep deployment identifiers out of fixtures and guidance.

## Python Best Practices
- Use the `uv` tool for python ecosystem, i.e `uv run ...`
- Follow PEP 8 with a 120-character line limit
- Run `uv run ruff` on new or changed files to validate Python coding standards
- Use double quotes for Python strings
- Sort imports with `isort`
- Use f-strings for string formatting
- If a class member is set in __init__, do not use getattr(), use direct reference.
- For multi-line strings, use triple quotes and limit each line to 100 characters.

### uv in the sandbox
- Configure `uv` to use the persistent project-local `.uv-cache` directory. The default user cache may be outside the
  sandbox's writable paths and can cause `uv` to fail before Python starts.
- From the repository root, initialize and synchronize the environment with:

  ```bash
  mkdir -p .uv-cache
  UV_CACHE_DIR="$PWD/.uv-cache" uv sync --all-extras
  ```

- Prefix subsequent `uv` commands with the same cache setting. Use the repository's `.venv` through `uv run`; do not
  activate a different virtual environment or invoke tools from a system Python.
- When running coverage or tests that import NumPy on macOS, also set `KMP_DUPLICATE_LIB_OK=TRUE` to avoid the
  duplicate OpenMP-library import error.
- Examples:

  ```bash
  UV_CACHE_DIR="$PWD/.uv-cache" uv run python3 --version
  KMP_DUPLICATE_LIB_OK=TRUE UV_CACHE_DIR="$PWD/.uv-cache" uv run pytest -q --tb=short
  UV_CACHE_DIR="$PWD/.uv-cache" uv run ruff check src tests
  # Use the repository coverage entry point. It configures pytest-cov correctly.
  UV_CACHE_DIR="$PWD/.uv-cache" uv run ./.github/scripts/run-python-coverage.sh
  # Run after coverage is collected, it reports files that do not pass the python coverage floor.
  UV_CACHE_DIR="$PWD/.uv-cache" uv run ./.github/scripts/check-python-coverage-floor.py coverage.json
  ```

- If `.uv-cache` is not present, create it before running commands. Keep it project-local and persistent between agent
  turns; do not use a temporary directory unless the project-local path is unavailable.


## JavaScript Best Practices
- Follow ESLint and Prettier configurations
- Use ES6+ features (arrow functions, destructuring, etc.)
- Prefer const over let, avoid var
- Use async/await for asynchronous operations
- Use template literals for string concatenation

## LLM Prompt Best Practices
- Keep prompts concise: avoid repeating tool schemas or guidance already present in the workflow.
- When providing to an LLM a list of data with two or more items that have the same shape, prefer TOON over JSON.
- When an LLM is to return structured data, prefer JSON.
