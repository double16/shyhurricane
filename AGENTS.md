## Critical rules the agent must follow before doing anything
- Read `README.md` and `CONTRIBUTING.md` before acting.
- Update `CHANGELOG.md` for user-facing changes. Categorize using `### Features` and `### Fixes`.

## Testing and contribution
- Always write unit tests and check that they pass for new and changed business logic.
- Changed and new code should have at least 80% code and branch coverage.
- Always run unit tests to verify changes.
- Test both positive and negative scenarios.
- Keep tests in files based on component or functionality. Use existing test files if applicable.

## Explicit prohibitions what agents must NOT do
- Do not bump major versions of core dependencies without a dedicated PR and discussion.
- Do not rename files without a valid technical reason.

## Documentation
- Keep documentation up-to-date and accurate.
- Use clear language.
- Follow a consistent style and format for documentation.
- Use examples and diagrams to illustrate concepts.
- Environment variables used for configuration must be documented in a table along-side similar variables.

## Python Best Practices
- Use the `uv` tool for python ecosystem, i.e `uv run ...`
- Follow PEP 8 with a 120-character line limit
- Run `uv run ruff` on new or changed files to validate Python coding standards
- Use double quotes for Python strings
- Sort imports with `isort`
- Use f-strings for string formatting
- If a class member is set in __init__, do not use getattr(), use direct reference.
- For multi-line strings, use triple quotes and limit each line to 100 characters.
- Environment variables used for configuration must be given an example in .env.example and forwarded through docker-compose.yml.

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
  KMP_DUPLICATE_LIB_OK=TRUE UV_CACHE_DIR="$PWD/.uv-cache" uv run coverage run -m pytest -q
  KMP_DUPLICATE_LIB_OK=TRUE UV_CACHE_DIR="$PWD/.uv-cache" uv run coverage report
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
- When providing to an LLM a list of data with two or more items that have the same shape, prefer TOON over JSON.
- When an LLM is to return structured data, prefer JSON.
