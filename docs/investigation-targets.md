# Finding correlation and investigation targets

[README](../README.md) · [Documentation index](README.md)

ShyHurricane joins saved findings to captured resources and graph evidence without model calls or
application requests. Background materialization produces ranked investigation targets, shared hotspots,
and rule-based chain candidates. Scores rank investigation effort, not exploit probability.

## Finding submission contract

HTTP `/findings` accepts a JSON object, JSONL records, or form fields. Existing `target`/`targets`,
`title`, and `markdown` fields retain their meaning. Markdown is required; a missing title is generated.
Every new field is optional. MCP `save_finding` accepts the same `metadata` object. `query_findings`
returns `finding_id`, `metadata_revision`, `metadata`, and `metadata_conflicts` alongside existing fields.

```json
{
  "target": "https://example.com/search?q=test",
  "title": "HTML injection candidate",
  "markdown": "# HTML injection candidate\n\nObserved scanner evidence; validation pending.",
  "metadata": {
    "source": "zap",
    "source_finding_id": "alert-42",
    "rule_id": "40012",
    "severity": "high",
    "native_severity": "High",
    "confidence": "medium",
    "native_confidence": "Medium",
    "verification_status": "unverified",
    "cwe_ids": ["CWE-79"],
    "vulnerability_types": ["xss"],
    "affected_method": "GET",
    "parameter": {"name": "q", "location": "query"}
  }
}
```

The example metadata is already canonical: it is persisted unchanged. Changing `affected_method` to
`get` normalizes it to `GET`; duplicate CWE identifiers are removed. Null fields are omitted. A sparse
submission containing only `target` and `markdown` remains valid and stores empty metadata.

| Metadata field | Type / accepted values |
|----------------|------------------------|
| `source` | Producer string, for example `burp`, `zap`, `opengrep`, `nuclei` |
| `source_finding_id` | Producer instance identifier string, when available |
| `rule_id` | Producer issue-type, plugin, or rule identifier string |
| `severity` | `informational`, `low`, `medium`, `high`, `critical`, `unknown` |
| `confidence` | Producer confidence: `low`, `medium`, `high`, `unknown` |
| `native_severity`, `native_confidence` | Original producer labels as strings |
| `verification_status` | `confirmed`, `suspected`, `unverified`, `false_positive` |
| `cwe_ids` | Array of canonical identifiers, such as `CWE-79` |
| `vulnerability_types` | Array: `xss`, `access_control`, `authentication`, `injection`, `ssrf`, `configuration`, `exposure`, `cryptography`, `dependency`, `unknown` |
| `affected_method` | Actual affected HTTP method; normalized to uppercase |
| `parameter` | Object with optional `name` and `location` |
| `code_location` | Object with optional `source_path`, `start_line`, `end_line`, `start_column`, `end_column`, `coordinate_space` |
| `capture_id` | Actual known ShyHurricane capture identity |
| `content_sha256` | SHA-256 hexadecimal digest of the exact affected source artifact |
| `observed_at` | Non-negative finite Unix seconds |

Parameter locations are `query`, `body`, `path`, `header`, `cookie`, `fragment`, or `unknown`.
Code coordinates are positive, one-based integers. End coordinates cannot precede start coordinates.
Coordinate spaces are `delivered`, `recovered`, or `unknown`. Recovered paths are virtual identifiers;
they are not URLs to fetch. Unknown metadata members and invalid values return HTTP 400 with
`errors` containing `field` and `message`. All records are validated before any are queued; transport
or persistence failures during enqueue can still leave an accepted prefix, so retries must be safe.

For form submissions, encode `metadata` as a JSON string; repeated `targets` fields are supported.
A metadata object applies to every target in its record. Submit one record per affected request when
methods or parameters differ. HTTP 201 means durably queued, not yet searchable or correlated.

Do not treat scanner confidence as verification. Do not infer structured fields from arbitrary
Markdown, fabricate capture IDs, or substitute the submission POST for the affected request method.
Opengrep and Nuclei retain their available rule, severity, CWE, and source-location data directly.
Opengrep ERROR/WARNING/INFO map to high/medium/informational; Nuclei uses its named severity levels.
Unknown labels stay unknown. Neither adapter marks a finding confirmed.

Submissions retain target-plus-Markdown deduplication. Repeated submissions fill missing metadata,
including nested fields, without changing the original finding ID, title, Markdown, or timestamp.
Different supplied values remain recorded as conflicts; unknown values do not overwrite known values.
Conflicting method, location, artifact identity, or parameter metadata cannot establish stronger anchors.
Server-assigned metadata revisions prevent an older reconciliation page from replacing newer enrichment.
Lists with different known contents are conflicts, rather than silently combined provenance.
Metadata is included in finding logs and recovery exports.

## Read ranked targets

```json
{"scope":"example.com","include_hypotheses":true,"limit":20}
```

Call `find_investigation_targets` with these arguments. `scope` uses the graph hostname, host:port,
or HTTP(S) URL-prefix rules. Optional `vulnerability_type` selects one normalized category from the
table above; it is not semantic text. `limit` is the saved page size, from 1 to 1,000. Follow
`pagination.next_page_token` with `get_result_page`. Results are fixed saved snapshots.

Each candidate includes finding IDs and revisions, affected URLs/methods, anchor strength, graph
revision, witnesses and evidence IDs, missing prerequisites, coverage gaps, and concrete follow-up calls.
Hotspots aggregate contributing findings for shared URLs, script contexts, operations, or sinks.
`contexts_limited` identifies bounded counts. Narrow queries omit unrelated contexts and multi-finding
results whose findings do not all match scope; follow-up calls retain the requested scope.

Anchors distinguish host context, exact URLs, known methods, and code operations. Exact operation
anchors require compatible coordinates plus capture identity or a verifiable artifact hash.
A script consumer is an association; only flow relationships establish a flow witness.
Source/sink labels alone do not prove attacker control or exploitation. Unknown methods, uncaptured
resources, missing imports, deferred detail, mismatched versions, and disconnected paths remain gaps.

### Priority scoring version 2

| Contribution | Points |
|--------------|--------|
| Severity: informational/unknown, low, medium, high, critical | 0, 5, 10, 20, 25 |
| Anchor: host, URL, method, compatible operation | 0, 8, 12, 20 |
| Connectivity: association, contextual flow, anchored flow | 0, 15, 30 |
| Verification: unverified/unknown, suspected, confirmed | 0, 4, 10 |
| Distinct captured contexts | 1 each, capped at 10 |
| Producer confidence: low/unknown, medium, high | 0, 2, 5 |
| Anchor-critical metadata conflict | -10 |
| Incomplete or summarized supporting path | -10 |

Scores range from 0 to 100; host-only candidates cap at 20 and broad hypotheses at 40.
False-positive findings are excluded. Chains use the strongest metadata contribution, without
multiplying points by finding count. Ties sort by stronger anchor and then stable candidate ID.
The contribution breakdown and policy version are returned. Reach describes retained bounded
materialization; it is not a complete application inventory or a probability estimate.

### Chain rules

| Rule ID | Required evidence | Output |
|---------|-------------------|--------|
| `shared_flow` | Both operation anchors occur on one flow witness | Supported relationship candidate |
| `response_to_sink` | Explicit `RESPONSE_FROM` relation and response-source-to-sink witness | Supported relationship candidate |
| `shared_state` | Same explicit storage/message identity, write/read witnesses, and both operation anchors | Supported relationship candidate |
| `protection_gap` | Configuration category and compatible XSS/injection/exposure sink in the same captured context | Broad hypothesis |
| `navigation` | Authentication/access-control categories and an actual journey between affected URLs | Broad hypothesis |

The response rule never substitutes a request-body path for a response. Current analyzer captures may
lack the explicit response association; the rule then emits no candidate. Shared names, URLs, or hosts
cannot replace its prerequisite. Navigation and protection hypotheses require validation of applicability,
session continuity, privileges, and exploit composition. No backend execution is inferred. Candidates
are never automatically saved as findings.

## Materialization lifecycle and operations

An assessment-local `investigation_state/correlations.sqlite` stores durable finding obligations,
checkpoints, compact witnesses, and derived records. Finding handoff is idempotent and completes before
its processing queue is acknowledged. The worker checks publication revisions and recomputes older
findings in bounded jobs, coalescing graph changes. Reconciliation reads at most 100 Qdrant records per
slice, without vectors or Markdown, checkpoints its cursor, and repeats every 60 seconds.

Each finding job shares a pinned graph revision across focused queries and uses the graph's existing
120-second budget and traversal limits. It retains at most 100 witnesses per relation, considers at most
20 resource methods, 10 code operations, and 100 neighboring findings, and reports reached limits.
Witnesses retain at most three consuming-context examples per node, prioritizing the affected URL,
without copying unbounded shared-script context lists. Finding jobs atomically publish individual
results. Separate durable jobs derive chains and rebuild hotspots without repeating graph analysis. Each job uses a generation guard so an older completion
cannot acknowledge newer work. Derived publications also validate contributing result generations.
Interrupted jobs restart at a fresh graph revision; incomplete work never overwrites a successful materialization. Successful
bounded graph queries may publish partial witnesses with explicit gaps.

The worker runs independently of model loading and supports low-power mode. It pauses while dependency
health is unavailable and stops claiming work at shutdown. Transient failures retry with bounded backoff;
permanent failures require dashboard `f` retry, including chain and hotspot jobs. Previous successful
results remain readable as stale.
Queries do not trigger synchronous recomputation or target requests.

`graph.investigation` in `/status` and the graph dashboard panel report pending, completed, failed,
and stale counts, observed graph revision, policy version, last successful refresh/reconciliation, and
worker errors. Stale counts measure findings behind the last observed publication revision; they are
not elapsed-time estimates. Query `status` is scoped. Check both freshness and analysis gaps before
using a score. Empty or complete saved pages never establish assessment completeness or safety.

This finding metadata version is 3. Use a fresh assessment directory and replay captures/findings;
old findings are not migrated. Preserve existing directories. The graph format itself is unchanged.
New server deployments accept old extension payloads, so extensions can be upgraded independently.
See the [Burp handoff](codex-burp-findings.md) and [ZAP handoff](codex-zap-findings.md) for ready-to-send prompts.

Correlation policy 3 uses storage format 4 and requires rebuilt assessment storage. Older correlation
files are rejected without migration or automatic deletion. Finding metadata remains version 3.

### Scheduling and bounded reads

A compact persistent work table holds correlation, chain derivation, and hotspot aggregation jobs.
Indexed eligibility times provide deterministic work selection and retry backoff. New metadata and
manual retries advance job generations; stale completions and failures leave newer work untouched.
Graph refresh sweeps checkpoint batches of 100 finding IDs. A sweep finishes before another begins,
coalescing newer graph revisions without repeatedly restarting its prefix. New findings enqueue directly.

Chain selection uses explicit flow, storage/message, and response-endpoint identities. These lookup
keys select neighbors; the witness prerequisites above still determine supported relationships.
Pairing considers at most 100 keys and 100 neighbors and reports reached bounds. Hotspot membership
uses shared URLs, contexts, operations, and sinks, independently of chain lookup keys. Rebuilding one
hotspot retains at most 100 members in deterministic ID order and reports bounded contributing counts.
Pending or failed members keep the previous aggregate readable as stale. Excluding one member
rebuilds the group from its remaining members; fewer than two eligible members removes the hotspot.

Saved-result reads filter lightweight headers by scope, category, hypotheses, and complete dependency
membership before loading witness payloads in batches of at most 100. They retain at most 1,000 results;
`limit` is the saved page size. A qualifying extra header detects truncation without loading another
payload. Scope selection retains at most 10,000 finding headers and reports when that bound is reached.
Reads use a consistent SQLite snapshot and batch dependency checks. Memory scales with retained
results and the working batch rather than every matching payload.

`graph.investigation.work` reports `pending` and `failed` job counts under `correlate`, `derive`, and
`hotspot`. These are work counts; existing finding-level counts retain their meaning. The dashboard
shows these queues and `f` retries failed jobs of all three kinds. Derived candidates report incomplete
materialization while their contributing results or derived jobs are pending, failed, or stale.
Bare IPv6 finding targets are accepted; graph scope arguments use bracketed IPv6 authorities.

The “Find vulnerability chains” MCP prompt uses this tool as its initial worklist. It validates
chains and hotspots through returned follow-up calls, retrieving finding details or exploring the
graph only when necessary. Hypotheses and stale results remain explicitly qualified.

## Contributor context and classification

Responses include `findings`, keyed by contributing finding ID, containing `title`, the original
submitted `target`, `metadata_revision`, `metadata`, `metadata_conflicts`, and `category_basis`.
Saved pages include only their own contributors. Titles and targets remain independent: a scanner's
title can describe an application page while its submitted target identifies an evidence request.
Full finding Markdown remains available through scoped `query_findings`.

`category_basis` records producer categories and recognized CWE mappings. If neither provides a known
category, a source-specific scanner rule allowlist is used. Unknown IDs remain unknown; names and
Markdown never drive classification. ZAP already provides CWE and, for selected CWEs, explicit categories.
The initial Burp mappings are reflected XSS (2097920), stored XSS (2097408), DOM XSS (2097936), and
client-side template injection (2097928). References:
[reflected XSS](https://portswigger.net/kb/issues/00200300_cross-site-scripting-reflected),
[stored XSS](https://portswigger.net/kb/issues/00200100_cross-site-scripting-stored),
[DOM XSS](https://portswigger.net/kb/issues/00200310_cross-site-scripting-dom-based),
[template injection](https://portswigger.net/kb/issues/00200308_client-side-template-injection).
The scanner-rule allowlist is versioned with correlation policy 3.

`category_coverage` counts scoped `categorized`, `unknown`, and `without_metadata` findings, before
category filtering. These describe the bounded scoped finding selection; they are not mutually exclusive:
metadata-free findings are also unknown. A complete processing status does not establish classification,
graph completeness, or exploitation verification.

Hotspots expose `association_basis` (`direct` or `contextual`), `direct_contributor_count`, and
`contextual_contributor_count`. Direct support requires at least two findings whose submitted affected
URL or compatible anchored operation matches the shared key. Context-only groups remain readable but
score at most 20 with no context-count bonus. Scoring version 2 retains other contributions.
Witnesses are deduplicated and selected deterministically, prioritizing the shared key within the existing
ten-witness bound; `omitted_witness_count` reports distinct witnesses beyond that bound. Follow-up calls
are deduplicated after scope rewriting. Full distinct retained evidence remains in the response.

Storage format 4 rejects older correlation databases without migration or deletion. Rebuild assessment
storage and replay findings/captures; this change does not update a running assessment automatically.

Additional allowlisted Burp types:

| Decimal rule ID | Category | Definition |
|-----------------|----------|------------|
| 2097938 | xss | [PortSwigger definition](https://portswigger.net/kb/issues/00200312_cross-site-scripting-stored-dom-based) |
| 1048832 | injection | [PortSwigger definition](https://portswigger.net/kb/issues/00100100_os-command-injection) |
| 1049088 | injection | [PortSwigger definition](https://portswigger.net/kb/issues/00100200_sql-injection) |
| 1049104 | injection | [PortSwigger definition](https://portswigger.net/kb/issues/00100210_sql-injection-second-order) |
| 1052800 | injection | [PortSwigger definition](https://portswigger.net/kb/issues/00101080_server-side-template-injection) |
| 3146256 | ssrf | [PortSwigger definition](https://portswigger.net/kb/issues/00300210_external-service-interaction-http) |
| 5244416 | configuration | [PortSwigger definition](https://portswigger.net/kb/issues/00500600_cookie-without-httponly-flag-set) |
| 16777984 | configuration | [PortSwigger definition](https://portswigger.net/kb/issues/01000300_strict-transport-security-not-enforced) |
