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

### Priority scoring version 4

| Contribution | Points |
|--------------|--------|
| Severity: informational/unknown, low, medium, high, critical | 0, 5, 10, 20, 25 |
| Anchor: host, URL, method, compatible operation | 0, 8, 12, 20 |
| Connectivity: association, contextual flow, anchored flow | 0, 0, 30 |
| Verification: unverified/unknown, suspected, confirmed | 0, 4, 10 |
| Distinct directly affected URLs | 1 each, capped at 10 |
| Producer confidence: low/unknown, medium, high | 0, 2, 5 |
| Demonstrated UI origin on a complete operation-bound flow | 10 once |
| Anchor-critical metadata conflict | -10 |
| Incomplete or summarized supporting path | -10 |

Scores range from 0 to 100; host-only candidates cap at 20 and broad hypotheses at 40.
False-positive findings are excluded. Chains use the strongest metadata contribution, without
multiplying points by finding count. Ties sort by stronger anchor and then stable candidate ID.
The contribution breakdown and policy version are returned. Reach describes retained bounded
materialization; it is not a complete application inventory or a probability estimate.

### UI-origin evidence

The `ui_origin` contribution requires a captured control, editable element, or interactive element
with an evidenced, capture-compatible flow through a finding operation to a sink.
`ui_origins` identifies the element, capture, location, evidence IDs, and witness node IDs.
Library code along the path does not disqualify it. Contextual hotspots, broad hypotheses,
and summarized paths receive no bonus. UI origin does not prove attacker control.
Scoring version 4 and correlation policy 6 recompute existing correlations.

Resolved `addEventListener` callbacks and inline HTML handlers support input, change, submit, click,
keydown, and keyup events. The flow must use a value from the element or event payload; registration
alone earns no points. Inline handlers retain their original source coordinates. Unresolved receivers,
ambiguous callback receivers, and delegated selectors remain gaps and receive no origin bonus.
Analyzer policy 9 invalidates reusable JavaScript caches. Runtime-only elements remain unsupported.

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
The scanner-rule allowlist is versioned with correlation policy 4.

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

Contextual flows receive no connectivity bonus. Context-count scoring uses directly affected URLs.
Protection-gap hypotheses have unproven applicability and a priority cap of 20; their association
reason identifies contributors and shared contexts. Correlation policy 4 uses scoring version 3.

### Evidence relevance and readable source identity

Graph analyzer version 8 records SHA-256 of the normalized or reconstructed source alongside
operation coordinates. Opengrep matches those analyzed-source hashes; raw response hashes are
not substituted for normalized coordinates. Recovered sources also retain their own hashes.
Code-location lookup filters by source path and line range before hydrating at most 1,000 operations,
using the selected publication revision and existing query budget.

Target `binding_status` is `not_requested`, `bound`, `conflicting_metadata`, `bounded_lookup`,
`missing_artifact`, `hash_mismatch`, or `coordinate_mismatch`. An unbound location retains URL
fallback and never becomes an operation anchor on line numbers alone. Witness `evidence_basis`
distinguishes operation-bound flows, contextual flows, and resource associations. Operation-bound
witnesses precede contextual evidence when recommending evidence reads.

Each page includes unique `follow_up` tool/argument combinations with `result_ids`; per-result
calls and full witnesses remain available. Reuse retrieved evidence across pages.
`unknown_categories` groups scoped unknown findings by source/rule, before category filtering,
with counts and at most three example IDs. At most 100 groups are returned; inspect
`unknown_categories_truncated`. Generic Burp extension IDs remain unknown without structured
producer categories or CWEs; finding titles are never used to infer categories or affected URLs.

Additional reviewed category sources:

| Burp type index | Category | Definition |
|---|---|---|
| 1049600 | injection | [XXE](https://portswigger.net/kb/issues/00100400_xml-external-entity-injection) |
| 2097664 | injection | [Header injection](https://portswigger.net/kb/issues/00200200_http-response-header-injection) |
| 2097942 | injection | [Prototype pollution](https://portswigger.net/kb/issues/00200316_client-side-prototype-pollution) |
| 5243392 | configuration | [Insecure cookie](https://portswigger.net/kb/issues/00500200_tls-cookie-without-secure-flag-set) |
| 5243008 | dependency | [Vulnerable dependency](https://portswigger.net/kb/issues/00500080_vulnerable-javascript-dependency) |

Corresponding CWE fallbacks include CWE-611, CWE-113, CWE-915/CWE-1321, CWE-614, and CWE-1104.
These categories group investigation work; they do not assert exploitability.
Rebuild assessment storage for the new graph source identities; no migration or automatic replay is provided.

## Expanded web classification catalog

Reviewed against PortSwigger issue definitions and the MITRE OWASP Top Ten CWE view.
Mappings are investigation categories, not exploitability claims. Existing mappings take precedence
over broader groupings. Generic upload functionality, custom extension rules, hardware, memory
safety, and standalone denial-of-service findings are intentionally not classified.

| Decimal ID | Category | Definition |
|---|---|---|
| 1049344 | access_control | [file-path-traversal](https://portswigger.net/kb/issues/00100300_file-path-traversal) |
| 1049856 | injection | [ldap-injection](https://portswigger.net/kb/issues/00100500_ldap-injection) |
| 1050112 | injection | [xpath-injection](https://portswigger.net/kb/issues/00100600_xpath-injection) |
| 1050368 | injection | [xml-injection](https://portswigger.net/kb/issues/00100700_xml-injection) |
| 1051648 | injection | [php-code-injection](https://portswigger.net/kb/issues/00100c00_php-code-injection) |
| 1051904 | injection | [server-side-javascript-code-injection](https://portswigger.net/kb/issues/00100d00_server-side-javascript-code-injection) |
| 1052160 | injection | [perl-code-injection](https://portswigger.net/kb/issues/00100e00_perl-code-injection) |
| 1052416 | injection | [ruby-code-injection](https://portswigger.net/kb/issues/00100f00_ruby-code-injection) |
| 1052432 | injection | [python-code-injection](https://portswigger.net/kb/issues/00100f10_python-code-injection) |
| 1052448 | injection | [expression-language-injection](https://portswigger.net/kb/issues/00100f20_expression-language-injection) |
| 1052672 | injection | [unidentified-code-injection](https://portswigger.net/kb/issues/00101000_unidentified-code-injection) |
| 1052928 | injection | [ssi-injection](https://portswigger.net/kb/issues/00101100_ssi-injection) |
| 2097937 | xss | [cross-site-scripting-reflected-dom-based](https://portswigger.net/kb/issues/00200311_cross-site-scripting-reflected-dom-based) |
| 4195328 | exposure | [password-returned-in-url-query-string](https://portswigger.net/kb/issues/00400400_password-returned-in-url-query-string) |
| 16777472 | cryptography | [tls-certificate](https://portswigger.net/kb/issues/01000100_tls-certificate) |

CWE additions (each identifier links to its authoritative definition):

- xss: [CWE-80](https://cwe.mitre.org/data/definitions/80.html), [CWE-81](https://cwe.mitre.org/data/definitions/81.html), [CWE-83](https://cwe.mitre.org/data/definitions/83.html), [CWE-84](https://cwe.mitre.org/data/definitions/84.html), [CWE-85](https://cwe.mitre.org/data/definitions/85.html), [CWE-86](https://cwe.mitre.org/data/definitions/86.html), [CWE-87](https://cwe.mitre.org/data/definitions/87.html).
- injection: [CWE-74](https://cwe.mitre.org/data/definitions/74.html), [CWE-77](https://cwe.mitre.org/data/definitions/77.html), [CWE-88](https://cwe.mitre.org/data/definitions/88.html), [CWE-90](https://cwe.mitre.org/data/definitions/90.html), [CWE-91](https://cwe.mitre.org/data/definitions/91.html), [CWE-93](https://cwe.mitre.org/data/definitions/93.html), [CWE-95](https://cwe.mitre.org/data/definitions/95.html), [CWE-96](https://cwe.mitre.org/data/definitions/96.html), [CWE-97](https://cwe.mitre.org/data/definitions/97.html), [CWE-98](https://cwe.mitre.org/data/definitions/98.html), [CWE-99](https://cwe.mitre.org/data/definitions/99.html), [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html), [CWE-502](https://cwe.mitre.org/data/definitions/502.html), [CWE-643](https://cwe.mitre.org/data/definitions/643.html), [CWE-652](https://cwe.mitre.org/data/definitions/652.html), [CWE-917](https://cwe.mitre.org/data/definitions/917.html).
- access_control: [CWE-22](https://cwe.mitre.org/data/definitions/22.html), [CWE-23](https://cwe.mitre.org/data/definitions/23.html), [CWE-36](https://cwe.mitre.org/data/definitions/36.html), [CWE-284](https://cwe.mitre.org/data/definitions/284.html), [CWE-285](https://cwe.mitre.org/data/definitions/285.html), [CWE-352](https://cwe.mitre.org/data/definitions/352.html), [CWE-425](https://cwe.mitre.org/data/definitions/425.html), [CWE-441](https://cwe.mitre.org/data/definitions/441.html), [CWE-565](https://cwe.mitre.org/data/definitions/565.html), [CWE-732](https://cwe.mitre.org/data/definitions/732.html), [CWE-749](https://cwe.mitre.org/data/definitions/749.html).
- authentication: [CWE-256](https://cwe.mitre.org/data/definitions/256.html), [CWE-259](https://cwe.mitre.org/data/definitions/259.html), [CWE-288](https://cwe.mitre.org/data/definitions/288.html), [CWE-289](https://cwe.mitre.org/data/definitions/289.html), [CWE-290](https://cwe.mitre.org/data/definitions/290.html), [CWE-294](https://cwe.mitre.org/data/definitions/294.html), [CWE-295](https://cwe.mitre.org/data/definitions/295.html), [CWE-297](https://cwe.mitre.org/data/definitions/297.html), [CWE-306](https://cwe.mitre.org/data/definitions/306.html), [CWE-307](https://cwe.mitre.org/data/definitions/307.html), [CWE-308](https://cwe.mitre.org/data/definitions/308.html), [CWE-309](https://cwe.mitre.org/data/definitions/309.html), [CWE-346](https://cwe.mitre.org/data/definitions/346.html), [CWE-347](https://cwe.mitre.org/data/definitions/347.html), [CWE-521](https://cwe.mitre.org/data/definitions/521.html), [CWE-613](https://cwe.mitre.org/data/definitions/613.html), [CWE-620](https://cwe.mitre.org/data/definitions/620.html), [CWE-640](https://cwe.mitre.org/data/definitions/640.html), [CWE-645](https://cwe.mitre.org/data/definitions/645.html), [CWE-646](https://cwe.mitre.org/data/definitions/646.html), [CWE-647](https://cwe.mitre.org/data/definitions/647.html).
- configuration: [CWE-15](https://cwe.mitre.org/data/definitions/15.html), [CWE-209](https://cwe.mitre.org/data/definitions/209.html), [CWE-444](https://cwe.mitre.org/data/definitions/444.html), [CWE-548](https://cwe.mitre.org/data/definitions/548.html), [CWE-602](https://cwe.mitre.org/data/definitions/602.html), [CWE-614](https://cwe.mitre.org/data/definitions/614.html), [CWE-615](https://cwe.mitre.org/data/definitions/615.html), [CWE-693](https://cwe.mitre.org/data/definitions/693.html), [CWE-942](https://cwe.mitre.org/data/definitions/942.html), [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html), [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html).
- exposure: [CWE-201](https://cwe.mitre.org/data/definitions/201.html), [CWE-203](https://cwe.mitre.org/data/definitions/203.html), [CWE-204](https://cwe.mitre.org/data/definitions/204.html), [CWE-215](https://cwe.mitre.org/data/definitions/215.html), [CWE-359](https://cwe.mitre.org/data/definitions/359.html), [CWE-497](https://cwe.mitre.org/data/definitions/497.html), [CWE-498](https://cwe.mitre.org/data/definitions/498.html), [CWE-532](https://cwe.mitre.org/data/definitions/532.html), [CWE-538](https://cwe.mitre.org/data/definitions/538.html), [CWE-539](https://cwe.mitre.org/data/definitions/539.html), [CWE-540](https://cwe.mitre.org/data/definitions/540.html), [CWE-541](https://cwe.mitre.org/data/definitions/541.html), [CWE-598](https://cwe.mitre.org/data/definitions/598.html).
- cryptography: [CWE-261](https://cwe.mitre.org/data/definitions/261.html), [CWE-311](https://cwe.mitre.org/data/definitions/311.html), [CWE-312](https://cwe.mitre.org/data/definitions/312.html), [CWE-319](https://cwe.mitre.org/data/definitions/319.html), [CWE-321](https://cwe.mitre.org/data/definitions/321.html), [CWE-322](https://cwe.mitre.org/data/definitions/322.html), [CWE-323](https://cwe.mitre.org/data/definitions/323.html), [CWE-324](https://cwe.mitre.org/data/definitions/324.html), [CWE-325](https://cwe.mitre.org/data/definitions/325.html), [CWE-326](https://cwe.mitre.org/data/definitions/326.html), [CWE-327](https://cwe.mitre.org/data/definitions/327.html), [CWE-328](https://cwe.mitre.org/data/definitions/328.html), [CWE-329](https://cwe.mitre.org/data/definitions/329.html), [CWE-330](https://cwe.mitre.org/data/definitions/330.html), [CWE-331](https://cwe.mitre.org/data/definitions/331.html), [CWE-334](https://cwe.mitre.org/data/definitions/334.html), [CWE-335](https://cwe.mitre.org/data/definitions/335.html), [CWE-336](https://cwe.mitre.org/data/definitions/336.html), [CWE-337](https://cwe.mitre.org/data/definitions/337.html), [CWE-338](https://cwe.mitre.org/data/definitions/338.html), [CWE-522](https://cwe.mitre.org/data/definitions/522.html), [CWE-759](https://cwe.mitre.org/data/definitions/759.html), [CWE-760](https://cwe.mitre.org/data/definitions/760.html), [CWE-916](https://cwe.mitre.org/data/definitions/916.html).
- dependency: [CWE-829](https://cwe.mitre.org/data/definitions/829.html), [CWE-830](https://cwe.mitre.org/data/definitions/830.html), [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html).

Correlation policy 5 invalidates prior classifications through the existing background sweep;
no storage format change or manual migration is required.

CWE-922 maps to exposure (insecure storage); CWE-1275 maps to configuration (SameSite).
