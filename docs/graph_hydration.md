# Graph hydration measurements

Hydration loads a fixed set of immutable relationship memberships. Each window completes its
relationship, entity, metadata, and context reads before the next window begins. Dependencies are
cached across windows. On timeout, already completed records remain usable; incomplete records are
never emitted.

## Restricted-memory regression

Measured locally on 2026-10-16 with Neo4j `2026.09.0-community`, a 512 MiB heap, 128 MiB page cache,
128 MiB transaction budget, and a 2 GiB container memory limit. The existing reproduction fixture
publishes 9,905 entities, 20,000 relationships, and 15,140 evidence records.

| Trial | Initial state | Hydration seconds | Complete relationships | Truncated |
|-------|---------------|------------------:|-----------------------:|-----------|
| 1 | Fresh Neo4j container; first hydration after publishing fixture | 1.922 | 20,000 | No |
| 2 | Same container; fixture rebuilt | 1.673 | 20,000 | No |
| 3 | Same container; fixture rebuilt | 1.873 | 20,000 | No |

Timings measure hydration, excluding fixture publication and initial membership selection. Each trial
also passed the existing snapshot assertions for all 9,905 entities and 20,000 relationships.
The 120-second hydration budget and ten-second per-read cap were unchanged.

## Sampled query profiles

After the first trial, `PROFILE` compared the previous and new queries with the same 500 relationship
IDs or 500 entity IDs. These samples had warm data; they do not establish worst-case latency.

| Read | Query shape | Seconds | DB hits | Reported plan allocation, bytes |
|------|-------------|--------:|--------:|--------------------------------:|
| Relationships, previous | `UNWIND` with one indexed lookup per ID | 0.083 | 10,000 | 64 |
| Relationships, new | Indexed `r.id IN $ids` | 0.032 | 10,000 | 64 |
| Entities, previous | `UNWIND` with one indexed lookup per ID | 0.035 | 5,500 | 64 |
| Entities, new | Indexed `n.id IN $ids` | 0.027 | 5,500 | 64 |

Neo4j's reported plan allocation is not total transaction or JVM memory usage.
The relationship plan changed from `Unwind → Apply → DirectedRelationshipIndexSeek → Filter →
Projection` to `DirectedRelationshipIndexSeek → Filter → Projection`. Entity reads changed from
`Unwind → Apply → NodeUniqueIndexSeek → Projection` to `NodeUniqueIndexSeek → Projection`.
The new queries explicitly seek the existing `graph_rel_id` and `graphentity_id` indexes.

These profiles show fewer operators and faster sampled reads. They do not independently explain the
previous intermittent 120-second failures. Incremental completion also removes the earlier behavior
where time spent loading relationships could leave no budget to hydrate any complete records.

## Reproduction and diagnostics

Use the isolated Neo4j setup in CONTRIBUTING.md, then run:

```shell
NEO4J_TEST_URI=bolt://127.0.0.1:17687 KMP_DUPLICATE_LIB_OK=TRUE UV_CACHE_DIR="$PWD/.uv-cache" \
  uv run pytest tests/graph/test_neo4j_integration.py \
  -k reproduction_sized -q --log-cli-level=INFO
```

For each trial, the hydration completion log records elapsed time, completed memberships, memory
subdivisions, and incompleteness reasons. DEBUG logs provide per-stage and per-batch timing.
Run three times, using a fresh container for the first trial. Do not point these tests at an
application database; their fixture deletes test resources.

To profile the relationship read, supply at most 500 selected storage membership IDs as `$ids`:

```cypher
PROFILE MATCH (a:GraphEntity)-[r:RELATES]->(b:GraphEntity)
USING INDEX SEEK r:RELATES(id)
WHERE r.id IN $ids
RETURN a.id AS source_id, b.id AS target_id, properties(r) AS relationship
```

Profile entity reads with at most 500 selected storage entity IDs:

```cypher
PROFILE MATCH (n:GraphEntity)
USING INDEX SEEK n:GraphEntity(id)
WHERE n.id IN $ids
RETURN properties(n) AS node
```


## Frontier traversal with disconnected noise

The frontier regression on the same restricted-memory Neo4j configuration publishes a two-edge flow
and adds 22,001 disconnected relationships under the same hostname. Each trial resolves the source
and destination and returns the complete path without a whole-scope snapshot or truncation.

| Trial | Traversal seconds | Hydrated memberships |
|-------|------------------:|---------------------:|
| 1, first compilation; includes profiling overhead | 1.174 | 2 |
| 2, warm | 0.050 | 2 |
| 3, warm | 0.062 | 2 |

The sampled first frontier query used an indexed `anchor.id IN $ids` lookup and recorded 147 total
DB hits. Seed lookup plans used storage-ID, logical-ID, and URL indexes without `AllNodesScan`.
The measurements exclude graph publication. Legacy inline context discovery may still scan legacy
context properties; modern contextual scripts are located through publication metadata and indexed
context-owner IDs. These measurements concern an explicit-element flow, not every association shape.

Reproduce with the isolated test database:

```shell
NEO4J_TEST_URI=bolt://127.0.0.1:17687 KMP_DUPLICATE_LIB_OK=TRUE UV_CACHE_DIR="$PWD/.uv-cache" \
  uv run pytest tests/graph/test_neo4j_integration.py \
  -k frontier_ignores_disconnected -q -s
```
