# Construction cost measurements

This report defines a repeatable, test-only measurement of model construction
for the large valid workloads accepted by the current parser and compiler. It
times parsing, validation, compilation, index construction, full public
construction, and destruction separately. The ignored Rust test accesses
private `CompiledModel` fields so each workload is checked before timing.

These measurements describe construction work. They do not set latency limits
or establish runtime authorization speed. No runtime speed or platform support
claim follows until Task 6 supplies observations.

## Workloads

The generators live in `relgraph-authz/tests/support/construction_models.rs`
and are included only by the test module. Declaration counts include type and
relation declarations. The relation-unit maximum is the largest parser budget
used by any single relation in that workload.

| Case | Workload | Declarations | Maximum relation units |
| --- | --- | ---: | ---: |
| `union_32` | 32 computed-user-set terms in a left-deep union, plus the base relation | 4 | 63 |
| `union_128` | 128 computed-user-set terms in a left-deep union, plus the base relation | 4 | 255 |
| `union_256` | 256 computed-user-set terms in a left-deep union, plus the base relation | 4 | 511 |
| `union_exact_512` | Direct-assignment root plus 255 computed-user-set terms; exactly 512 relation units | 4 | 512 |
| `intersection_256` | 256 computed-user-set terms in a left-deep intersection, plus the base relation | 4 | 511 |
| `nested_128` | Direct assignment nested in 128 pairs of parentheses | 3 | 2 |
| `targets_511` | One direct assignment with 511 subject type targets | 513 | 512 |
| `wide_indexes_2047` | 2,047 independent bucket types, each with a member relation | 4,095 | 2 |
| `edges_511` | 511 node types and tuple-to-userset edges from one document relation | 1,026 | 512 |
| `repeated_128` | 128 relations, each with 256 terms and exactly 512 relation units | 131 | 512 |

The pre-measurement assertions check the compiled expression, relation, target,
and tuple-to-userset edge counts specified by the workload definitions. They
also compare type and relation index entry counts with declarations in the
parsed schema.

## Timed boundaries

| Phase | Timed operation |
| --- | --- |
| `parse` | `parse_fga_schema(source)` |
| `validate` | `validate_schema(&parsed_schema)` |
| `compile` | `CompiledModel::compile_validated(owned_validated_schema)`, including capability/dependency checks, empty condition compilation, and indexes |
| `indexes` | `CompiledModel::compile_indexes(owned_validated_schema, HashMap::new())`; all workloads are condition-free |
| `full` | `FgaAuthz::new(source)`, including parse, validation, and compilation |
| `drop` | Destruction of a prepared compiled model |

The source, validation inputs, and cloned schemas are prepared before each
timer starts. The clock stops before dropping phase outputs, except for the
explicit `drop` phase. `std::hint::black_box` surrounds timed inputs and
outputs to keep the measured operation observable.

Each phase discards three warmup samples and records 21 samples. Values are
sorted; the reported median is sample 10, p95 is sample 19, and maximum is
sample 20 (zero-based indexes). CSV durations are nanoseconds. No phase
medians are subtracted to estimate another phase because phase setup and
allocation states differ.

## Commands

Compile the ignored test in default and Axum configurations:

```sh
cargo check -p relgraph-authz --all-targets
cargo check -p relgraph-authz --all-targets --all-features
```

Measure only the exact-limit union case:

```sh
RELGRAPH_CONSTRUCTION_COST_CASE=union_exact_512 cargo test -p relgraph-authz --release --lib authz::model::construction_costs::measure_construction_costs -- --ignored --exact --nocapture --test-threads=1
```

Measure all workloads by omitting the case selector:

```sh
cargo test -p relgraph-authz --release --lib authz::model::construction_costs::measure_construction_costs -- --ignored --exact --nocapture --test-threads=1
```

The normal test suite skips this measurement because it is marked ignored.
Each selected case emits one CSV header followed by six rows in phase order:

```text
case,phase,source_bytes,declarations,maximum_relation_units,samples,median_ns,p95_ns,max_ns
```

## Results

**Not measured yet**

Each run cell will contain `median / p95 / max (ns)`.

### Parse

| Workload | Run 1 | Run 2 | Run 3 |
| --- | --- | --- | --- |
| `union_32` |  |  |  |
| `union_128` |  |  |  |
| `union_256` |  |  |  |
| `union_exact_512` |  |  |  |
| `intersection_256` |  |  |  |
| `nested_128` |  |  |  |
| `targets_511` |  |  |  |
| `wide_indexes_2047` |  |  |  |
| `edges_511` |  |  |  |
| `repeated_128` |  |  |  |

### Validate

| Workload | Run 1 | Run 2 | Run 3 |
| --- | --- | --- | --- |
| `union_32` |  |  |  |
| `union_128` |  |  |  |
| `union_256` |  |  |  |
| `union_exact_512` |  |  |  |
| `intersection_256` |  |  |  |
| `nested_128` |  |  |  |
| `targets_511` |  |  |  |
| `wide_indexes_2047` |  |  |  |
| `edges_511` |  |  |  |
| `repeated_128` |  |  |  |

### Compile

| Workload | Run 1 | Run 2 | Run 3 |
| --- | --- | --- | --- |
| `union_32` |  |  |  |
| `union_128` |  |  |  |
| `union_256` |  |  |  |
| `union_exact_512` |  |  |  |
| `intersection_256` |  |  |  |
| `nested_128` |  |  |  |
| `targets_511` |  |  |  |
| `wide_indexes_2047` |  |  |  |
| `edges_511` |  |  |  |
| `repeated_128` |  |  |  |

### Indexes

| Workload | Run 1 | Run 2 | Run 3 |
| --- | --- | --- | --- |
| `union_32` |  |  |  |
| `union_128` |  |  |  |
| `union_256` |  |  |  |
| `union_exact_512` |  |  |  |
| `intersection_256` |  |  |  |
| `nested_128` |  |  |  |
| `targets_511` |  |  |  |
| `wide_indexes_2047` |  |  |  |
| `edges_511` |  |  |  |
| `repeated_128` |  |  |  |

### Full

| Workload | Run 1 | Run 2 | Run 3 |
| --- | --- | --- | --- |
| `union_32` |  |  |  |
| `union_128` |  |  |  |
| `union_256` |  |  |  |
| `union_exact_512` |  |  |  |
| `intersection_256` |  |  |  |
| `nested_128` |  |  |  |
| `targets_511` |  |  |  |
| `wide_indexes_2047` |  |  |  |
| `edges_511` |  |  |  |
| `repeated_128` |  |  |  |

### Drop

| Workload | Run 1 | Run 2 | Run 3 |
| --- | --- | --- | --- |
| `union_32` |  |  |  |
| `union_128` |  |  |  |
| `union_256` |  |  |  |
| `union_exact_512` |  |  |  |
| `intersection_256` |  |  |  |
| `nested_128` |  |  |  |
| `targets_511` |  |  |  |
| `wide_indexes_2047` |  |  |  |
| `edges_511` |  |  |  |
| `repeated_128` |  |  |  |

## Caveats

- `Instant` resolution and measurement overhead matter most for short phases.
  Warmups, a single-threaded test run, and repeated samples reduce some noise;
  they do not eliminate scheduler, allocator, or host-load variation.
- The compile and indexes samples retain a separately parsed source schema
  while compiling a cloned schema. The compiled model also retains its source
  AST for diagnostics. These setup and ownership choices affect allocation
  state, so phase values are observations of this harness's boundaries.
- Workloads have no conditions. The compile phase exercises the normal
  condition-compilation path with an empty condition set, not CEL compilation
  cost.
- Whole-process peak RSS includes the test harness, fixture preparation, and
  all phases for a selected case. It is not an index-only allocation measure
  or live evaluator memory. Task 6 will record RSS separately where available.
- No timing threshold is asserted, and measurements do not establish
  authorization runtime speed or broad platform support.
