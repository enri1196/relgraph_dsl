# Construction cost measurements

This report defines a repeatable, test-only measurement of model construction
for the large valid workloads accepted by the current parser and compiler. It
times parsing, validation, compilation, index construction, full public
construction, and destruction separately. The ignored Rust test accesses
private `CompiledModel` fields so each workload is checked before timing.

These measurements describe construction work. They do not set latency limits
or establish runtime authorization speed. Task 6 records observations for this
host only; they do not establish support across platforms.

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

## Host, profile, and commands

Measurements were collected on 2026-10-04. The starting Git revision was
`ec877dcf043c703dbc38a3784b77ba4f26bc0ffb` (`perf(authz): add construction cost measurement harness`).
The pre-run process check found no active Cargo build or test process.

| Item | Recorded value |
| --- | --- |
| `rustc -Vv` | `rustc 1.94.0 (4a4ef493e 2026-03-02)`; host `aarch64-apple-darwin`; LLVM `21.1.8` |
| `cargo -V` | `cargo 1.94.0 (85eff7c80 2026-01-15)` |
| `uname -sm` | `Darwin arm64` |
| CPU (`sysctl -n machdep.cpu.brand_string`) | `Apple M1` |
| RAM (`sysctl -n hw.memsize`) | `17179869184` bytes |
| Power (`pmset -g batt`, `pmset -g`) | AC power; battery charging; `lowpowermode 0` |
| Stress profile | Debug and release; default package features |
| Timing and RSS profile | Release; `relgraph-authz` default features (`default = []`), no feature flags |
| Declared MSRV | None in the workspace |
| Second host | **Linux x86_64 not measured**; no such host was available through this authorized environment |

The full output of these commands is captured in
`/private/tmp/relgraph-task6-20261004/host-metadata.txt`. The complete
`rustc -Vv` output was:

```text
rustc 1.94.0 (4a4ef493e 2026-03-02)
binary: rustc
commit-hash: 4a4ef493e3a1488c6e321570238084b38948f6db
commit-date: 2026-03-02
host: aarch64-apple-darwin
release: 1.94.0
LLVM version: 21.1.8
```

The host metadata commands were:

```sh
rustc -Vv
cargo -V
uname -sm
sysctl -n machdep.cpu.brand_string
sysctl -n hw.memsize
pmset -g batt
pmset -g
git rev-parse HEAD
```

The child stress suite passed in both profiles. Its commands and captured
outputs were:

```sh
cargo test -p relgraph-authz --test construction_depth
cargo test -p relgraph-authz --release --test construction_depth
```

Outputs: `/private/tmp/relgraph-task6-20261004/stress-debug.log` and
`/private/tmp/relgraph-task6-20261004/stress-release.log` (5 passed in each run).

The full release measurement command below was run three times sequentially,
without another build or test process running concurrently:

```sh
cargo test -p relgraph-authz --release --lib authz::model::construction_costs::measure_construction_costs -- --ignored --exact --nocapture --test-threads=1
```

Captured outputs: `release-all-run-1.log`, `release-all-run-2.log`, and
`release-all-run-3.log` under `/private/tmp/relgraph-task6-20261004/`.
Each run passed and reported 10 workloads × six phases.

## Results

Every timing cell is `median / p95 / max` in nanoseconds, as emitted by the
test harness. Each phase table is grouped by phase; runs are the three
sequential all-case release invocations.

### Parse

| Workload | Run 1 (ns) | Run 2 (ns) | Run 3 (ns) |
| --- | --- | --- | --- |
| `union_32` | 8958 / 10167 / 10666 | 8167 / 9209 / 9250 | 8459 / 9334 / 9625 |
| `union_128` | 28625 / 28791 / 28959 | 26542 / 27708 / 27917 | 28542 / 28750 / 29167 |
| `union_256` | 53458 / 55542 / 55750 | 52250 / 55000 / 55000 | 53583 / 55125 / 55666 |
| `union_exact_512` | 51792 / 52750 / 53250 | 51416 / 51875 / 52000 | 52125 / 52959 / 70125 |
| `intersection_256` | 52500 / 52709 / 52750 | 52583 / 54209 / 54458 | 54583 / 56000 / 56250 |
| `nested_128` | 10916 / 11042 / 11125 | 10541 / 10959 / 11042 | 10541 / 11042 / 11167 |
| `targets_511` | 148291 / 160000 / 192542 | 147042 / 153250 / 188708 | 151792 / 172125 / 173041 |
| `wide_indexes_2047` | 1325333 / 1382334 / 1394250 | 1326750 / 1397208 / 1455875 | 1415125 / 1511416 / 1597708 |
| `edges_511` | 400500 / 419375 / 473541 | 401750 / 451875 / 452750 | 433125 / 791125 / 834083 |
| `repeated_128` | 6794625 / 7258875 / 7328750 | 6990792 / 7274792 / 7312083 | 7189750 / 7792458 / 7854583 |

### Validate

| Workload | Run 1 (ns) | Run 2 (ns) | Run 3 (ns) |
| --- | --- | --- | --- |
| `union_32` | 2417 / 4792 / 5291 | 2209 / 3875 / 8417 | 2250 / 3875 / 5208 |
| `union_128` | 5792 / 6250 / 6292 | 5750 / 5875 / 5916 | 5584 / 5875 / 6916 |
| `union_256` | 10042 / 10667 / 12250 | 10250 / 11458 / 25042 | 10667 / 12000 / 15416 |
| `union_exact_512` | 9917 / 13458 / 16333 | 9708 / 9792 / 10541 | 9750 / 9834 / 10250 |
| `intersection_256` | 10375 / 11000 / 11666 | 9958 / 10584 / 10666 | 9792 / 10583 / 10833 |
| `nested_128` | 708 / 2041 / 6375 | 625 / 666 / 667 | 667 / 708 / 709 |
| `targets_511` | 109750 / 145625 / 163333 | 111875 / 120125 / 122000 | 113625 / 146292 / 155667 |
| `wide_indexes_2047` | 1005708 / 1103000 / 1117334 | 1018792 / 1103208 / 1142333 | 1183375 / 1508209 / 1915792 |
| `edges_511` | 272708 / 323667 / 347208 | 276333 / 312958 / 319834 | 284667 / 320625 / 331916 |
| `repeated_128` | 1311500 / 1462666 / 1486875 | 1282000 / 1464542 / 1520542 | 1362584 / 1525208 / 1582917 |

### Compile

| Workload | Run 1 (ns) | Run 2 (ns) | Run 3 (ns) |
| --- | --- | --- | --- |
| `union_32` | 5416 / 6750 / 6750 | 5417 / 6625 / 6625 | 5375 / 6875 / 7791 |
| `union_128` | 16292 / 16959 / 16959 | 16291 / 16459 / 16541 | 16375 / 17000 / 17333 |
| `union_256` | 30916 / 31917 / 32083 | 31292 / 31625 / 31667 | 30375 / 31292 / 31583 |
| `union_exact_512` | 30750 / 33208 / 49542 | 30209 / 32375 / 38625 | 31667 / 34083 / 34583 |
| `intersection_256` | 30625 / 32833 / 33000 | 31333 / 33209 / 33250 | 31083 / 36583 / 48333 |
| `nested_128` | 917 / 1000 / 1041 | 875 / 917 / 958 | 916 / 958 / 959 |
| `targets_511` | 27167 / 29875 / 31583 | 27750 / 28209 / 28333 | 29584 / 32083 / 33791 |
| `wide_indexes_2047` | 1187167 / 1241416 / 1397042 | 1102291 / 1161041 / 1177500 | 1253084 / 1539166 / 1664459 |
| `edges_511` | 330291 / 374625 / 398042 | 335500 / 364166 / 400375 | 343916 / 376000 / 419458 |
| `repeated_128` | 3725667 / 3948250 / 3950833 | 3742083 / 3904417 / 3934417 | 3772625 / 3970250 / 3994583 |

### Indexes

| Workload | Run 1 (ns) | Run 2 (ns) | Run 3 (ns) |
| --- | --- | --- | --- |
| `union_32` | 1500 / 1583 / 1583 | 1459 / 1541 / 1542 | 1500 / 1542 / 1542 |
| `union_128` | 4500 / 4792 / 4792 | 4709 / 4792 / 4792 | 4875 / 5042 / 5208 |
| `union_256` | 8875 / 9792 / 9834 | 8875 / 10000 / 10208 | 8417 / 10209 / 14792 |
| `union_exact_512` | 9042 / 10459 / 14709 | 8750 / 9125 / 9125 | 9083 / 10584 / 14375 |
| `intersection_256` | 9041 / 9500 / 9500 | 9208 / 9500 / 10041 | 8709 / 9208 / 9209 |
| `nested_128` | 333 / 708 / 875 | 333 / 417 / 4792 | 334 / 375 / 1750 |
| `targets_511` | 24833 / 25875 / 29458 | 25458 / 32000 / 34500 | 26375 / 30750 / 32083 |
| `wide_indexes_2047` | 316209 / 357916 / 358667 | 317209 / 331291 / 391417 | 339708 / 383833 / 442208 |
| `edges_511` | 95916 / 98167 / 123042 | 98500 / 110125 / 122333 | 105708 / 121958 / 230084 |
| `repeated_128` | 943458 / 1004416 / 1022458 | 922250 / 992875 / 992958 | 936417 / 982708 / 987625 |

### Full

| Workload | Run 1 (ns) | Run 2 (ns) | Run 3 (ns) |
| --- | --- | --- | --- |
| `union_32` | 16375 / 16959 / 17000 | 15792 / 16167 / 16959 | 15834 / 20708 / 37333 |
| `union_128` | 48875 / 49417 / 49459 | 48542 / 50292 / 50417 | 51042 / 52834 / 53542 |
| `union_256` | 96125 / 107167 / 136625 | 92208 / 105917 / 113708 | 93125 / 93708 / 93750 |
| `union_exact_512` | 92375 / 100625 / 105167 | 92666 / 96125 / 96792 | 95333 / 100042 / 102917 |
| `intersection_256` | 94750 / 95750 / 96125 | 93750 / 94708 / 95667 | 94917 / 98459 / 135667 |
| `nested_128` | 11875 / 12584 / 16375 | 11584 / 11791 / 11875 | 11833 / 14167 / 53709 |
| `targets_511` | 289834 / 330250 / 342208 | 288291 / 300000 / 313459 | 304667 / 324291 / 352042 |
| `wide_indexes_2047` | 3445000 / 3565417 / 3571167 | 3498417 / 3652459 / 3671958 | 3724417 / 3894625 / 3985250 |
| `edges_511` | 987250 / 1002250 / 1004708 | 1040208 / 1104667 / 1164750 | 1079625 / 1274416 / 1483375 |
| `repeated_128` | 12193750 / 12530458 / 12615000 | 12060250 / 12523875 / 12630833 | 13824417 / 16386917 / 19577291 |

### Drop

| Workload | Run 1 (ns) | Run 2 (ns) | Run 3 (ns) |
| --- | --- | --- | --- |
| `union_32` | 1500 / 1542 / 1625 | 1416 / 1458 / 1459 | 1583 / 1792 / 1833 |
| `union_128` | 5708 / 5709 / 5750 | 5583 / 5708 / 5709 | 5625 / 5667 / 5750 |
| `union_256` | 11333 / 11958 / 12250 | 11333 / 12209 / 12250 | 12000 / 12583 / 12666 |
| `union_exact_512` | 11375 / 12083 / 12208 | 11375 / 11541 / 11583 | 11583 / 11875 / 23417 |
| `intersection_256` | 11583 / 12209 / 12792 | 11292 / 11417 / 12167 | 11542 / 12125 / 12167 |
| `nested_128` | 250 / 291 / 292 | 250 / 250 / 250 | 292 / 292 / 458 |
| `targets_511` | 16417 / 17542 / 42500 | 16375 / 17959 / 22542 | 17083 / 21417 / 21709 |
| `wide_indexes_2047` | 190667 / 201667 / 217167 | 192542 / 216417 / 227250 | 205417 / 236958 / 262583 |
| `edges_511` | 51375 / 52834 / 55250 | 52333 / 56833 / 57000 | 54208 / 62250 / 79125 |
| `repeated_128` | 1512917 / 1647208 / 1651959 | 1481042 / 1610791 / 1689291 | 1583292 / 2108333 / 2937875 |

### Union median ratios

Each ratio is the workload median divided by `union_32` median for the same
phase and run. These observations do not establish linear complexity.

#### Parse

| Workload | Run 1 | Run 2 | Run 3 |
| --- | ---: | ---: | ---: |
| `union_32` | 1.00× | 1.00× | 1.00× |
| `union_128` | 3.20× | 3.25× | 3.37× |
| `union_256` | 5.97× | 6.40× | 6.33× |
| `union_exact_512` | 5.78× | 6.30× | 6.16× |

#### Validate

| Workload | Run 1 | Run 2 | Run 3 |
| --- | ---: | ---: | ---: |
| `union_32` | 1.00× | 1.00× | 1.00× |
| `union_128` | 2.40× | 2.60× | 2.48× |
| `union_256` | 4.15× | 4.64× | 4.74× |
| `union_exact_512` | 4.10× | 4.39× | 4.33× |

#### Compile

| Workload | Run 1 | Run 2 | Run 3 |
| --- | ---: | ---: | ---: |
| `union_32` | 1.00× | 1.00× | 1.00× |
| `union_128` | 3.01× | 3.01× | 3.05× |
| `union_256` | 5.71× | 5.78× | 5.65× |
| `union_exact_512` | 5.68× | 5.58× | 5.89× |

#### Indexes

| Workload | Run 1 | Run 2 | Run 3 |
| --- | ---: | ---: | ---: |
| `union_32` | 1.00× | 1.00× | 1.00× |
| `union_128` | 3.00× | 3.23× | 3.25× |
| `union_256` | 5.92× | 6.08× | 5.61× |
| `union_exact_512` | 6.03× | 6.00× | 6.06× |

#### Full

| Workload | Run 1 | Run 2 | Run 3 |
| --- | ---: | ---: | ---: |
| `union_32` | 1.00× | 1.00× | 1.00× |
| `union_128` | 2.98× | 3.07× | 3.22× |
| `union_256` | 5.87× | 5.84× | 5.88× |
| `union_exact_512` | 5.64× | 5.87× | 6.02× |

#### Drop

| Workload | Run 1 | Run 2 | Run 3 |
| --- | ---: | ---: | ---: |
| `union_32` | 1.00× | 1.00× | 1.00× |
| `union_128` | 3.81× | 3.94× | 3.55× |
| `union_256` | 7.56× | 8.00× | 7.58× |
| `union_exact_512` | 7.58× | 8.03× | 7.32× |

### Peak RSS

For RSS, the executable path came from the `compiler-artifact` JSON record
for target `relgraph_authz`, `kind: ["lib"]`, with `profile.test: true`.
The discovered executable was
`/Users/enrico/Programming/openfga_dsl/target/release/deps/relgraph_authz-5b7626293854cda4`.
The JSON stream and Cargo stderr are saved as `no-run.json` and `no-run.stderr`
under `/private/tmp/relgraph-task6-20261004/`.

```sh
cargo test -p relgraph-authz --release --lib --no-run --message-format=json > /private/tmp/relgraph-task6-20261004/no-run.json 2> /private/tmp/relgraph-task6-20261004/no-run.stderr
construction_test_executable=/Users/enrico/Programming/openfga_dsl/target/release/deps/relgraph_authz-5b7626293854cda4
RELGRAPH_CONSTRUCTION_COST_CASE=union_exact_512 /usr/bin/time -l "$construction_test_executable" authz::model::construction_costs::measure_construction_costs --ignored --exact --nocapture --test-threads=1
RELGRAPH_CONSTRUCTION_COST_CASE=wide_indexes_2047 /usr/bin/time -l "$construction_test_executable" authz::model::construction_costs::measure_construction_costs --ignored --exact --nocapture --test-threads=1
RELGRAPH_CONSTRUCTION_COST_CASE=edges_511 /usr/bin/time -l "$construction_test_executable" authz::model::construction_costs::measure_construction_costs --ignored --exact --nocapture --test-threads=1
RELGRAPH_CONSTRUCTION_COST_CASE=repeated_128 /usr/bin/time -l "$construction_test_executable" authz::model::construction_costs::measure_construction_costs --ignored --exact --nocapture --test-threads=1
```

Each RSS command started a fresh executable process. On macOS, `/usr/bin/time -l`
reports maximum resident set size in bytes; values below are recorded as
printed, without conversion. The measure includes fixture preparation, the
test harness, and all six phases for one selected workload.

| Workload | Maximum resident set size (bytes) | Captured output |
| --- | ---: | --- |
| `union_exact_512` | 9633792 | `rss-union_exact_512.log` |
| `wide_indexes_2047` | 17383424 | `rss-wide_indexes_2047.log` |
| `edges_511` | 12451840 | `rss-edges_511.log` |
| `repeated_128` | 233979904 | `rss-repeated_128.log` |

All captured RSS logs are under `/private/tmp/relgraph-task6-20261004/`.

## Interpretation of the observations

**Exact-limit chain compilation.** `union_exact_512` has a direct-assignment
root followed by 255 computed-user-set terms, for exactly 512 relation units.
The child stress suite constructed and dropped all ten allowed cases
successfully in debug and release. Its release `compile` medians were
`30750 / 30209 / 31667` ns, and `full` medians were `92375 / 92666 / 95333`
ns across the three runs. These measurements report the current recursive
compiler cost; they do not make a latency guarantee.

**Wide indexes.** `wide_indexes_2047` contains 2,047 independent bucket
relations (4,095 declarations). The `indexes` medians were
`316209 / 317209 / 339708` ns; `full` medians were
`3445000 / 3498417 / 3724417` ns. Its fresh-process peak was 17383424 bytes.
This case measures broad index volume without a reference chain.

**Target and edge fanout.** `targets_511` accepts 511 subject targets; its
`full` medians were `289834 / 288291 / 304667` ns. `edges_511` has 511
compiled tuple-to-userset edges; its `full` medians were
`987250 / 1040208 / 1079625` ns and its fresh-process peak was 12451840 bytes.
Both allowed workloads constructed and dropped in the debug and release
child stress runs.

**Repeated large expressions.** `repeated_128` contains 128 relations with
512 relation units each and 65409 compiled expressions. Its `compile`
medians were `3725667 / 3742083 / 3772625` ns, `full` medians were
`12193750 / 12060250 / 13824417` ns, and `drop` medians were
`1512917 / 1481042 / 1583292` ns. Its fresh-process peak was 233979904 bytes,
the largest of the four measured cases. RSS is a whole-process peak, not a
per-index allocation or live evaluator measurement.

**Destruction.** The `drop` phase times destruction of a prepared compiled
model. Median values were `11375 / 11375 / 11583` ns for `union_exact_512`,
`190667 / 192542 / 205417` ns for `wide_indexes_2047`,
`51375 / 52333 / 54208` ns for `edges_511`, and
`1512917 / 1481042 / 1583292` ns for `repeated_128`. It is reported as its
own operation; no phase medians are subtracted from one another.

The stress results are deterministic success evidence for the listed allowed
inputs on this host. Timings are descriptive observations. Only macOS
aarch64 was measured, and the workspace declares no MSRV, so this report
makes no blanket platform-support claim.
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
  or live evaluator memory. RSS was measured here with macOS `/usr/bin/time -l`.
- No timing threshold is asserted, and measurements do not establish
  authorization runtime speed or broad platform support.
