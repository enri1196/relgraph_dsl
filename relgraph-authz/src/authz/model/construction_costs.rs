use std::collections::HashMap;
use std::hint::black_box;
use std::time::Instant;

use relgraph_dsl::{parse_fga_schema, validate_schema};

use super::super::FgaAuthz;
use super::CompiledModel;

mod construction_models {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/support/construction_models.rs"
    ));
}

const WARMUP_SAMPLES: usize = 3;
const MEASURED_SAMPLES: usize = 21;
const MEASUREMENT_CASE_ENV: &str = "RELGRAPH_CONSTRUCTION_COST_CASE";

#[derive(Clone, Copy)]
enum ConstructionPhase {
    Parse,
    Validate,
    Compile,
    Indexes,
    Full,
    Drop,
}

struct ConstructionMeasurement {
    case: &'static str,
    phase: ConstructionPhase,
    source_bytes: usize,
    declarations: usize,
    maximum_relation_units: usize,
    samples_ns: Vec<u128>,
}

#[test]
#[ignore = "manual construction cost measurement"]
fn measure_construction_costs() {
    let cases = construction_models::construction_cases();
    let selected_case = match std::env::var(MEASUREMENT_CASE_ENV) {
        Ok(name) => Some(
            cases
                .iter()
                .find(|case| case.name == name)
                .unwrap_or_else(|| panic!("unknown construction measurement case: {name}")),
        ),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => panic!("could not read {MEASUREMENT_CASE_ENV}: {error}"),
    };

    println!(
        "case,phase,source_bytes,declarations,maximum_relation_units,samples,median_ns,p95_ns,max_ns"
    );
    for case in cases
        .iter()
        .filter(|case| selected_case.is_none_or(|selected| selected.name == case.name))
    {
        let parsed = parse_fga_schema(&case.source).expect("construction case must parse");
        validate_schema(&parsed).expect("construction case must validate");
        let compiled = CompiledModel::compile_validated(parsed.clone())
            .expect("construction case must compile");

        assert_eq!(compiled.type_index.len(), parsed.type_definitions.len());
        assert_eq!(compiled.relation_index.len(), parsed.type_definitions.len());
        let source_relation_count: usize = parsed
            .type_definitions
            .iter()
            .map(|type_definition| type_definition.relations.len())
            .sum();
        let indexed_relation_count: usize = compiled.relation_index.iter().map(HashMap::len).sum();
        assert_eq!(indexed_relation_count, source_relation_count);
        assert_eq!(compiled.relations.len(), source_relation_count);
        assert!(parsed.condition_definitions.is_empty());

        let (expressions, relations, targets, edges) = match case.name {
            "union_32" => (64, None, None, None),
            "union_128" => (256, None, None, None),
            "union_256" | "union_exact_512" | "intersection_256" => (512, None, None, None),
            "nested_128" | "targets_511" => (1, None, None, None),
            "wide_indexes_2047" => (2047, Some(2047), None, None),
            "edges_511" => (513, Some(513), Some(1022), Some(511)),
            "repeated_128" => (65_409, Some(129), Some(129), None),
            name => panic!("unexpected construction case: {name}"),
        };
        assert_eq!(compiled.expressions.len(), expressions, "{}", case.name);
        if let Some(relations) = relations {
            assert_eq!(compiled.relations.len(), relations, "{}", case.name);
        }
        if let Some(targets) = targets {
            assert_eq!(compiled.targets.len(), targets, "{}", case.name);
        }
        if let Some(edges) = edges {
            assert_eq!(
                compiled.tuple_to_userset_edges.len(),
                edges,
                "{}",
                case.name
            );
        }
        drop(compiled);

        for measurement in measure_case(case) {
            print_measurement(&measurement);
        }
    }
}

fn measure_case(case: &construction_models::ConstructionCase) -> Vec<ConstructionMeasurement> {
    [
        ConstructionPhase::Parse,
        ConstructionPhase::Validate,
        ConstructionPhase::Compile,
        ConstructionPhase::Indexes,
        ConstructionPhase::Full,
        ConstructionPhase::Drop,
    ]
    .into_iter()
    .map(|phase| measure_phase(case, phase))
    .collect()
}

fn measure_phase(
    case: &construction_models::ConstructionCase,
    phase: ConstructionPhase,
) -> ConstructionMeasurement {
    for _ in 0..WARMUP_SAMPLES {
        black_box(measure_sample(case, phase));
    }
    let samples_ns = (0..MEASURED_SAMPLES)
        .map(|_| measure_sample(case, phase))
        .collect();

    ConstructionMeasurement {
        case: case.name,
        phase,
        source_bytes: case.source.len(),
        declarations: case.declarations,
        maximum_relation_units: case.maximum_relation_units,
        samples_ns,
    }
}

fn measure_sample(case: &construction_models::ConstructionCase, phase: ConstructionPhase) -> u128 {
    match phase {
        ConstructionPhase::Parse => {
            let source = case.source.as_str();
            let started = Instant::now();
            let parsed = black_box(parse_fga_schema(black_box(source)));
            let elapsed = started.elapsed().as_nanos();
            assert!(parsed.is_ok(), "{} must parse", case.name);
            drop(parsed);
            elapsed
        }
        ConstructionPhase::Validate => {
            let parsed = parse_fga_schema(&case.source).expect("construction case must parse");
            let started = Instant::now();
            let validation = black_box(validate_schema(black_box(&parsed)));
            let elapsed = started.elapsed().as_nanos();
            assert!(validation.is_ok(), "{} must validate", case.name);
            drop(validation);
            drop(parsed);
            elapsed
        }
        ConstructionPhase::Compile => {
            let parsed = parse_fga_schema(&case.source).expect("construction case must parse");
            validate_schema(&parsed).expect("construction case must validate");
            let owned_validated_schema = parsed.clone();
            let started = Instant::now();
            let compiled = black_box(CompiledModel::compile_validated(black_box(
                owned_validated_schema,
            )));
            let elapsed = started.elapsed().as_nanos();
            assert!(compiled.is_ok(), "{} must compile", case.name);
            drop(compiled);
            drop(parsed);
            elapsed
        }
        ConstructionPhase::Indexes => {
            let parsed = parse_fga_schema(&case.source).expect("construction case must parse");
            validate_schema(&parsed).expect("construction case must validate");
            assert!(parsed.condition_definitions.is_empty());
            let owned_validated_schema = parsed.clone();
            let started = Instant::now();
            let compiled = black_box(CompiledModel::compile_indexes(
                black_box(owned_validated_schema),
                HashMap::new(),
            ));
            let elapsed = started.elapsed().as_nanos();
            black_box(compiled);
            drop(parsed);
            elapsed
        }
        ConstructionPhase::Full => {
            let source = case.source.as_str();
            let started = Instant::now();
            let compiled = black_box(FgaAuthz::new(black_box(source)));
            let elapsed = started.elapsed().as_nanos();
            assert!(compiled.is_ok(), "{} must construct", case.name);
            drop(compiled);
            elapsed
        }
        ConstructionPhase::Drop => {
            let parsed = parse_fga_schema(&case.source).expect("construction case must parse");
            validate_schema(&parsed).expect("construction case must validate");
            let compiled =
                CompiledModel::compile_validated(parsed).expect("construction case must compile");
            let started = Instant::now();
            drop(black_box(compiled));
            started.elapsed().as_nanos()
        }
    }
}

fn print_measurement(measurement: &ConstructionMeasurement) {
    let mut samples = measurement.samples_ns.clone();
    samples.sort_unstable();
    let phase = match measurement.phase {
        ConstructionPhase::Parse => "parse",
        ConstructionPhase::Validate => "validate",
        ConstructionPhase::Compile => "compile",
        ConstructionPhase::Indexes => "indexes",
        ConstructionPhase::Full => "full",
        ConstructionPhase::Drop => "drop",
    };
    println!(
        "{},{},{},{},{},{},{},{},{}",
        measurement.case,
        phase,
        measurement.source_bytes,
        measurement.declarations,
        measurement.maximum_relation_units,
        samples.len(),
        samples[10],
        samples[19],
        samples[20]
    );
}
