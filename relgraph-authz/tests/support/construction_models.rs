/// One generated model used by construction stress tests and measurements.
pub struct ConstructionCase {
    /// Stable case name used by child-process selection and measurement output.
    pub name: &'static str,
    /// Complete model definition.
    pub source: String,
    /// Number of schema declarations in the generated model.
    pub declarations: usize,
    /// Maximum expression and target node units in any relation.
    pub maximum_relation_units: usize,
}

/// Returns the fixed construction workloads in their required execution order.
pub fn construction_cases() -> Vec<ConstructionCase> {
    vec![
        ConstructionCase {
            name: "union_32",
            source: union_model(32, false),
            declarations: 35,
            maximum_relation_units: 63,
        },
        ConstructionCase {
            name: "union_128",
            source: union_model(128, false),
            declarations: 131,
            maximum_relation_units: 255,
        },
        ConstructionCase {
            name: "union_256",
            source: union_model(256, false),
            declarations: 259,
            maximum_relation_units: 511,
        },
        ConstructionCase {
            name: "union_exact_512",
            source: union_model(256, true),
            declarations: 258,
            maximum_relation_units: 512,
        },
        ConstructionCase {
            name: "intersection_256",
            source: intersection_model(256),
            declarations: 259,
            maximum_relation_units: 511,
        },
        ConstructionCase {
            name: "nested_128",
            source: nested_model(128),
            declarations: 3,
            maximum_relation_units: 2,
        },
        ConstructionCase {
            name: "targets_511",
            source: target_fanout_model(511),
            declarations: 513,
            maximum_relation_units: 512,
        },
        ConstructionCase {
            name: "wide_indexes_2047",
            source: wide_index_model(2047),
            declarations: 4095,
            maximum_relation_units: 2,
        },
        ConstructionCase {
            name: "edges_511",
            source: edge_fanout_model(511),
            declarations: 1026,
            maximum_relation_units: 512,
        },
        ConstructionCase {
            name: "repeated_128",
            source: repeated_expression_model(128),
            declarations: 385,
            maximum_relation_units: 512,
        },
    ]
}

/// Operand names `base000`, `base001`, ... for terms `first..terms`. OpenFGA
/// rejects a repeated operand, so every computed-userset term is distinct.
fn base_names(first: usize, terms: usize) -> Vec<String> {
    (first..terms)
        .map(|term| format!("base{term:03}"))
        .collect()
}

/// One `define <name>: [user]` declaration per operand name.
fn base_relations(names: &[String]) -> String {
    names
        .iter()
        .map(|name| format!("  define {name}: [user]\n"))
        .collect()
}

/// Generates a flat union of distinct computed usersets, optionally starting
/// with `[user]`.
pub fn union_model(terms: usize, direct_root: bool) -> String {
    let names = base_names(usize::from(direct_root), terms);
    let mut operands = Vec::with_capacity(terms);
    if direct_root && terms > 0 {
        operands.push(String::from("[user]"));
    }
    operands.extend(names.iter().cloned());
    let expression = operands.join(" or ");

    format!(
        "model\nschema 1.1\ntype user\ntype document\n relations\n{}  define viewer: {expression}\n",
        base_relations(&names)
    )
}

/// Generates a flat intersection of distinct computed usersets.
pub fn intersection_model(terms: usize) -> String {
    let names = base_names(0, terms);
    let expression = names.join(" and ");

    format!(
        "model\nschema 1.1\ntype user\ntype document\n relations\n{}  define viewer: {expression}\n",
        base_relations(&names)
    )
}

/// Generates a direct assignment wrapped in exactly `depth` parentheses.
pub fn nested_model(depth: usize) -> String {
    format!(
        "model\nschema 1.1\ntype user\ntype document\n relations\n  define viewer: {}[user]{}\n",
        "(".repeat(depth),
        ")".repeat(depth),
    )
}

/// Generates one direct assignment with `targets` distinct type restrictions.
pub fn target_fanout_model(targets: usize) -> String {
    let mut model = String::from("model\nschema 1.1\n");
    for index in 0..targets {
        model.push_str(&format!("type s{index:04}\n"));
    }

    model.push_str("type document\n relations\n  define viewer: [");
    for index in 0..targets {
        if index > 0 {
            model.push_str(", ");
        }
        model.push_str(&format!("s{index:04}"));
    }
    model.push_str("]\n");
    model
}

/// Generates independent bucket relations to stress type and relation indexes.
pub fn wide_index_model(types: usize) -> String {
    let mut model = String::from("model\nschema 1.1\ntype user\n");
    for index in 0..types {
        model.push_str(&format!(
            "type bucket{index:04}\n relations\n  define member: [user]\n"
        ));
    }
    model
}

/// Generates tuple-to-userset edges from one document parent relation to many node types.
pub fn edge_fanout_model(targets: usize) -> String {
    let mut model = String::from("model\nschema 1.1\ntype user\n");
    for index in 0..targets {
        model.push_str(&format!(
            "type node{index:04}\n relations\n  define member: [user]\n"
        ));
    }

    model.push_str("type document\n relations\n  define parent: [");
    for index in 0..targets {
        if index > 0 {
            model.push_str(", ");
        }
        model.push_str(&format!("node{index:04}"));
    }
    model.push_str("]\n  define viewer: member from parent\n");
    model
}

/// Generates many relations containing the same exact-limit direct-assignment
/// union of 255 distinct computed usersets.
pub fn repeated_expression_model(relations: usize) -> String {
    let names = base_names(1, 256);
    let mut model = String::from("model\nschema 1.1\ntype user\ntype document\n relations\n");
    model.push_str(&base_relations(&names));
    let expression = format!("[user] or {}", names.join(" or "));
    for index in 0..relations {
        model.push_str(&format!("  define viewer{index:04}: {expression}\n"));
    }
    model
}
