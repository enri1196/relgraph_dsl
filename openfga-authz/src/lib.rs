//! Authorization runtime built on top of the `openfga_dsl` parser.
//! Local OpenFGA authorization runtime.
//!
//! The [`openfga_dsl`] crate remains a parser and semantic validator. This crate
//! owns runtime compilation and authorization APIs built on top of that parser.

mod authz;

pub use authz::{
    Bound, CapabilityDiagnostic, ConstructionError, FgaAuthz, RelationExpressionKind,
    RelationLocation, RuntimeCapability, Unbound,
};
