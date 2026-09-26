//! Authorization model construction and lifecycle state types.

mod model;
mod request;

pub use request::{
    CapabilityDiagnostic, ConstructionError, RelationExpressionKind, RelationLocation,
    RuntimeCapability,
};

use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

use model::CompiledModel;

/// Marker for a compiled authorization model that has no relationship store.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unbound;

/// Marker for a compiled authorization model after it is bound to a store.
///
/// Store binding is introduced in a later runtime slice. Its private field
/// prevents callers from manufacturing a bound model themselves.
pub struct Bound<S>(PhantomData<fn() -> S>);

/// A validated, compiled OpenFGA model in a typed lifecycle state.
///
/// Cloning this value shares its immutable compiled model through an `Arc`.
#[must_use = "constructing an authorization model has no effect until it is used"]
pub struct FgaAuthz<State = Unbound> {
    pub(crate) compiled: Arc<CompiledModel>,
    state: PhantomData<fn() -> State>,
}

impl FgaAuthz<Unbound> {
    /// Parses, semantically validates, checks runtime capabilities, and compiles
    /// an authorization definition synchronously without accessing a store.
    pub fn new(definition: &str) -> Result<Self, ConstructionError> {
        let schema = openfga_dsl::parse_fga_schema(definition).map_err(ConstructionError::Parse)?;
        let compiled = CompiledModel::compile(schema)?;
        Ok(Self {
            compiled: Arc::new(compiled),
            state: PhantomData,
        })
    }

    /// Returns the validated syntax tree used to build this model.
    pub fn schema(&self) -> &openfga_dsl::Schema {
        self.compiled.schema()
    }
}

impl<State> Clone for FgaAuthz<State> {
    fn clone(&self) -> Self {
        Self {
            compiled: Arc::clone(&self.compiled),
            state: PhantomData,
        }
    }
}

impl<State> fmt::Debug for FgaAuthz<State> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FgaAuthz")
            .field("types", &self.compiled.type_count())
            .field("relations", &self.compiled.relation_count())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::FgaAuthz;
    use std::sync::Arc;

    #[test]
    fn cloning_shares_the_compiled_model() {
        let model = FgaAuthz::new("model\nschema 1.1\ntype user\n").unwrap();
        let clone = model.clone();

        assert!(Arc::ptr_eq(&model.compiled, &clone.compiled));
    }
}
