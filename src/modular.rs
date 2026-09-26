//! Pure assembly and synchronous loading for OpenFGA modular models.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::ast::{ConditionDefinition, Schema, SchemaHeader, TypeDefinition};
use crate::diagnostics::{ParseError, SourceLocation, SourceSpan, ValidationError};
use crate::manifest::{
    ManifestError, ModelManifest, normalize_manifest_path, parse_model_manifest,
    validate_manifest_value,
};
use crate::parse_fga_schema;
use crate::validation::{ValidationIssue, duplicate_relation_error};

/// A parsed module and its normalized manifest-relative identity.
#[derive(Debug, Clone, PartialEq)]
pub struct ModuleSource {
    /// Normalized manifest-relative path identifying this source document.
    pub path: PathBuf,
    /// Parsed module document. Its header must be [`SchemaHeader::Module`].
    pub schema: Schema,
}

/// A composed model together with the original module documents and provenance.
#[derive(Debug, Clone, PartialEq)]
pub struct ModularModel {
    /// Parsed and validated manifest value used to compose this model.
    pub manifest: ModelManifest,
    /// Original module declarations in manifest order.
    pub modules: Vec<ModuleSource>,
    /// Assembled schema with base types and extension relations merged.
    pub schema: Schema,
    /// Origins aligned with [`Schema::type_definitions`].
    pub type_origins: Vec<SourceLocation>,
    /// Origins aligned with each type's relations.
    pub relation_origins: Vec<Vec<SourceLocation>>,
    /// Origins aligned with [`Schema::condition_definitions`].
    pub condition_origins: Vec<SourceLocation>,
}

/// Errors returned while assembling or loading a modular model.
#[derive(Debug)]
pub enum ModularModelError {
    /// Reading a manifest or module file failed.
    Io {
        /// Joined filesystem path that could not be read as UTF-8 text.
        path: PathBuf,
        /// Module entry index, or `None` when reading the manifest.
        entry: Option<usize>,
        /// Underlying filesystem or UTF-8 decoding error.
        source: io::Error,
    },
    /// The manifest file could not be parsed under the manifest contract.
    Manifest {
        /// Filesystem path of the manifest.
        path: PathBuf,
        /// Manifest diagnostic.
        source: ManifestError,
    },
    /// A manually constructed manifest value violates the manifest contract.
    InvalidManifest {
        /// Path-free manifest diagnostic.
        source: ManifestError,
    },
    /// A module file failed to parse.
    Parse {
        /// Normalized manifest-relative identity of the module.
        path: PathBuf,
        /// Manifest entry index.
        entry: usize,
        /// Parser diagnostic.
        source: ParseError,
    },
    /// Supplied module sources do not exactly match manifest entries.
    InputMismatch {
        /// First differing, missing, or extra zero-based entry.
        entry: usize,
        /// Explanation of the mismatch.
        message: String,
    },
    /// A source document has a standalone model header instead of a module header.
    NonModuleDocument {
        /// Normalized manifest-relative identity of the document.
        path: PathBuf,
        /// Manifest entry index.
        entry: usize,
    },
    /// One or more structural composition rules failed.
    Composition {
        /// Structural diagnostics in deterministic order.
        errors: Vec<ValidationError>,
    },
}

impl fmt::Display for ModularModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                path,
                entry: None,
                source,
            } => write!(
                formatter,
                "could not read manifest '{}': {source}",
                path.display()
            ),
            Self::Io {
                path,
                entry: Some(entry),
                source,
            } => write!(
                formatter,
                "could not read module entry {entry} at '{}': {source}",
                path.display()
            ),
            Self::Manifest { path, source } => {
                write!(formatter, "invalid manifest '{}': {source}", path.display())
            }
            Self::InvalidManifest { source } => {
                write!(formatter, "invalid manifest value: {source}")
            }
            Self::Parse {
                path,
                entry,
                source,
            } => write!(
                formatter,
                "could not parse module entry {entry} ('{}'): {source}",
                path.display()
            ),
            Self::InputMismatch { entry, message } => {
                write!(
                    formatter,
                    "module input mismatch at entry {entry}: {message}"
                )
            }
            Self::NonModuleDocument { path, entry } => write!(
                formatter,
                "entry {entry} ('{}') does not have a module header",
                path.display()
            ),
            Self::Composition { errors } => write!(
                formatter,
                "modular model has {} structural composition error(s)",
                errors.len()
            ),
        }
    }
}

impl Error for ModularModelError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Manifest { source, .. } | Self::InvalidManifest { source } => Some(source),
            Self::Parse { source, .. } => Some(source),
            Self::InputMismatch { .. }
            | Self::NonModuleDocument { .. }
            | Self::Composition { .. } => None,
        }
    }
}

/// Assembles parsed module documents without filesystem access or semantic validation.
///
/// The supplied module paths and order must match the manifest exactly. Assembly
/// combines base types and extension relations and records source origins, but
/// does not check schema versions, ordinary references, CEL, or static validation
/// rules. Call [`validate_modular_model`] separately when those checks are needed.
///
/// ```
/// use openfga_dsl::{
///     ModelManifest, ModuleSource, assemble_modular_model, parse_fga_schema,
///     validate_modular_model,
/// };
/// use std::path::PathBuf;
///
/// let manifest = ModelManifest {
///     schema: "1.2".to_owned(),
///     contents: vec![PathBuf::from("base.fga")],
/// };
/// let module = ModuleSource {
///     path: PathBuf::from("base.fga"),
///     schema: parse_fga_schema("module core\n\ntype user\n")
///         .expect("module syntax is valid"),
/// };
/// let model = assemble_modular_model(manifest, vec![module])
///     .expect("module structure is valid");
/// validate_modular_model(&model).expect("model passes bounded validation");
/// ```
pub fn assemble_modular_model(
    manifest: ModelManifest,
    modules: Vec<ModuleSource>,
) -> Result<ModularModel, ModularModelError> {
    validate_manifest_value(&manifest)
        .map_err(|source| ModularModelError::InvalidManifest { source })?;
    check_module_inputs(&manifest, &modules)?;

    let module_names = modules
        .iter()
        .enumerate()
        .map(|(entry, module)| match &module.schema.header {
            SchemaHeader::Module { name } => Ok(name.clone()),
            SchemaHeader::ModelSchema { .. } => Err(ModularModelError::NonModuleDocument {
                path: manifest.contents[entry].clone(),
                entry,
            }),
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut errors = Vec::<(usize, ValidationError)>::new();
    let mut assembled_types = Vec::<TypeDefinition>::new();
    let mut type_origins = Vec::<SourceLocation>::new();
    let mut relation_origins = Vec::<Vec<SourceLocation>>::new();
    let mut first_base_types = HashMap::<String, SourceLocation>::new();
    let mut base_counts = HashMap::<String, usize>::new();
    let mut base_indices = HashMap::<String, usize>::new();
    let mut relation_declarations = HashMap::<(String, String), SourceLocation>::new();

    // All base declarations are processed first, preserving their manifest and declaration order.
    for (entry, module) in modules.iter().enumerate() {
        let source_path = &manifest.contents[entry];
        let module_name = &module_names[entry];
        for definition in module
            .schema
            .type_definitions
            .iter()
            .filter(|definition| !definition.is_extended)
        {
            *base_counts.entry(definition.name.clone()).or_default() += 1;
            let type_origin = source_location(source_path, module_name, definition.span.as_ref());
            let first_index = if let Some(first) = first_base_types.get(&definition.name) {
                errors.push((
                    entry,
                    ValidationError {
                        issue: ValidationIssue::DuplicateType,
                        location: type_origin.clone(),
                        related: vec![first.clone()],
                        message: format!("type '{}' is declared more than once", definition.name),
                    },
                ));
                None
            } else {
                first_base_types.insert(definition.name.clone(), type_origin.clone());
                let index = assembled_types.len();
                base_indices.insert(definition.name.clone(), index);
                let mut base = definition.clone();
                base.is_extended = false;
                base.relations.clear();
                assembled_types.push(base);
                type_origins.push(type_origin);
                relation_origins.push(Vec::new());
                Some(index)
            };

            for relation in &definition.relations {
                let relation_origin =
                    source_location(source_path, module_name, relation.span.as_ref());
                let key = (definition.name.clone(), relation.name.clone());
                if let Some(first) = relation_declarations.get(&key) {
                    errors.push((
                        entry,
                        duplicate_relation_error(
                            &definition.name,
                            &relation.name,
                            relation_origin.clone(),
                            first.clone(),
                        ),
                    ));
                } else {
                    relation_declarations.insert(key, relation_origin.clone());
                }
                if let Some(index) = first_index {
                    assembled_types[index].relations.push(relation.clone());
                    relation_origins[index].push(relation_origin);
                }
            }
        }
    }

    let mut first_extensions_in_file = HashMap::<(usize, String), SourceLocation>::new();
    let mut conditions = Vec::<ConditionDefinition>::new();
    let mut condition_origins = Vec::<SourceLocation>::new();

    // Extensions are visited only after every base has been collected, even if they appeared first.
    for (entry, module) in modules.iter().enumerate() {
        let source_path = &manifest.contents[entry];
        let module_name = &module_names[entry];
        for definition in module
            .schema
            .type_definitions
            .iter()
            .filter(|definition| definition.is_extended)
        {
            let extension_origin =
                source_location(source_path, module_name, definition.span.as_ref());
            let extension_key = (entry, definition.name.clone());
            if let Some(first) = first_extensions_in_file.get(&extension_key) {
                errors.push((
                    entry,
                    ValidationError {
                        issue: ValidationIssue::DuplicateExtension,
                        location: extension_origin.clone(),
                        related: vec![first.clone()],
                        message: format!(
                            "module file extends type '{}' more than once",
                            definition.name
                        ),
                    },
                ));
            } else {
                first_extensions_in_file.insert(extension_key, extension_origin.clone());
            }

            let base_count = base_counts.get(&definition.name).copied().unwrap_or(0);
            if base_count == 0 {
                errors.push((
                    entry,
                    ValidationError {
                        issue: ValidationIssue::UnknownExtensionType,
                        location: extension_origin,
                        related: Vec::new(),
                        message: format!(
                            "extension refers to type '{}' with no base declaration",
                            definition.name
                        ),
                    },
                ));
                push_local_extension_relation_duplicates(
                    &mut errors,
                    entry,
                    source_path,
                    module_name,
                    definition,
                );
                continue;
            }
            if base_count > 1 {
                // Ambiguous bases prevent the extension from being safely merged.
                push_local_extension_relation_duplicates(
                    &mut errors,
                    entry,
                    source_path,
                    module_name,
                    definition,
                );
                continue;
            }

            let index = base_indices[&definition.name];
            for relation in &definition.relations {
                let relation_origin =
                    source_location(source_path, module_name, relation.span.as_ref());
                let key = (definition.name.clone(), relation.name.clone());
                if let Some(first) = relation_declarations.get(&key) {
                    errors.push((
                        entry,
                        duplicate_relation_error(
                            &definition.name,
                            &relation.name,
                            relation_origin.clone(),
                            first.clone(),
                        ),
                    ));
                } else {
                    relation_declarations.insert(key, relation_origin.clone());
                }
                assembled_types[index].relations.push(relation.clone());
                relation_origins[index].push(relation_origin);
            }
        }

        for condition in &module.schema.condition_definitions {
            conditions.push(condition.clone());
            condition_origins.push(source_location(
                source_path,
                module_name,
                condition.span.as_ref(),
            ));
        }
    }

    if !errors.is_empty() {
        let errors = sort_composition_errors(errors);
        return Err(ModularModelError::Composition { errors });
    }

    Ok(ModularModel {
        schema: Schema {
            header: SchemaHeader::ModelSchema {
                version: manifest.schema.clone(),
            },
            header_span: None,
            type_definitions: assembled_types,
            condition_definitions: conditions,
        },
        manifest,
        modules,
        type_origins,
        relation_origins,
        condition_origins,
    })
}

/// Loads the manifest and each listed module once, in manifest order, then assembles them.
/// Validates the public assembled schema and its source provenance.
///
/// The model is recomposed from its retained manifest and module documents
/// first, so callers cannot bypass structural checks by mutating public fields.
/// Verifies the public composition invariants and applies modular static checks.
///
/// Modular models require the exact version `1.2`. Diagnostics retain manifest
/// path, module name, and declaration spans. As with standalone validation, CEL
/// is not compiled or evaluated and server-only limits are outside this API.
pub fn validate_modular_model(model: &ModularModel) -> Result<(), Vec<ValidationError>> {
    let recomposed = match assemble_modular_model(model.manifest.clone(), model.modules.clone()) {
        Ok(recomposed) => recomposed,
        Err(ModularModelError::Composition { errors }) => {
            let mut result = vec![invalid_composition(
                "retained modules have structural composition errors",
            )];
            result.extend(errors);
            return Err(result);
        }
        Err(error) => {
            return Err(vec![invalid_composition(format!(
                "retained manifest and modules cannot be recomposed: {error}"
            ))]);
        }
    };

    let mut failed_invariants = Vec::new();
    if model.schema != recomposed.schema {
        failed_invariants.push("assembled schema differs from recomposition");
    }
    if model.type_origins != recomposed.type_origins {
        failed_invariants.push("type origins differ from recomposition");
    }
    if model.relation_origins != recomposed.relation_origins {
        failed_invariants.push("relation origins differ from recomposition");
    }
    if model.condition_origins != recomposed.condition_origins {
        failed_invariants.push("condition origins differ from recomposition");
    }
    if !failed_invariants.is_empty() {
        return Err(vec![invalid_composition(format!(
            "public modular model invariant failed: {}",
            failed_invariants.join("; ")
        ))]);
    }

    crate::validation::validate_schema_with_origins(
        &model.schema,
        crate::validation::ValidationOrigins {
            type_origins: &model.type_origins,
            relation_origins: &model.relation_origins,
            condition_origins: &model.condition_origins,
        },
        &model.manifest.contents,
    )
}

fn invalid_composition(message: impl Into<String>) -> ValidationError {
    ValidationError {
        issue: ValidationIssue::InvalidComposition,
        location: SourceLocation {
            file: None,
            module: None,
            span: None,
        },
        related: Vec::new(),
        message: message.into(),
    }
}

/// Synchronously reads a manifest and each listed module file once.
///
/// The manifest path is resolved from the process working directory; content
/// paths are resolved against the manifest's parent. Loading does not discover
/// files, use the network, or run static validation. After loading, call
/// [`validate_modular_model`] explicitly.
///
/// ```no_run
/// use openfga_dsl::{load_modular_model, validate_modular_model};
///
/// let model = load_modular_model(std::path::Path::new("model.yaml"))
///     .expect("manifest and listed module files should load");
/// validate_modular_model(&model).expect("model should pass bounded validation");
/// ```
pub fn load_modular_model(manifest_path: &Path) -> Result<ModularModel, ModularModelError> {
    load_modular_model_with_reader(manifest_path, |path| fs::read_to_string(path))
}

/// Loads through an injectable reader so file access order and failures can be tested.
fn load_modular_model_with_reader<F>(
    manifest_path: &Path,
    mut read_text: F,
) -> Result<ModularModel, ModularModelError>
where
    F: FnMut(&Path) -> io::Result<String>,
{
    let manifest_text = read_text(manifest_path).map_err(|source| ModularModelError::Io {
        path: manifest_path.to_path_buf(),
        entry: None,
        source,
    })?;
    let manifest =
        parse_model_manifest(&manifest_text).map_err(|source| ModularModelError::Manifest {
            path: manifest_path.to_path_buf(),
            source,
        })?;
    let content_root = manifest_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut modules = Vec::with_capacity(manifest.contents.len());

    for (entry, relative_path) in manifest.contents.iter().enumerate() {
        let filesystem_path = content_root.join(relative_path);
        let source_text = read_text(&filesystem_path).map_err(|source| ModularModelError::Io {
            path: filesystem_path.clone(),
            entry: Some(entry),
            source,
        })?;
        let schema = parse_fga_schema(&source_text).map_err(|source| ModularModelError::Parse {
            path: relative_path.clone(),
            entry,
            source,
        })?;
        if !matches!(&schema.header, SchemaHeader::Module { .. }) {
            return Err(ModularModelError::NonModuleDocument {
                path: relative_path.clone(),
                entry,
            });
        }
        modules.push(ModuleSource {
            path: relative_path.clone(),
            schema,
        });
    }

    assemble_modular_model(manifest, modules)
}

/// Checks source count and normalized identities before inspecting module declarations.
fn check_module_inputs(
    manifest: &ModelManifest,
    modules: &[ModuleSource],
) -> Result<(), ModularModelError> {
    let expected_count = manifest.contents.len();
    let input_count = modules.len();
    for entry in 0..expected_count.max(input_count) {
        let Some(expected) = manifest.contents.get(entry) else {
            return Err(ModularModelError::InputMismatch {
                entry,
                message: format!(
                    "unexpected extra module source '{}'",
                    modules[entry].path.display()
                ),
            });
        };
        let Some(module) = modules.get(entry) else {
            return Err(ModularModelError::InputMismatch {
                entry,
                message: format!("missing module source for '{}'", expected.display()),
            });
        };
        let Some(path_text) = module.path.to_str() else {
            return Err(ModularModelError::InputMismatch {
                entry,
                message: "module source path is not valid UTF-8".to_string(),
            });
        };
        let normalized = normalize_manifest_path(path_text).map_err(|message| {
            ModularModelError::InputMismatch {
                entry,
                message: format!("module source path is invalid: {message}"),
            }
        })?;
        if normalized.to_str() != Some(path_text) {
            return Err(ModularModelError::InputMismatch {
                entry,
                message: format!(
                    "module source path '{}' is not normalized",
                    module.path.display()
                ),
            });
        }
        if normalized != *expected {
            return Err(ModularModelError::InputMismatch {
                entry,
                message: format!(
                    "expected '{}' but received '{}'",
                    expected.display(),
                    normalized.display()
                ),
            });
        }
    }
    Ok(())
}

/// Builds provenance for a declaration from its manifest identity and parsed span.
fn source_location(path: &Path, module: &str, span: Option<&SourceSpan>) -> SourceLocation {
    SourceLocation {
        file: Some(path.to_path_buf()),
        module: Some(module.to_string()),
        span: span.cloned(),
    }
}

/// Reports duplicate relation names local to an extension without choosing a base declaration.
fn push_local_extension_relation_duplicates(
    errors: &mut Vec<(usize, ValidationError)>,
    entry: usize,
    source_path: &Path,
    module_name: &str,
    definition: &TypeDefinition,
) {
    let mut seen = HashMap::<String, SourceLocation>::new();
    for relation in &definition.relations {
        let location = source_location(source_path, module_name, relation.span.as_ref());
        if let Some(first) = seen.get(&relation.name) {
            errors.push((
                entry,
                duplicate_relation_error(&definition.name, &relation.name, location, first.clone()),
            ));
        } else {
            seen.insert(relation.name.clone(), location);
        }
    }
}

/// Orders structural diagnostics by manifest entry and source position, then removes duplicates.
fn sort_composition_errors(mut errors: Vec<(usize, ValidationError)>) -> Vec<ValidationError> {
    errors.sort_by(|(left_entry, left), (right_entry, right)| {
        left_entry
            .cmp(right_entry)
            .then_with(|| span_start(&left.location).cmp(&span_start(&right.location)))
            .then_with(|| left.issue.code().cmp(right.issue.code()))
            .then_with(|| left.message.cmp(&right.message))
    });
    errors.dedup_by(|right, left| {
        right.1.issue == left.1.issue
            && right.1.location == left.1.location
            && right.1.message == left.1.message
    });
    errors.into_iter().map(|(_, error)| error).collect()
}

/// Returns the declaration offset, placing locations without spans after parsed declarations.
fn span_start(location: &SourceLocation) -> usize {
    location.span.as_ref().map_or(usize::MAX, |span| span.start)
}

#[cfg(test)]
mod internal_tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[test]
    fn injected_reader_reads_manifest_and_each_entry_once() {
        let manifest_path = Path::new("model.yaml");
        let inputs = HashMap::from([
            (
                "model.yaml",
                "schema: '1.2'\ncontents: [a.fga, b.fga]\n".to_string(),
            ),
            ("a.fga", "module shared\n\ntype user\n".to_string()),
            ("b.fga", "module shared\n\ntype document\n".to_string()),
        ]);
        let reads = RefCell::new(Vec::<String>::new());
        let model = load_modular_model_with_reader(manifest_path, |path| {
            let key = path.file_name().unwrap().to_string_lossy().to_string();
            reads.borrow_mut().push(key.clone());
            inputs.get(key.as_str()).cloned().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("unexpected read: {key}"))
            })
        })
        .unwrap();

        assert_eq!(model.modules.len(), 2);
        assert_eq!(reads.into_inner(), ["model.yaml", "a.fga", "b.fga"]);
    }

    #[test]
    fn injected_io_error_stops_at_the_failing_entry_with_context() {
        let error = load_modular_model_with_reader(Path::new("model.yaml"), |path| {
            match path.file_name().and_then(|name| name.to_str()) {
                Some("model.yaml") => Ok("schema: '1.2'\ncontents: [a.fga, b.fga]\n".to_string()),
                Some("a.fga") => Err(io::Error::new(io::ErrorKind::PermissionDenied, "injected")),
                other => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("unexpected read: {other:?}"),
                )),
            }
        })
        .unwrap_err();

        assert!(matches!(
            error,
            ModularModelError::Io {
                entry: Some(0),
                source,
                ..
            } if source.kind() == io::ErrorKind::PermissionDenied
        ));
    }
}
