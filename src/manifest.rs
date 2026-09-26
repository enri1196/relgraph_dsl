//! Parsing and validating OpenFGA modular-model manifest YAML.
//!
//! This module validates manifest structure and normalized relative paths only.
//! It performs no filesystem access or module loading.

use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::path::PathBuf;

use serde::de::{EnumAccess, MapAccess, VariantAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_yaml::Deserializer as YamlDeserializer;

/// A parsed modular-model manifest, with paths normalized in manifest order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelManifest {
    /// The version string exactly as written in the YAML scalar.
    pub schema: String,
    /// Normalized relative module paths in their original entry order.
    pub contents: Vec<PathBuf>,
}

/// A stable category for a manifest parsing failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestErrorCode {
    /// The YAML document is malformed or contains more than one document.
    InvalidYaml,
    /// The single YAML document does not have a mapping root.
    InvalidRoot,
    /// A required top-level field is absent.
    MissingField,
    /// The manifest contains an unrecognized top-level field.
    UnknownField,
    /// A top-level field occurs more than once.
    DuplicateField,
    /// A YAML key or value has the wrong scalar/container type.
    WrongType,
    /// The schema string does not match the required numeric version form.
    InvalidSchemaVersion,
    /// The contents sequence is empty.
    EmptyContents,
    /// A module path violates the manifest path policy.
    InvalidPath,
    /// Two entries normalize to the same module path.
    DuplicatePath,
    /// The document contains an explicit YAML tag.
    UnsupportedYamlFeature,
}

impl ManifestErrorCode {
    /// Returns the stable PascalCase diagnostic code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidYaml => "InvalidYaml",
            Self::InvalidRoot => "InvalidRoot",
            Self::MissingField => "MissingField",
            Self::UnknownField => "UnknownField",
            Self::DuplicateField => "DuplicateField",
            Self::WrongType => "WrongType",
            Self::InvalidSchemaVersion => "InvalidSchemaVersion",
            Self::EmptyContents => "EmptyContents",
            Self::InvalidPath => "InvalidPath",
            Self::DuplicatePath => "DuplicatePath",
            Self::UnsupportedYamlFeature => "UnsupportedYamlFeature",
        }
    }
}

/// A manifest parsing error with an optional field path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestError {
    /// Stable machine-readable error category.
    pub code: ManifestErrorCode,
    /// Top-level field or zero-based contents entry associated with the error.
    pub field: Option<String>,
    /// Human-readable explanation; wording is not a stable API.
    pub message: String,
}

impl fmt::Display for ManifestError {
    /// Formats the diagnostic code, field when present, and message.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.field {
            Some(field) => write!(
                formatter,
                "{} at {field}: {}",
                self.code.code(),
                self.message
            ),
            None => write!(formatter, "{}: {}", self.code.code(), self.message),
        }
    }
}

impl Error for ManifestError {}

/// Parses one manifest YAML document and applies the crate's manifest policies.
///
/// This function performs no filesystem I/O. It requires exactly one mapping
/// with only `schema` and `contents` keys; `schema` must be a YAML string
/// matching ASCII `major.minor`, and `contents` must be a nonempty list of
/// strings. Relative slash-separated paths are normalized lexically before
/// storage. Absolute paths, backslashes, drive prefixes, NUL, and paths that
/// traverse above the root are rejected. Spaces and non-`.fga` suffixes are
/// preserved. A well-formed unsupported version is returned for later modular
/// validation.
///
/// Comments and resolved aliases are accepted. Explicit tags, merge keys,
/// unknown or duplicate fields, and multiple YAML documents are rejected.
pub fn parse_model_manifest(input: &str) -> Result<ModelManifest, ManifestError> {
    let mut documents = Vec::new();
    for document in YamlDeserializer::from_str(input) {
        let value = YamlNode::deserialize(document).map_err(|error| {
            manifest_error(
                ManifestErrorCode::InvalidYaml,
                None,
                format!("invalid YAML: {error}"),
            )
        })?;
        documents.push(value);
    }

    if documents.len() != 1 {
        return Err(manifest_error(
            ManifestErrorCode::InvalidYaml,
            None,
            "manifest must contain exactly one YAML document".to_string(),
        ));
    }

    let document = documents.pop().expect("one YAML document was checked");
    if document.contains_explicit_tag() {
        return Err(manifest_error(
            ManifestErrorCode::UnsupportedYamlFeature,
            None,
            "explicit YAML tags are not supported in manifests".to_string(),
        ));
    }

    let YamlNode::Mapping(entries) = document else {
        return Err(manifest_error(
            ManifestErrorCode::InvalidRoot,
            None,
            "manifest root must be a mapping".to_string(),
        ));
    };

    let mut schema = None;
    let mut contents = None;
    for (key, value) in entries {
        let YamlNode::String(key) = key else {
            return Err(manifest_error(
                ManifestErrorCode::WrongType,
                None,
                "manifest mapping keys must be strings".to_string(),
            ));
        };

        match key.as_str() {
            "schema" => {
                if schema.is_some() {
                    return Err(manifest_error(
                        ManifestErrorCode::DuplicateField,
                        Some(key),
                        "field 'schema' occurs more than once".to_string(),
                    ));
                }
                schema = Some(value);
            }
            "contents" => {
                if contents.is_some() {
                    return Err(manifest_error(
                        ManifestErrorCode::DuplicateField,
                        Some(key),
                        "field 'contents' occurs more than once".to_string(),
                    ));
                }
                contents = Some(value);
            }
            unknown => {
                return Err(manifest_error(
                    ManifestErrorCode::UnknownField,
                    Some(key.clone()),
                    format!("unknown manifest field '{unknown}'"),
                ));
            }
        }
    }

    let schema = schema.ok_or_else(|| {
        manifest_error(
            ManifestErrorCode::MissingField,
            Some("schema".to_string()),
            "required field 'schema' is missing".to_string(),
        )
    })?;
    let contents = contents.ok_or_else(|| {
        manifest_error(
            ManifestErrorCode::MissingField,
            Some("contents".to_string()),
            "required field 'contents' is missing".to_string(),
        )
    })?;

    let schema = match schema {
        YamlNode::String(schema) if is_numeric_schema_version(&schema) => schema,
        YamlNode::String(schema) => {
            return Err(manifest_error(
                ManifestErrorCode::InvalidSchemaVersion,
                Some("schema".to_string()),
                format!("schema version '{schema}' must match ASCII major.minor digits"),
            ));
        }
        _ => {
            return Err(manifest_error(
                ManifestErrorCode::WrongType,
                Some("schema".to_string()),
                "field 'schema' must be a YAML string".to_string(),
            ));
        }
    };

    let entries = match contents {
        YamlNode::Sequence(entries) => entries,
        _ => {
            return Err(manifest_error(
                ManifestErrorCode::WrongType,
                Some("contents".to_string()),
                "field 'contents' must be a sequence".to_string(),
            ));
        }
    };
    if entries.is_empty() {
        return Err(manifest_error(
            ManifestErrorCode::EmptyContents,
            Some("contents".to_string()),
            "field 'contents' must contain at least one module path".to_string(),
        ));
    }

    let mut normalized_paths = Vec::with_capacity(entries.len());
    let mut seen_paths = HashSet::with_capacity(entries.len());
    for (index, entry) in entries.into_iter().enumerate() {
        let field = format!("contents[{index}]");
        let path = match entry {
            YamlNode::String(path) => path,
            _ => {
                return Err(manifest_error(
                    ManifestErrorCode::WrongType,
                    Some(field),
                    "module path entries must be YAML strings".to_string(),
                ));
            }
        };
        let path = normalize_manifest_path(&path).map_err(|message| {
            manifest_error(
                ManifestErrorCode::InvalidPath,
                Some(field.clone()),
                message.to_string(),
            )
        })?;
        if !seen_paths.insert(path.clone()) {
            return Err(manifest_error(
                ManifestErrorCode::DuplicatePath,
                Some(field),
                format!(
                    "module path '{}' duplicates an earlier normalized path",
                    path.display()
                ),
            ));
        }
        normalized_paths.push(path);
    }

    Ok(ModelManifest {
        schema,
        contents: normalized_paths,
    })
}

/// Creates one manifest diagnostic with the requested code and field.
fn manifest_error(
    code: ManifestErrorCode,
    field: Option<String>,
    message: String,
) -> ManifestError {
    ManifestError {
        code,
        field,
        message,
    }
}

/// Checks the exact ASCII `major.minor` spelling required for manifest versions.
fn is_numeric_schema_version(version: &str) -> bool {
    let Some((major, minor)) = version.split_once('.') else {
        return false;
    };
    !major.is_empty()
        && !minor.is_empty()
        && major.bytes().all(|byte| byte.is_ascii_digit())
        && minor.bytes().all(|byte| byte.is_ascii_digit())
        && !minor.contains('.')
}

/// A YAML node that retains mapping order, duplicate keys, and tagged values.
enum YamlNode {
    Null,
    Bool,
    Number,
    String(String),
    Sequence(Vec<YamlNode>),
    Mapping(Vec<(YamlNode, YamlNode)>),
    Tagged(Box<YamlNode>),
}

impl YamlNode {
    /// Returns whether a tag occurs at this node or anywhere below it.
    fn contains_explicit_tag(&self) -> bool {
        match self {
            Self::Tagged(inner) => {
                let _ = inner;
                true
            }
            Self::Sequence(values) => values.iter().any(Self::contains_explicit_tag),
            Self::Mapping(entries) => entries
                .iter()
                .any(|(key, value)| key.contains_explicit_tag() || value.contains_explicit_tag()),
            Self::Null | Self::Bool | Self::Number | Self::String(_) => false,
        }
    }
}

impl<'de> Deserialize<'de> for YamlNode {
    /// Deserializes YAML while preserving mappings as ordered entry vectors.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(YamlNodeVisitor)
    }
}

/// Deserializes YAML scalars, sequences, mappings, and explicit tags.
struct YamlNodeVisitor;

impl<'de> Visitor<'de> for YamlNodeVisitor {
    type Value = YamlNode;

    /// Describes the YAML values this visitor accepts.
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a YAML value")
    }

    /// Retains YAML boolean values as a typed scalar marker.
    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(YamlNode::Bool)
    }

    /// Retains signed YAML integers as a typed scalar marker.
    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(YamlNode::Number)
    }

    /// Retains unsigned YAML integers as a typed scalar marker.
    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(YamlNode::Number)
    }

    /// Retains YAML floating-point numbers as a typed scalar marker.
    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(YamlNode::Number)
    }

    /// Stores a borrowed YAML string as a manifest string scalar.
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(YamlNode::String(value.to_string()))
    }

    /// Stores an owned YAML string as a manifest string scalar.
    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(YamlNode::String(value))
    }

    /// Retains a YAML null scalar.
    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(YamlNode::Null)
    }

    /// Retains an optional YAML null scalar.
    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(YamlNode::Null)
    }

    /// Collects sequence entries in their original order.
    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(YamlNode::Sequence(values))
    }

    /// Collects mapping entries in source order, including duplicate keys.
    fn visit_map<A>(self, mut mapping: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut entries = Vec::new();
        while let Some(entry) = mapping.next_entry::<YamlNode, YamlNode>()? {
            entries.push(entry);
        }
        Ok(YamlNode::Mapping(entries))
    }

    /// Preserves explicit tags so the manifest policy can reject them by precedence.
    fn visit_enum<A>(self, tagged: A) -> Result<Self::Value, A::Error>
    where
        A: EnumAccess<'de>,
    {
        let (_tag, value) = tagged.variant::<String>()?;
        Ok(YamlNode::Tagged(Box::new(value.newtype_variant()?)))
    }
}

/// Normalizes a slash-separated relative path without consulting the filesystem.
pub(crate) fn normalize_manifest_path(path: &str) -> Result<PathBuf, &'static str> {
    if path.contains('\0') {
        return Err("module paths cannot contain NUL");
    }
    if path.contains('\\') {
        return Err("module paths must use forward slashes");
    }
    if path.starts_with('/') {
        return Err("module paths must be relative");
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err("module paths cannot use a drive prefix");
    }

    let mut components: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err("module path traverses above its relative root");
                }
            }
            other => components.push(other),
        }
    }
    if components.is_empty() {
        return Err("module path normalizes to an empty path");
    }

    Ok(PathBuf::from(components.join("/")))
}

/// Validates a constructed manifest value without parsing or serializing YAML.
pub(crate) fn validate_manifest_value(manifest: &ModelManifest) -> Result<(), ManifestError> {
    if !is_numeric_schema_version(&manifest.schema) {
        return Err(manifest_error(
            ManifestErrorCode::InvalidSchemaVersion,
            Some("schema".to_string()),
            format!(
                "schema version '{}' must match ASCII major.minor digits",
                manifest.schema
            ),
        ));
    }

    if manifest.contents.is_empty() {
        return Err(manifest_error(
            ManifestErrorCode::EmptyContents,
            Some("contents".to_string()),
            "field 'contents' must contain at least one module path".to_string(),
        ));
    }

    let mut seen = HashSet::with_capacity(manifest.contents.len());
    for (index, path) in manifest.contents.iter().enumerate() {
        let field = format!("contents[{index}]");
        let Some(path_text) = path.to_str() else {
            return Err(manifest_error(
                ManifestErrorCode::InvalidPath,
                Some(field),
                "module paths must be valid UTF-8 slash-separated paths".to_string(),
            ));
        };
        let normalized = normalize_manifest_path(path_text).map_err(|message| {
            manifest_error(
                ManifestErrorCode::InvalidPath,
                Some(field.clone()),
                message.to_string(),
            )
        })?;
        if normalized.to_str() != Some(path_text) {
            return Err(manifest_error(
                ManifestErrorCode::InvalidPath,
                Some(field),
                format!(
                    "module path '{}' is not lexically normalized",
                    path.display()
                ),
            ));
        }
        if !seen.insert(normalized.clone()) {
            return Err(manifest_error(
                ManifestErrorCode::DuplicatePath,
                Some(format!("contents[{index}]")),
                format!(
                    "module path '{}' duplicates an earlier normalized path",
                    normalized.display()
                ),
            ));
        }
    }

    Ok(())
}
