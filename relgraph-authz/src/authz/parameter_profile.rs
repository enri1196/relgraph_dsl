use relgraph_dsl::ParameterType;

/// Scalar kinds accepted by the authorization runtime for condition parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RuntimeScalarType {
    /// CEL boolean.
    Bool,
    /// Signed CEL integer.
    Int,
    /// Unsigned CEL integer.
    Uint,
    /// CEL double precision number.
    Double,
    /// CEL string.
    String,
    /// CEL duration.
    Duration,
    /// CEL timestamp.
    Timestamp,
    /// OpenFGA's opaque `ipaddress` extension type.
    IpAddress,
}

impl RuntimeScalarType {
    /// Resolves a DSL scalar name to the supported local runtime profile.
    fn from_dsl_name(name: &str) -> Option<Self> {
        match name {
            "bool" => Some(Self::Bool),
            "int" => Some(Self::Int),
            "uint" => Some(Self::Uint),
            "double" => Some(Self::Double),
            "string" => Some(Self::String),
            "duration" => Some(Self::Duration),
            "timestamp" => Some(Self::Timestamp),
            "ipaddress" => Some(Self::IpAddress),
            _ => None,
        }
    }
}

/// A scalar, one-level list, or string-keyed map supported by the runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RuntimeParameterType {
    /// A supported scalar parameter.
    Scalar(RuntimeScalarType),
    /// A one-level list of supported scalar parameters.
    List(RuntimeScalarType),
    /// A one-level string-keyed map of supported scalar parameters.
    Map(RuntimeScalarType),
}

impl RuntimeParameterType {
    /// Maps a DSL parameter into the subset accepted by both route and CEL APIs.
    pub(super) fn from_dsl(parameter_type: &ParameterType) -> Option<Self> {
        match parameter_type {
            ParameterType::Simple(name) => RuntimeScalarType::from_dsl_name(name).map(Self::Scalar),
            ParameterType::Generic { container, inner } => {
                let scalar = RuntimeScalarType::from_dsl_name(inner)?;
                match container.as_str() {
                    "list" => Some(Self::List(scalar)),
                    "map" => Some(Self::Map(scalar)),
                    _ => None,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use cel_core::CelType;
    use relgraph_dsl::ParameterType;

    use super::{RuntimeParameterType, RuntimeScalarType};
    use crate::authz::{conditions::cel_type, ipaddress, policy::ContextValueType};

    fn scalar(name: &str) -> ParameterType {
        ParameterType::Simple(name.to_owned())
    }

    fn container(container: &str, inner: &str) -> ParameterType {
        ParameterType::Generic {
            container: container.to_owned(),
            inner: inner.to_owned(),
        }
    }

    #[test]
    fn route_and_cel_profiles_share_supported_scalar_and_container_mapping() {
        let scalars = [
            (
                "bool",
                RuntimeScalarType::Bool,
                ContextValueType::Bool,
                CelType::Bool,
            ),
            (
                "int",
                RuntimeScalarType::Int,
                ContextValueType::Int,
                CelType::Int,
            ),
            (
                "uint",
                RuntimeScalarType::Uint,
                ContextValueType::Uint,
                CelType::UInt,
            ),
            (
                "double",
                RuntimeScalarType::Double,
                ContextValueType::Double,
                CelType::Double,
            ),
            (
                "string",
                RuntimeScalarType::String,
                ContextValueType::String,
                CelType::String,
            ),
            (
                "duration",
                RuntimeScalarType::Duration,
                ContextValueType::Duration,
                CelType::Duration,
            ),
            (
                "timestamp",
                RuntimeScalarType::Timestamp,
                ContextValueType::Timestamp,
                CelType::Timestamp,
            ),
            (
                "ipaddress",
                RuntimeScalarType::IpAddress,
                ContextValueType::IpAddress,
                ipaddress::cel_type(),
            ),
        ];

        for (name, scalar_kind, route_type, cel_type_expected) in scalars {
            let parameter_type = scalar(name);
            assert_eq!(
                RuntimeParameterType::from_dsl(&parameter_type),
                Some(RuntimeParameterType::Scalar(scalar_kind))
            );
            assert_eq!(
                ContextValueType::from_parameter_type(&parameter_type),
                Some(route_type)
            );
            assert_eq!(cel_type(&parameter_type), Some(cel_type_expected));
        }

        let containers = [
            (
                container("list", "bool"),
                RuntimeParameterType::List(RuntimeScalarType::Bool),
                ContextValueType::List(Box::new(ContextValueType::Bool)),
                CelType::list(CelType::Bool),
            ),
            (
                container("map", "string"),
                RuntimeParameterType::Map(RuntimeScalarType::String),
                ContextValueType::Map(Box::new(ContextValueType::String)),
                CelType::map(CelType::String, CelType::String),
            ),
            (
                container("list", "ipaddress"),
                RuntimeParameterType::List(RuntimeScalarType::IpAddress),
                ContextValueType::List(Box::new(ContextValueType::IpAddress)),
                CelType::list(ipaddress::cel_type()),
            ),
            (
                container("map", "ipaddress"),
                RuntimeParameterType::Map(RuntimeScalarType::IpAddress),
                ContextValueType::Map(Box::new(ContextValueType::IpAddress)),
                CelType::map(CelType::String, ipaddress::cel_type()),
            ),
        ];

        for (parameter_type, runtime_type, route_type, cel_type_expected) in containers {
            assert_eq!(
                RuntimeParameterType::from_dsl(&parameter_type),
                Some(runtime_type)
            );
            assert_eq!(
                ContextValueType::from_parameter_type(&parameter_type),
                Some(route_type)
            );
            assert_eq!(cel_type(&parameter_type), Some(cel_type_expected));
        }
    }

    #[test]
    fn unsupported_parameter_shapes_stay_outside_both_runtime_profiles() {
        let unsupported = [
            scalar("any"),
            scalar("bytes"),
            container("list", "any"),
            container("set", "string"),
            container("list", "list<string>"),
        ];

        for parameter_type in unsupported {
            assert_eq!(RuntimeParameterType::from_dsl(&parameter_type), None);
            assert_eq!(ContextValueType::from_parameter_type(&parameter_type), None);
            assert_eq!(cel_type(&parameter_type), None);
        }
    }
}
