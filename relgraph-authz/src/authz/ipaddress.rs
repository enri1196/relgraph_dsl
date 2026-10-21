//! OpenFGA's `ipaddress` CEL extension, implemented on top of `cel-core`.
//!
//! OpenFGA `v1.21.0` (`internal/condition/types/ipaddress.go`) adds one opaque
//! CEL type with three operations, all of which every condition can use:
//!
//! - `ipaddress(string) -> ipaddress` (overload `string_to_ipaddress`);
//! - `<ipaddress>.in_cidr(string) -> bool` (overload `ipaddr_in_cidr`);
//! - equality between two addresses.
//!
//! Addresses follow Go's `netip.ParseAddr` and are unmapped, so an IPv4-mapped
//! IPv6 address equals and matches its IPv4 form. A CIDR follows Go's
//! `netip.ParsePrefix`: host bits may be set, the prefix length is decimal
//! without a sign or leading zero, and an IPv4-mapped IPv6 prefix of at least
//! 96 bits is unmapped to the matching IPv4 prefix. An IPv4 address never
//! matches an IPv6 prefix and vice versa. A malformed CIDR is an evaluation
//! error. Parsing uses `std::net`, which rejects IPv6 zone identifiers
//! (`fe80::1%eth0`); OpenFGA parses those addresses, so a zoned address is a
//! documented difference here (an invalid value rather than an address).

use std::any::Any;
use std::net::IpAddr;

use cel_core::{CelType, EvalError, FunctionDecl, MessageValue, OverloadDecl, Value};

/// The CEL type name OpenFGA registers for `ipaddress` parameters.
const TYPE_NAME: &str = "IPAddress";

/// An unmapped IP address carried through CEL as an opaque value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct IpAddress(IpAddr);

impl IpAddress {
    /// Parses an address as OpenFGA does, unmapping IPv4-mapped IPv6 forms.
    pub(super) fn parse(text: &str) -> Option<Self> {
        text.parse::<IpAddr>()
            .ok()
            .map(|address| Self(unmap(address)))
    }

    /// Wraps the address as a CEL value.
    pub(super) fn into_value(self) -> Value {
        Value::Message(Box::new(self))
    }

    /// Whether the address lies in `cidr`; `None` when `cidr` is malformed.
    fn in_cidr(self, cidr: &str) -> Option<bool> {
        let (network, bits) = parse_prefix(cidr)?;
        // OpenFGA unmaps the prefix too, so `::ffff:192.0.2.0/120` is the IPv4
        // prefix `192.0.2.0/24`. A shorter mapped prefix stays an IPv6 prefix.
        let (network, bits) = match network {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) if bits >= 96 => (IpAddr::V4(v4), bits - 96),
                _ => (network, bits),
            },
            IpAddr::V4(_) => (network, bits),
        };
        Some(match (network, self.0) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0);
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(bits)).unwrap_or(0);
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        })
    }
}

impl MessageValue for IpAddress {
    fn type_name(&self) -> &str {
        TYPE_NAME
    }

    fn eq_message(&self, other: &dyn MessageValue) -> bool {
        other
            .as_any()
            .downcast_ref::<Self>()
            .is_some_and(|other| other == self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn clone_boxed(&self) -> Box<dyn MessageValue> {
        Box::new(*self)
    }
}

/// The CEL type of `ipaddress` parameters and values.
pub(super) fn cel_type() -> CelType {
    CelType::abstract_type(TYPE_NAME, &[])
}

/// The `ipaddress` conversion and `in_cidr` member function declarations.
pub(super) fn functions() -> [FunctionDecl; 2] {
    [
        FunctionDecl::new("ipaddress").with_overload(
            OverloadDecl::function("string_to_ipaddress", vec![CelType::String], cel_type())
                .with_impl(|arguments| match arguments {
                    [Value::String(text)] => IpAddress::parse(text)
                        .map(IpAddress::into_value)
                        .unwrap_or_else(|| {
                            Value::error(EvalError::invalid_argument(format!(
                                "'{text}' is not a well-formed IP address"
                            )))
                        }),
                    _ => Value::error(EvalError::no_matching_overload("ipaddress")),
                }),
        ),
        FunctionDecl::new("in_cidr").with_overload(
            OverloadDecl::method(
                "ipaddr_in_cidr",
                vec![cel_type(), CelType::String],
                CelType::Bool,
            )
            .with_impl(|arguments| match arguments {
                [Value::Message(address), Value::String(cidr)] => {
                    match address.as_any().downcast_ref::<IpAddress>() {
                        Some(address) => match address.in_cidr(cidr) {
                            Some(contained) => Value::Bool(contained),
                            None => Value::error(EvalError::invalid_argument(format!(
                                "'{cidr}' is a malformed CIDR string"
                            ))),
                        },
                        None => Value::error(EvalError::no_matching_overload("in_cidr")),
                    }
                }
                _ => Value::error(EvalError::no_matching_overload("in_cidr")),
            }),
        ),
    ]
}

fn unmap(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

/// Parses `address/bits` like Go's `netip.ParsePrefix`, without unmapping.
fn parse_prefix(cidr: &str) -> Option<(IpAddr, u8)> {
    let (address, bits) = cidr.rsplit_once('/')?;
    let address = address.parse::<IpAddr>().ok()?;
    // Go rejects a sign and leading zeros; `str::parse` would accept `+8`.
    if bits.is_empty()
        || !bits.bytes().all(|byte| byte.is_ascii_digit())
        || (bits.len() > 1 && bits.starts_with('0'))
    {
        return None;
    }
    let bits = bits.parse::<u8>().ok()?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    (bits <= maximum).then_some((address, bits))
}

#[cfg(test)]
mod tests {
    use super::IpAddress;

    fn contains(address: &str, cidr: &str) -> Option<bool> {
        IpAddress::parse(address)
            .expect("test address is well formed")
            .in_cidr(cidr)
    }

    #[test]
    fn addresses_parse_like_netip_and_are_unmapped() {
        assert_eq!(
            IpAddress::parse("::ffff:192.0.2.1"),
            IpAddress::parse("192.0.2.1")
        );
        assert_ne!(
            IpAddress::parse("::192.0.2.1"),
            IpAddress::parse("192.0.2.1")
        );
        for malformed in [
            "",
            "192.0.2",
            "192.0.2.256",
            "192.0.2.01",
            " 192.0.2.1",
            "192.0.2.1/32",
            "fe80::1%eth0",
            "1:2:3:4:5:6:7:8:9",
        ] {
            assert_eq!(IpAddress::parse(malformed), None, "{malformed}");
        }
    }

    #[test]
    fn in_cidr_follows_the_openfga_extension() {
        // The upstream unit cases (`ipaddress_test.go` at v1.21.0).
        assert_eq!(contains("192.168.1.1", "192.168.1.0/24"), Some(true));
        assert_eq!(contains("192.168.1.1", "10.0.0.0/8"), Some(false));
        assert_eq!(contains("::ffff:192.168.1.1", "192.168.1.0/24"), Some(true));
        assert_eq!(contains("::ffff:192.168.1.1", "10.0.0.0/8"), Some(false));
        assert_eq!(
            contains("::ffff:192.168.1.1", "::ffff:192.168.1.0/120"),
            Some(true)
        );
        assert_eq!(
            contains("192.168.1.1", "::ffff:192.168.1.0/120"),
            Some(true)
        );
        assert_eq!(contains("192.168.1.1", "::ffff:10.0.0.0/104"), Some(false));
        assert_eq!(contains("192.168.1.1", "malformed"), None);

        // Host bits, boundaries and families.
        assert_eq!(contains("192.168.0.1", "192.168.0.77/24"), Some(true));
        assert_eq!(contains("203.0.113.9", "0.0.0.0/0"), Some(true));
        assert_eq!(contains("203.0.113.9", "203.0.113.9/32"), Some(true));
        assert_eq!(contains("203.0.113.8", "203.0.113.9/32"), Some(false));
        assert_eq!(contains("2001:db8::1", "2001:db8::/32"), Some(true));
        assert_eq!(contains("2001:db9::1", "2001:db8::/32"), Some(false));
        assert_eq!(contains("2001:db8::1", "::/0"), Some(true));
        assert_eq!(contains("192.0.2.1", "::/0"), Some(false));
        assert_eq!(contains("2001:db8::1", "0.0.0.0/0"), Some(false));
        // A mapped prefix shorter than 96 bits stays an IPv6 prefix.
        assert_eq!(contains("192.0.2.1", "::ffff:0.0.0.0/95"), Some(false));
    }

    #[test]
    fn malformed_cidrs_are_rejected_like_netip() {
        for cidr in [
            "192.0.2.0",
            "192.0.2.0/",
            "192.0.2.0/33",
            "2001:db8::/129",
            "192.0.2.0/+8",
            "192.0.2.0/-1",
            "192.0.2.0/08",
            "192.0.2.0/ 8",
            "192.0.2.0/24/8",
            "fe80::%eth0/64",
            "/8",
        ] {
            assert_eq!(contains("192.0.2.1", cidr), None, "{cidr}");
        }
        assert_eq!(contains("192.0.2.1", "192.0.2.0/0"), Some(true));
    }
}
