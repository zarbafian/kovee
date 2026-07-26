//! The fail-closed egress destination checks (§16.3): the pinned-host
//! allowlist and the connection-time address-class check.
//!
//! Two gates, both fail closed, and **neither is chooseable by a worker**:
//! the destination comes from the `ModelProviderBinding`'s endpoint, which
//! a ModelProfile may not override (§16.3).
//!
//! - [`check_origin`] — the origin must be `https` and one of the exact
//!   allowed origins. An empty allowlist allows nothing.
//! - [`check_resolved_address`] — the address the origin actually resolves
//!   to at connection time must be globally routable unicast. Loopback,
//!   private, link-local, unique-local, CGNAT, multicast, NAT64-wrapped
//!   inward v4 and every other special class are refused, so a provider
//!   hostname that resolves inward (SSRF / DNS rebinding) cannot reach the
//!   host or the local network.
//!
//! What you write:
//! ```
//! use kovee_effects::{check_origin, check_resolved_address, EgressPolicy, Origin};
//! let policy = EgressPolicy::allowing([Origin::https("api.anthropic.com", 443)]);
//! check_origin(&Origin::https("api.anthropic.com", 443), &policy).unwrap();
//! check_resolved_address("160.79.104.10".parse().unwrap(), &policy).unwrap();
//! // A provider host that resolves to loopback is refused.
//! assert!(check_resolved_address("127.0.0.1".parse().unwrap(), &policy).is_err());
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

/// An exact destination origin: scheme, host, port. The broker only ever
/// dials the origin its provider binding records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl Origin {
    /// An `https` origin on `host:port` (host lowercased — origins compare
    /// case-insensitively on host).
    pub fn https(host: &str, port: u16) -> Origin {
        Origin {
            scheme: "https".to_owned(),
            host: host.to_ascii_lowercase(),
            port,
        }
    }

    /// The `Host` header value: the host, plus the port when it is not the
    /// https default.
    pub fn host_header(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}", self.scheme, self.host_header())
    }
}

/// The egress policy for model calls (§16.3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressPolicy {
    /// The exact origins a provider binding may be dialed at. Empty means
    /// nothing is allowed — the fail-closed default.
    pub origin_allowlist: Vec<Origin>,
}

impl EgressPolicy {
    pub fn allowing(origins: impl IntoIterator<Item = Origin>) -> EgressPolicy {
        EgressPolicy {
            origin_allowlist: origins.into_iter().collect(),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EgressError {
    #[error("scheme {0:?} is not permitted; model egress is https only")]
    NotHttps(String),
    #[error("origin {0} is not in the provider binding's allowlist")]
    OriginNotAllowed(String),
    #[error("{origin} resolves to {addr}, a {class} address that is not globally routable")]
    NonGlobalAddress {
        origin: String,
        addr: IpAddr,
        class: &'static str,
    },
    #[error("{0} resolved to no address")]
    Unresolvable(String),
}

/// Checks a configured origin: `https` and exactly allowlisted (§16.3).
pub fn check_origin(origin: &Origin, policy: &EgressPolicy) -> Result<(), EgressError> {
    if origin.scheme != "https" {
        return Err(EgressError::NotHttps(origin.scheme.clone()));
    }
    if !policy.origin_allowlist.iter().any(|o| o == origin) {
        return Err(EgressError::OriginNotAllowed(origin.to_string()));
    }
    Ok(())
}

/// Checks the address an origin resolved to at connection time. This is
/// the anti-SSRF / anti-rebinding gate: it runs against the address the
/// connection will actually use, not against the name.
pub fn check_resolved_address(addr: IpAddr, policy: &EgressPolicy) -> Result<(), EgressError> {
    let _ = policy;
    match non_global_class(addr) {
        Some(class) => Err(EgressError::NonGlobalAddress {
            origin: addr.to_string(),
            addr,
            class,
        }),
        None => Ok(()),
    }
}

/// The same check, naming the origin in the error for an audit record.
pub fn check_resolved_for(
    origin: &Origin,
    addr: IpAddr,
    _policy: &EgressPolicy,
) -> Result<(), EgressError> {
    match non_global_class(addr) {
        Some(class) => Err(EgressError::NonGlobalAddress {
            origin: origin.to_string(),
            addr,
            class,
        }),
        None => Ok(()),
    }
}

/// Classifies `addr` as a non-global class, or `None` for globally
/// routable unicast. Conservative: anything not clearly global is named.
fn non_global_class(addr: IpAddr) -> Option<&'static str> {
    match addr {
        IpAddr::V4(v4) => non_global_v4(v4),
        IpAddr::V6(v6) => non_global_v6(v6),
    }
}

fn non_global_v4(v4: Ipv4Addr) -> Option<&'static str> {
    let o = v4.octets();
    if v4.is_unspecified() {
        Some("unspecified")
    } else if v4.is_loopback() {
        Some("loopback")
    } else if v4.is_private() {
        Some("private")
    } else if v4.is_link_local() {
        Some("link-local")
    } else if v4.is_broadcast() {
        Some("broadcast")
    } else if v4.is_multicast() {
        Some("multicast")
    } else if v4.is_documentation() {
        Some("documentation")
    } else if o[0] == 100 && (o[1] & 0xc0) == 0x40 {
        // 100.64.0.0/10 — carrier-grade NAT (RFC 6598).
        Some("shared-cgnat")
    } else if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        // 192.0.0.0/24 — IETF protocol assignments.
        Some("protocol-assignment")
    } else if o[0] == 198 && (o[1] & 0xfe) == 18 {
        // 198.18.0.0/15 — benchmarking (RFC 2544).
        Some("benchmarking")
    } else if o[0] >= 240 {
        // 240.0.0.0/4 — reserved.
        Some("reserved")
    } else {
        None
    }
}

fn non_global_v6(v6: Ipv6Addr) -> Option<&'static str> {
    // `::1` and `::` are inside ::/96, so the sentinels come first.
    if v6.is_unspecified() {
        return Some("unspecified");
    }
    if v6.is_loopback() {
        return Some("loopback");
    }
    // An IPv4-mapped address must be judged by its embedded v4 class, or
    // ::ffff:127.0.0.1 would pass as "some v6 address".
    if let Some(v4) = v6.to_ipv4_mapped() {
        return non_global_v4(v4).or(Some("ipv4-mapped"));
    }
    let seg = v6.segments();
    // 64:ff9b::/96 — well-known NAT64: judge the embedded v4.
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6].iter().all(|&s| s == 0) {
        let v4 = Ipv4Addr::from(((seg[6] as u32) << 16) | seg[7] as u32);
        return non_global_v4(v4).or(Some("nat64"));
    }
    if v6.is_multicast() {
        Some("multicast")
    } else if (seg[0] & 0xffc0) == 0xfec0 {
        // fec0::/10 — deprecated site-local unicast.
        Some("site-local")
    } else if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0x0001 {
        // 64:ff9b:1::/48 — local-use NAT64 (RFC 8215).
        Some("nat64-local")
    } else if (seg[0] & 0xfe00) == 0xfc00 {
        // fc00::/7 — unique local.
        Some("unique-local")
    } else if (seg[0] & 0xffc0) == 0xfe80 {
        // fe80::/10 — link-local unicast.
        Some("link-local")
    } else if seg[0] == 0x2001 && seg[1] == 0x0db8 {
        // 2001:db8::/32 — documentation.
        Some("documentation")
    } else if seg[..6].iter().all(|&s| s == 0) {
        // ::/96 — deprecated IPv4-compatible.
        Some("ipv4-compatible")
    } else {
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn policy() -> EgressPolicy {
        EgressPolicy::allowing([Origin::https("api.anthropic.com", 443)])
    }

    #[test]
    fn only_https_and_exactly_allowlisted_origins_pass() {
        check_origin(&Origin::https("api.anthropic.com", 443), &policy()).unwrap();
        // Case-insensitive on host, because `https` normalizes it.
        check_origin(&Origin::https("API.Anthropic.com", 443), &policy()).unwrap();
        assert!(matches!(
            check_origin(
                &Origin {
                    scheme: "http".into(),
                    host: "api.anthropic.com".into(),
                    port: 443
                },
                &policy()
            ),
            Err(EgressError::NotHttps(_))
        ));
        assert!(matches!(
            check_origin(&Origin::https("evil.example", 443), &policy()),
            Err(EgressError::OriginNotAllowed(_))
        ));
        // Same host, another port is another origin.
        assert!(matches!(
            check_origin(&Origin::https("api.anthropic.com", 8443), &policy()),
            Err(EgressError::OriginNotAllowed(_))
        ));
        // An empty allowlist allows nothing.
        assert!(check_origin(
            &Origin::https("api.anthropic.com", 443),
            &EgressPolicy::default()
        )
        .is_err());
    }

    #[test]
    fn global_unicast_addresses_pass() {
        for a in ["160.79.104.10", "8.8.8.8", "2606:4700::6810:85e5"] {
            check_resolved_address(a.parse().unwrap(), &policy())
                .unwrap_or_else(|e| panic!("{a} should be global: {e}"));
        }
    }

    #[test]
    fn inward_and_special_addresses_are_refused() {
        for (a, class) in [
            ("0.0.0.0", "unspecified"),
            ("127.0.0.1", "loopback"),
            ("10.1.2.3", "private"),
            ("192.168.1.1", "private"),
            ("172.16.0.1", "private"),
            ("169.254.169.254", "link-local"),
            ("100.64.0.1", "shared-cgnat"),
            ("198.18.0.1", "benchmarking"),
            ("255.255.255.255", "broadcast"),
            ("224.0.0.1", "multicast"),
            ("::1", "loopback"),
            ("fe80::1", "link-local"),
            ("fc00::1", "unique-local"),
            ("::ffff:127.0.0.1", "loopback"),
            ("fec0::1", "site-local"),
            ("64:ff9b:1::1", "nat64-local"),
            ("64:ff9b::7f00:1", "loopback"),
            ("64:ff9b::a00:1", "private"),
        ] {
            let err = check_resolved_address(a.parse().unwrap(), &policy()).unwrap_err();
            match err {
                EgressError::NonGlobalAddress { class: c, .. } => {
                    assert_eq!(c, class, "{a} classified wrong")
                }
                other => panic!("{a} should be non-global, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_host_header_omits_the_default_port() {
        assert_eq!(
            Origin::https("api.openai.com", 443).host_header(),
            "api.openai.com"
        );
        assert_eq!(
            Origin::https("api.openai.com", 8443).host_header(),
            "api.openai.com:8443"
        );
    }
}
