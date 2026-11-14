//! NAT mapping behaviour classification from multi-seed STUN observations.
//!
//! This is deliberately narrow. It answers exactly one question: does this
//! socket's NAT reuse one external port for every destination, or allocate a
//! different one per destination? That single bit decides which side of a
//! hole punch a peer must play, and it is measurable with no new
//! infrastructure at all -- the same retained data socket is already queried
//! against several STUN servers in rotation.
//!
//! Filtering behaviour (endpoint-independent, address-dependent or
//! address-and-port-dependent) is deliberately *not* measured here. That needs
//! either an RFC 5780 server with two public addresses or a cooperating peer,
//! and the punch itself already discovers it in one packet: if a single probe
//! to the peer's address on an arbitrary port gets a reply back, filtering is
//! no stricter than address-dependent and no grid is needed.
//!
//! A false "endpoint-dependent" verdict is the safe direction to be wrong in:
//! it costs a hard side some sockets, whereas a false "endpoint-independent"
//! verdict would send an easy side into a grid scan that can never succeed.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

/// Samples older than this relative to the newest one are ignored.
///
/// Without a coherence window, a NAT that simply rebinds over time would look
/// endpoint-dependent purely because two destinations were measured minutes
/// apart.
pub const NAT_SAMPLE_COHERENCE_MS: u64 = 60_000;

/// Distinct destination addresses required before any verdict is given.
pub const NAT_MIN_DISTINCT_DESTINATIONS: usize = 2;

/// How a NAT assigns external ports across destinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingBehavior {
    /// One external port for every destination (RFC 4787 endpoint-independent
    /// mapping). This peer can be the easy side of a punch.
    EndpointIndependent,
    /// A different external port per destination (RFC 4787 endpoint-dependent
    /// mapping). This peer must be the hard side, or must not punch at all.
    EndpointDependent,
    /// Not enough coherent evidence yet. No punch role can be chosen.
    Unknown,
}

impl MappingBehavior {
    /// Stable snake_case identifier for diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            MappingBehavior::EndpointIndependent => "eim",
            MappingBehavior::EndpointDependent => "edm",
            MappingBehavior::Unknown => "unknown",
        }
    }

    /// Whether a role can be chosen from this verdict.
    pub const fn is_known(self) -> bool {
        !matches!(self, MappingBehavior::Unknown)
    }

    /// The contact-record flag bits that describe this verdict.
    ///
    /// Endpoint-independent mapping needs no bit: a record that sets neither
    /// mapping bit is read as endpoint-independent, which is also what a peer
    /// predating these flags looks like.
    pub const fn record_flags(self) -> u8 {
        match self {
            MappingBehavior::EndpointIndependent => 0,
            MappingBehavior::EndpointDependent => crate::record::FLAG_MAPPING_EDM,
            MappingBehavior::Unknown => crate::record::FLAG_MAPPING_UNKNOWN,
        }
    }

    /// Recover a verdict from contact-record flag bits.
    pub const fn from_record_flags(flags: u8) -> Self {
        if flags & crate::record::FLAG_MAPPING_EDM != 0 {
            MappingBehavior::EndpointDependent
        } else if flags & crate::record::FLAG_MAPPING_UNKNOWN != 0 {
            MappingBehavior::Unknown
        } else {
            MappingBehavior::EndpointIndependent
        }
    }

    /// Parse a snake_case identifier. Deliberately not `FromStr`: this is a
    /// closed set of wire identifiers, not a general string parse.
    pub fn parse_str(value: &str) -> Option<Self> {
        match value {
            "eim" => Some(MappingBehavior::EndpointIndependent),
            "edm" => Some(MappingBehavior::EndpointDependent),
            "unknown" => Some(MappingBehavior::Unknown),
            _ => None,
        }
    }
}

/// One observation: a destination address and the external port the NAT chose
/// for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingSample {
    /// The destination address that was queried.
    pub destination: Ipv4Addr,
    /// The external port the NAT used towards that destination.
    pub port: u16,
    /// When this was observed, on the caller's monotonic clock.
    pub observed_at_ms: u64,
}

/// A verdict together with the evidence behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatProfile {
    /// The verdict.
    pub mapping: MappingBehavior,
    /// Distinct destination addresses that contributed.
    pub distinct_destinations: u8,
    /// Distinct external ports seen across those destinations.
    pub distinct_ports: u8,
}

impl NatProfile {
    /// No usable evidence.
    pub const fn unknown() -> Self {
        Self {
            mapping: MappingBehavior::Unknown,
            distinct_destinations: 0,
            distinct_ports: 0,
        }
    }
}

impl Default for NatProfile {
    fn default() -> Self {
        Self::unknown()
    }
}

/// Classify mapping behaviour from per-destination samples.
///
/// Only the newest sample per destination address counts, and only samples
/// inside the coherence window of the newest sample overall. Two destinations
/// that share an address cannot distinguish an address-dependent mapping from
/// an endpoint-independent one, so at least two distinct addresses are needed.
pub fn classify_mapping(samples: &[MappingSample]) -> NatProfile {
    let Some(newest) = samples.iter().map(|s| s.observed_at_ms).max() else {
        return NatProfile::unknown();
    };
    let mut latest: BTreeMap<Ipv4Addr, MappingSample> = BTreeMap::new();
    for sample in samples {
        if newest.saturating_sub(sample.observed_at_ms) > NAT_SAMPLE_COHERENCE_MS {
            continue;
        }
        match latest.get_mut(&sample.destination) {
            Some(existing) if existing.observed_at_ms > sample.observed_at_ms => {}
            Some(existing) => *existing = *sample,
            None => {
                latest.insert(sample.destination, *sample);
            }
        }
    }
    let destinations = latest.len();
    if destinations < NAT_MIN_DISTINCT_DESTINATIONS {
        return NatProfile {
            mapping: MappingBehavior::Unknown,
            distinct_destinations: destinations as u8,
            distinct_ports: 0,
        };
    }
    let mut ports: Vec<u16> = latest.values().map(|sample| sample.port).collect();
    ports.sort_unstable();
    ports.dedup();
    let mapping = if ports.len() == 1 {
        MappingBehavior::EndpointIndependent
    } else {
        MappingBehavior::EndpointDependent
    };
    NatProfile {
        mapping,
        distinct_destinations: destinations as u8,
        distinct_ports: ports.len() as u8,
    }
}

/// Reduce several sockets' verdicts to the one this host must publish.
///
/// A host is only as easy as its hardest socket: if any retained socket sits
/// behind an endpoint-dependent mapping, a punch that needs an easy side
/// cannot rely on this host being it. Unknown sockets simply do not vote, so a
/// host with one classified and one unclassified socket publishes the
/// classified verdict rather than degrading to unknown.
pub fn aggregate_mapping<I>(behaviors: I) -> MappingBehavior
where
    I: IntoIterator<Item = MappingBehavior>,
{
    let mut any_dependent = false;
    let mut any_known = false;
    for behavior in behaviors {
        match behavior {
            MappingBehavior::EndpointDependent => {
                any_dependent = true;
                any_known = true;
            }
            MappingBehavior::EndpointIndependent => any_known = true,
            MappingBehavior::Unknown => {}
        }
    }
    if any_dependent {
        MappingBehavior::EndpointDependent
    } else if any_known {
        MappingBehavior::EndpointIndependent
    } else {
        MappingBehavior::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, last)
    }

    fn sample(last: u8, port: u16, at: u64) -> MappingSample {
        MappingSample {
            destination: ip(last),
            port,
            observed_at_ms: at,
        }
    }

    #[test]
    fn one_port_across_several_destinations_is_endpoint_independent() {
        let profile = classify_mapping(&[
            sample(1, 51_000, 1_000),
            sample(2, 51_000, 2_000),
            sample(3, 51_000, 3_000),
        ]);
        assert_eq!(profile.mapping, MappingBehavior::EndpointIndependent);
        assert_eq!(profile.distinct_destinations, 3);
        assert_eq!(profile.distinct_ports, 1);
    }

    #[test]
    fn different_ports_across_destinations_is_endpoint_dependent() {
        let profile = classify_mapping(&[
            sample(1, 51_000, 1_000),
            sample(2, 26_170, 2_000),
            sample(3, 43_072, 3_000),
        ]);
        assert_eq!(profile.mapping, MappingBehavior::EndpointDependent);
        assert_eq!(profile.distinct_destinations, 3);
        assert_eq!(profile.distinct_ports, 3);
    }

    #[test]
    fn a_single_destination_can_never_decide() {
        // Two samples from one address cannot separate address-dependent
        // mapping from endpoint-independent mapping.
        let profile = classify_mapping(&[sample(1, 51_000, 1_000), sample(1, 51_000, 2_000)]);
        assert_eq!(profile.mapping, MappingBehavior::Unknown);
        assert_eq!(profile.distinct_destinations, 1);
    }

    #[test]
    fn no_samples_is_unknown() {
        assert_eq!(classify_mapping(&[]), NatProfile::unknown());
        assert_eq!(classify_mapping(&[]).mapping, MappingBehavior::Unknown);
    }

    #[test]
    fn only_the_newest_sample_per_destination_counts() {
        // The stale port for destination 1 must not resurrect an old verdict.
        let profile = classify_mapping(&[
            sample(1, 11_111, 1_000),
            sample(1, 51_000, 9_000),
            sample(2, 51_000, 9_500),
        ]);
        assert_eq!(profile.mapping, MappingBehavior::EndpointIndependent);
        assert_eq!(profile.distinct_ports, 1);
    }

    #[test]
    fn samples_outside_the_coherence_window_are_ignored() {
        // A rebinding NAT measured minutes apart must not be mistaken for
        // endpoint-dependent mapping.
        let profile = classify_mapping(&[
            sample(1, 51_000, 0),
            sample(2, 51_000, NAT_SAMPLE_COHERENCE_MS + 1),
        ]);
        assert_eq!(profile.mapping, MappingBehavior::Unknown);
        assert_eq!(profile.distinct_destinations, 1);
    }

    #[test]
    fn a_rebinding_nat_inside_the_window_reads_as_endpoint_dependent() {
        // The safe direction: a NAT that changes ports between two
        // destinations measured close together is treated as hard.
        let profile = classify_mapping(&[sample(1, 51_000, 0), sample(2, 51_001, 1_000)]);
        assert_eq!(profile.mapping, MappingBehavior::EndpointDependent);
    }

    #[test]
    fn aggregation_takes_the_hardest_socket_and_ignores_unknowns() {
        use MappingBehavior::*;
        assert_eq!(aggregate_mapping([]), Unknown);
        assert_eq!(aggregate_mapping([Unknown, Unknown]), Unknown);
        assert_eq!(
            aggregate_mapping([EndpointIndependent]),
            EndpointIndependent
        );
        assert_eq!(
            aggregate_mapping([EndpointIndependent, Unknown]),
            EndpointIndependent
        );
        // One hard socket makes the whole host hard.
        assert_eq!(
            aggregate_mapping([EndpointIndependent, EndpointDependent]),
            EndpointDependent
        );
        assert_eq!(
            aggregate_mapping([Unknown, EndpointDependent, EndpointIndependent]),
            EndpointDependent
        );
    }

    #[test]
    fn record_flags_round_trip_through_the_verdict() {
        for behavior in [
            MappingBehavior::EndpointIndependent,
            MappingBehavior::EndpointDependent,
            MappingBehavior::Unknown,
        ] {
            assert_eq!(
                MappingBehavior::from_record_flags(behavior.record_flags()),
                behavior,
                "{behavior:?}"
            );
        }
        // The punch offer bit must not disturb the mapping verdict.
        let flags =
            MappingBehavior::EndpointDependent.record_flags() | crate::record::FLAG_PUNCH_OFFER;
        assert_eq!(
            MappingBehavior::from_record_flags(flags),
            MappingBehavior::EndpointDependent
        );
        // A record with no mapping bits reads as endpoint-independent.
        assert_eq!(
            MappingBehavior::from_record_flags(0),
            MappingBehavior::EndpointIndependent
        );
    }

    #[test]
    fn identifiers_round_trip() {
        for behavior in [
            MappingBehavior::EndpointIndependent,
            MappingBehavior::EndpointDependent,
            MappingBehavior::Unknown,
        ] {
            assert_eq!(
                MappingBehavior::parse_str(behavior.as_str()),
                Some(behavior)
            );
            assert_eq!(behavior.is_known(), behavior != MappingBehavior::Unknown);
        }
        assert_eq!(MappingBehavior::parse_str("nonsense"), None);
    }
}
