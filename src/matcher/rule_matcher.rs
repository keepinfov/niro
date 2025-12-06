//! Rule matching logic.

use crate::config::{AddressPattern, Direction, PortPattern, Protocol, Rule};
use crate::matcher::Packet;
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

/// Rule matcher for evaluating packets against rules.
#[derive(Debug)]
pub struct RuleMatcher;

impl RuleMatcher {
    /// Check if a packet matches a rule.
    pub fn matches(rule: &Rule, packet: &Packet) -> bool {
        Self::matches_direction(rule.direction, packet.direction)
            && Self::matches_protocol(rule.protocol, packet.protocol)
            && Self::matches_address(&rule.local_addr, packet.local_addr)
            && Self::matches_address(&rule.remote_addr, packet.remote_addr)
            && Self::matches_port(&rule.local_port, packet.local_port)
            && Self::matches_port(&rule.remote_port, packet.remote_port)
    }

    /// Check if a packet direction matches a rule direction.
    fn matches_direction(rule_dir: Direction, packet_dir: Direction) -> bool {
        match rule_dir {
            Direction::Any => true,
            Direction::In => packet_dir == Direction::In,
            Direction::Out => packet_dir == Direction::Out,
        }
    }

    /// Check if a packet protocol matches a rule protocol.
    fn matches_protocol(rule_proto: Protocol, packet_proto: Protocol) -> bool {
        match rule_proto {
            Protocol::Any => true,
            Protocol::Tcp => packet_proto == Protocol::Tcp,
            Protocol::Udp => packet_proto == Protocol::Udp,
        }
    }

    /// Check if an address matches an address pattern.
    fn matches_address(pattern: &AddressPattern, addr: Ipv4Addr) -> bool {
        match pattern {
            AddressPattern::Any => true,
            AddressPattern::Exact(ip) => addr == *ip,
            AddressPattern::Cidr(net) => Self::ip_in_network(addr, net),
        }
    }

    /// Check if an IP is within a CIDR network.
    fn ip_in_network(ip: Ipv4Addr, net: &Ipv4Net) -> bool {
        net.contains(&ip)
    }

    /// Check if a port matches a port pattern.
    fn matches_port(pattern: &PortPattern, port: u16) -> bool {
        match pattern {
            PortPattern::Any => true,
            PortPattern::Exact(p) => port == *p,
            PortPattern::Prefix(prefix) => {
                let port_str = port.to_string();
                port_str.starts_with(prefix)
            }
            PortPattern::Suffix(suffix) => {
                let port_str = port.to_string();
                port_str.ends_with(suffix)
            }
        }
    }
}

/// Result of matching a packet against a rule.
#[derive(Debug, Clone)]
pub struct MatchResult {
    pub rule_name: String,
    pub matched: bool,
    pub details: MatchDetails,
}

/// Detailed match information for debugging/explanation.
#[derive(Debug, Clone, Default)]
pub struct MatchDetails {
    pub direction_match: bool,
    pub protocol_match: bool,
    pub local_addr_match: bool,
    pub remote_addr_match: bool,
    pub local_port_match: bool,
    pub remote_port_match: bool,
}

impl RuleMatcher {
    /// Get detailed match information for explanation purposes.
    pub fn match_details(rule: &Rule, packet: &Packet) -> MatchResult {
        let details = MatchDetails {
            direction_match: Self::matches_direction(rule.direction, packet.direction),
            protocol_match: Self::matches_protocol(rule.protocol, packet.protocol),
            local_addr_match: Self::matches_address(&rule.local_addr, packet.local_addr),
            remote_addr_match: Self::matches_address(&rule.remote_addr, packet.remote_addr),
            local_port_match: Self::matches_port(&rule.local_port, packet.local_port),
            remote_port_match: Self::matches_port(&rule.remote_port, packet.remote_port),
        };

        let matched = details.direction_match
            && details.protocol_match
            && details.local_addr_match
            && details.remote_addr_match
            && details.local_port_match
            && details.remote_port_match;

        MatchResult {
            rule_name: rule.name.clone(),
            matched,
            details,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::packet::PacketBuilder;

    fn test_rule() -> Rule {
        Rule {
            name: "test".to_string(),
            direction: Direction::In,
            protocol: Protocol::Tcp,
            local_addr: "192.168.1.0/24".parse().unwrap(),
            remote_addr: AddressPattern::Any,
            local_port: "80".parse().unwrap(),
            remote_port: PortPattern::Any,
            ..Default::default()
        }
    }

    #[test]
    fn test_exact_match() {
        let rule = test_rule();
        let packet = PacketBuilder::new()
            .direction(Direction::In)
            .protocol(Protocol::Tcp)
            .local_addr_str("192.168.1.100")
            .unwrap()
            .local_port(80)
            .build();

        assert!(RuleMatcher::matches(&rule, &packet));
    }

    #[test]
    fn test_direction_mismatch() {
        let rule = test_rule();
        let packet = PacketBuilder::new()
            .direction(Direction::Out)
            .protocol(Protocol::Tcp)
            .local_addr_str("192.168.1.100")
            .unwrap()
            .local_port(80)
            .build();

        assert!(!RuleMatcher::matches(&rule, &packet));
    }

    #[test]
    fn test_protocol_mismatch() {
        let rule = test_rule();
        let packet = PacketBuilder::new()
            .direction(Direction::In)
            .protocol(Protocol::Udp)
            .local_addr_str("192.168.1.100")
            .unwrap()
            .local_port(80)
            .build();

        assert!(!RuleMatcher::matches(&rule, &packet));
    }

    #[test]
    fn test_cidr_match() {
        let rule = test_rule();

        // In range
        let packet1 = PacketBuilder::new()
            .direction(Direction::In)
            .protocol(Protocol::Tcp)
            .local_addr_str("192.168.1.254")
            .unwrap()
            .local_port(80)
            .build();
        assert!(RuleMatcher::matches(&rule, &packet1));

        // Out of range
        let packet2 = PacketBuilder::new()
            .direction(Direction::In)
            .protocol(Protocol::Tcp)
            .local_addr_str("192.168.2.1")
            .unwrap()
            .local_port(80)
            .build();
        assert!(!RuleMatcher::matches(&rule, &packet2));
    }

    #[test]
    fn test_port_pattern_prefix() {
        let rule = Rule {
            name: "test".to_string(),
            local_port: "6*".parse().unwrap(),
            ..Default::default()
        };

        // Matches: 6, 60, 600, 6000, 6999
        assert!(RuleMatcher::matches_port(&rule.local_port, 6));
        assert!(RuleMatcher::matches_port(&rule.local_port, 60));
        assert!(RuleMatcher::matches_port(&rule.local_port, 600));
        assert!(RuleMatcher::matches_port(&rule.local_port, 6000));
        assert!(RuleMatcher::matches_port(&rule.local_port, 6999));

        // Doesn't match: 80, 7000
        assert!(!RuleMatcher::matches_port(&rule.local_port, 80));
        assert!(!RuleMatcher::matches_port(&rule.local_port, 7000));
    }

    #[test]
    fn test_port_pattern_suffix() {
        let rule = Rule {
            name: "test".to_string(),
            local_port: "*9".parse().unwrap(),
            ..Default::default()
        };

        // Matches: 9, 19, 29, 99, 109, 8009
        assert!(RuleMatcher::matches_port(&rule.local_port, 9));
        assert!(RuleMatcher::matches_port(&rule.local_port, 19));
        assert!(RuleMatcher::matches_port(&rule.local_port, 99));
        assert!(RuleMatcher::matches_port(&rule.local_port, 8009));

        // Doesn't match: 80, 90
        assert!(!RuleMatcher::matches_port(&rule.local_port, 80));
        assert!(!RuleMatcher::matches_port(&rule.local_port, 90));
    }
}
