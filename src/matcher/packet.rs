//! Packet representation for matching and filtering.

use crate::config::{Direction, Protocol};
use std::net::Ipv4Addr;

/// Represents a network packet for evaluation.
#[derive(Debug, Clone)]
pub struct Packet {
    /// Traffic direction.
    pub direction: Direction,
    /// Network protocol.
    pub protocol: Protocol,
    /// Local IP address.
    pub local_addr: Ipv4Addr,
    /// Remote IP address.
    pub remote_addr: Ipv4Addr,
    /// Local port.
    pub local_port: u16,
    /// Remote port.
    pub remote_port: u16,
    /// Packet payload data.
    pub payload: Vec<u8>,
}

impl Packet {
    /// Create a new packet.
    pub fn new(
        direction: Direction,
        protocol: Protocol,
        local_addr: Ipv4Addr,
        remote_addr: Ipv4Addr,
        local_port: u16,
        remote_port: u16,
    ) -> Self {
        Self {
            direction,
            protocol,
            local_addr,
            remote_addr,
            local_port,
            remote_port,
            payload: Vec::new(),
        }
    }

    /// Create a packet with payload.
    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    /// Get payload as a string (lossy UTF-8 conversion).
    pub fn payload_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.payload)
    }
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            direction: Direction::Any,
            protocol: Protocol::Any,
            local_addr: Ipv4Addr::UNSPECIFIED,
            remote_addr: Ipv4Addr::UNSPECIFIED,
            local_port: 0,
            remote_port: 0,
            payload: Vec::new(),
        }
    }
}

/// Builder for creating packets from CLI or test input.
#[derive(Debug, Default)]
pub struct PacketBuilder {
    direction: Option<Direction>,
    protocol: Option<Protocol>,
    local_addr: Option<Ipv4Addr>,
    remote_addr: Option<Ipv4Addr>,
    local_port: Option<u16>,
    remote_port: Option<u16>,
    payload: Option<Vec<u8>>,
}

impl PacketBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn direction(mut self, dir: Direction) -> Self {
        self.direction = Some(dir);
        self
    }

    pub fn direction_str(mut self, s: &str) -> Result<Self, String> {
        self.direction = Some(s.parse().map_err(|e| format!("{}", e))?);
        Ok(self)
    }

    pub fn protocol(mut self, proto: Protocol) -> Self {
        self.protocol = Some(proto);
        self
    }

    pub fn protocol_str(mut self, s: &str) -> Result<Self, String> {
        self.protocol = Some(s.parse().map_err(|e| format!("{}", e))?);
        Ok(self)
    }

    pub fn local_addr(mut self, addr: Ipv4Addr) -> Self {
        self.local_addr = Some(addr);
        self
    }

    pub fn local_addr_str(mut self, s: &str) -> Result<Self, String> {
        self.local_addr = Some(s.parse().map_err(|e| format!("{}", e))?);
        Ok(self)
    }

    pub fn remote_addr(mut self, addr: Ipv4Addr) -> Self {
        self.remote_addr = Some(addr);
        self
    }

    pub fn remote_addr_str(mut self, s: &str) -> Result<Self, String> {
        self.remote_addr = Some(s.parse().map_err(|e| format!("{}", e))?);
        Ok(self)
    }

    pub fn local_port(mut self, port: u16) -> Self {
        self.local_port = Some(port);
        self
    }

    pub fn remote_port(mut self, port: u16) -> Self {
        self.remote_port = Some(port);
        self
    }

    pub fn payload(mut self, data: Vec<u8>) -> Self {
        self.payload = Some(data);
        self
    }

    pub fn payload_str(mut self, s: &str) -> Self {
        self.payload = Some(s.as_bytes().to_vec());
        self
    }

    pub fn build(self) -> Packet {
        Packet {
            direction: self.direction.unwrap_or(Direction::Any),
            protocol: self.protocol.unwrap_or(Protocol::Any),
            local_addr: self.local_addr.unwrap_or(Ipv4Addr::UNSPECIFIED),
            remote_addr: self.remote_addr.unwrap_or(Ipv4Addr::UNSPECIFIED),
            local_port: self.local_port.unwrap_or(0),
            remote_port: self.remote_port.unwrap_or(0),
            payload: self.payload.unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_builder() {
        let packet = PacketBuilder::new()
            .direction(Direction::In)
            .protocol(Protocol::Tcp)
            .local_addr_str("192.168.1.1")
            .unwrap()
            .remote_addr_str("10.0.0.1")
            .unwrap()
            .local_port(80)
            .remote_port(12345)
            .payload_str("GET / HTTP/1.1")
            .build();

        assert_eq!(packet.direction, Direction::In);
        assert_eq!(packet.protocol, Protocol::Tcp);
        assert_eq!(packet.local_addr, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(packet.remote_addr, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(packet.local_port, 80);
        assert_eq!(packet.remote_port, 12345);
        assert_eq!(packet.payload_str(), "GET / HTTP/1.1");
    }
}
