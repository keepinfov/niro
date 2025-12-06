//! Configuration type definitions.

use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Traffic direction for packet matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
    #[default]
    Any,
}

impl FromStr for Direction {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "in" => Ok(Direction::In),
            "out" => Ok(Direction::Out),
            "any" => Ok(Direction::Any),
            _ => Err(ParseError::InvalidDirection(s.to_string())),
        }
    }
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Direction::In => write!(f, "in"),
            Direction::Out => write!(f, "out"),
            Direction::Any => write!(f, "any"),
        }
    }
}

/// Network protocol for packet matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    #[default]
    Any,
}

impl FromStr for Protocol {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            "any" => Ok(Protocol::Any),
            _ => Err(ParseError::InvalidProtocol(s.to_string())),
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Any => write!(f, "any"),
        }
    }
}

/// Action to take on a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Accept,
    Drop,
    Redirect,
    Mirror,
    #[default]
    Continue,
    Log,
}

impl FromStr for Action {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "accept" => Ok(Action::Accept),
            "drop" => Ok(Action::Drop),
            "redirect" => Ok(Action::Redirect),
            "mirror" => Ok(Action::Mirror),
            "continue" => Ok(Action::Continue),
            "log" => Ok(Action::Log),
            _ => Err(ParseError::InvalidAction(s.to_string())),
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Accept => write!(f, "accept"),
            Action::Drop => write!(f, "drop"),
            Action::Redirect => write!(f, "redirect"),
            Action::Mirror => write!(f, "mirror"),
            Action::Continue => write!(f, "continue"),
            Action::Log => write!(f, "log"),
        }
    }
}

impl Action {
    /// Returns true if this action is a final decision (not continue/log).
    pub fn is_final(&self) -> bool {
        !matches!(self, Action::Continue | Action::Log)
    }
}

/// Address pattern for matching IP addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressPattern {
    /// Match any address.
    Any,
    /// Match exact IPv4 address.
    Exact(std::net::Ipv4Addr),
    /// Match CIDR network.
    Cidr(ipnet::Ipv4Net),
}

impl Default for AddressPattern {
    fn default() -> Self {
        AddressPattern::Any
    }
}

impl FromStr for AddressPattern {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s == "*" {
            return Ok(AddressPattern::Any);
        }

        // Try CIDR first
        if s.contains('/') {
            let net: ipnet::Ipv4Net = s
                .parse()
                .map_err(|_| ParseError::InvalidAddress(s.to_string()))?;
            return Ok(AddressPattern::Cidr(net));
        }

        // Try exact IP
        let ip: std::net::Ipv4Addr = s
            .parse()
            .map_err(|_| ParseError::InvalidAddress(s.to_string()))?;
        Ok(AddressPattern::Exact(ip))
    }
}

impl std::fmt::Display for AddressPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressPattern::Any => write!(f, "*"),
            AddressPattern::Exact(ip) => write!(f, "{}", ip),
            AddressPattern::Cidr(net) => write!(f, "{}", net),
        }
    }
}

/// Port pattern for matching ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortPattern {
    /// Match any port.
    Any,
    /// Match exact port.
    Exact(u16),
    /// Match ports starting with prefix (e.g., "6*" matches 6, 60-69, 600-699, etc.).
    Prefix(String),
    /// Match ports ending with suffix (e.g., "*9" matches 9, 19, 29, etc.).
    Suffix(String),
}

impl Default for PortPattern {
    fn default() -> Self {
        PortPattern::Any
    }
}

impl FromStr for PortPattern {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s == "*" {
            return Ok(PortPattern::Any);
        }

        // Check for prefix pattern (e.g., "6*")
        if s.ends_with('*') && !s.starts_with('*') {
            let prefix = &s[..s.len() - 1];
            if prefix.chars().all(|c| c.is_ascii_digit()) && !prefix.is_empty() {
                return Ok(PortPattern::Prefix(prefix.to_string()));
            }
            return Err(ParseError::InvalidPort(s.to_string()));
        }

        // Check for suffix pattern (e.g., "*9")
        if s.starts_with('*') && !s.ends_with('*') {
            let suffix = &s[1..];
            if suffix.chars().all(|c| c.is_ascii_digit()) && !suffix.is_empty() {
                return Ok(PortPattern::Suffix(suffix.to_string()));
            }
            return Err(ParseError::InvalidPort(s.to_string()));
        }

        // Exact port
        let port: u16 = s.parse().map_err(|_| ParseError::InvalidPort(s.to_string()))?;
        Ok(PortPattern::Exact(port))
    }
}

impl std::fmt::Display for PortPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortPattern::Any => write!(f, "*"),
            PortPattern::Exact(port) => write!(f, "{}", port),
            PortPattern::Prefix(p) => write!(f, "{}*", p),
            PortPattern::Suffix(s) => write!(f, "*{}", s),
        }
    }
}

/// A named set of rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Set {
    pub name: String,
    pub rules: Vec<String>,
}

/// A packet matching rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub direction: Direction,
    pub protocol: Protocol,
    pub local_addr: AddressPattern,
    pub remote_addr: AddressPattern,
    pub local_port: PortPattern,
    pub remote_port: PortPattern,
    pub action: Action,
    pub redirect_to: Option<String>,
    pub filters: Vec<String>,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            name: String::new(),
            direction: Direction::Any,
            protocol: Protocol::Any,
            local_addr: AddressPattern::Any,
            remote_addr: AddressPattern::Any,
            local_port: PortPattern::Any,
            remote_port: PortPattern::Any,
            action: Action::Continue,
            redirect_to: None,
            filters: Vec::new(),
        }
    }
}

/// Raw rule for TOML deserialization.
#[derive(Debug, Deserialize)]
pub struct RawRule {
    pub name: String,
    #[serde(default)]
    pub direction: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub local_addr: Option<String>,
    #[serde(default)]
    pub remote_addr: Option<String>,
    #[serde(default)]
    pub local_port: Option<String>,
    #[serde(default)]
    pub remote_port: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub redirect_to: Option<String>,
    #[serde(default)]
    pub filters: Option<Vec<String>>,
}

impl From<RawRule> for Rule {
    fn from(raw: RawRule) -> Self {
        Self {
            name: raw.name,
            direction: raw
                .direction
                .and_then(|s| s.parse().ok())
                .unwrap_or_default(),
            protocol: raw
                .protocol
                .and_then(|s| s.parse().ok())
                .unwrap_or_default(),
            local_addr: raw
                .local_addr
                .and_then(|s| s.parse().ok())
                .unwrap_or_default(),
            remote_addr: raw
                .remote_addr
                .and_then(|s| s.parse().ok())
                .unwrap_or_default(),
            local_port: raw
                .local_port
                .and_then(|s| s.parse().ok())
                .unwrap_or_default(),
            remote_port: raw
                .remote_port
                .and_then(|s| s.parse().ok())
                .unwrap_or_default(),
            action: raw.action.and_then(|s| s.parse().ok()).unwrap_or_default(),
            redirect_to: raw.redirect_to,
            filters: raw.filters.unwrap_or_default(),
        }
    }
}

/// A packet filter.
#[derive(Debug, Clone)]
pub struct Filter {
    pub name: String,
    pub module: String,
    pub setup: Vec<String>,
    pub on_match: Action,
    pub on_miss: Action,
}

impl Default for Filter {
    fn default() -> Self {
        Self {
            name: String::new(),
            module: String::new(),
            setup: Vec::new(),
            on_match: Action::Continue,
            on_miss: Action::Continue,
        }
    }
}

/// Raw filter for TOML deserialization.
#[derive(Debug, Deserialize)]
pub struct RawFilter {
    pub name: String,
    pub module: String,
    #[serde(default)]
    pub setup: Option<Vec<String>>,
    #[serde(default)]
    pub on_match: Option<String>,
    #[serde(default)]
    pub on_miss: Option<String>,
}

impl From<RawFilter> for Filter {
    fn from(raw: RawFilter) -> Self {
        Self {
            name: raw.name,
            module: raw.module,
            setup: raw.setup.unwrap_or_default(),
            on_match: raw
                .on_match
                .and_then(|s| s.parse().ok())
                .unwrap_or(Action::Continue),
            on_miss: raw
                .on_miss
                .and_then(|s| s.parse().ok())
                .unwrap_or(Action::Continue),
        }
    }
}

/// Parse errors for configuration types.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ParseError {
    #[error("invalid direction: {0}")]
    InvalidDirection(String),

    #[error("invalid protocol: {0}")]
    InvalidProtocol(String),

    #[error("invalid action: {0}")]
    InvalidAction(String),

    #[error("invalid address pattern: {0}")]
    InvalidAddress(String),

    #[error("invalid port pattern: {0}")]
    InvalidPort(String),
}
