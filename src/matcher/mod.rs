//! Packet matching functionality.

pub mod packet;
mod rule_matcher;

pub use packet::Packet;
pub use rule_matcher::{MatchDetails, MatchResult, RuleMatcher};
