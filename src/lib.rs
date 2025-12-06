//! # niro - Network Interface Rules Orchestrator
//!
//! Lightweight Rust library for managing network rules and filtering packets.

pub mod config;
pub mod engine;
pub mod filter;
pub mod matcher;

#[cfg(target_os = "linux")]
pub mod linux;

pub use config::{Config, Filter, Rule, Set};
pub use engine::Engine;
pub use matcher::{MatchDetails, Packet};

#[cfg(target_os = "linux")]
pub use linux::{NfqueueError, NfqueueRunner, Stats};
