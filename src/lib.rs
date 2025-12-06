//! # niro - Network Interface Rules Orchestrator
//!
//! Lightweight Rust library for managing network rules and filtering packets.

pub mod config;
pub mod engine;
pub mod filter;
pub mod matcher;

pub use config::{Config, Filter, Rule, Set};
pub use engine::Engine;
pub use matcher::{MatchDetails, Packet};
