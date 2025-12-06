//! Configuration parsing and validation for niro.

mod types;
mod validator;

pub use types::*;
pub use validator::ValidationError;

use std::path::Path;
use thiserror::Error;

/// Errors that can occur when loading configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse TOML: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("validation failed: {0}")]
    Validation(#[from] ValidationError),
}

/// Complete niro configuration.
#[derive(Debug, Clone, Default)]
pub struct Config {
    pub sets: Vec<Set>,
    pub rules: Vec<Rule>,
    pub filters: Vec<Filter>,
    pub default_policy: Action,
}

impl Config {
    /// Load configuration from a TOML file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_str(&content)
    }

    /// Parse configuration from a TOML string.
    pub fn from_str(content: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(content)?;
        let config = Self::from_raw(raw);
        validator::validate(&config)?;
        Ok(config)
    }

    /// Merge another configuration into this one.
    /// Later definitions override earlier ones by name.
    pub fn merge(&mut self, other: Config) {
        // Merge sets - later overrides by name
        for set in other.sets {
            if let Some(existing) = self.sets.iter_mut().find(|s| s.name == set.name) {
                *existing = set;
            } else {
                self.sets.push(set);
            }
        }

        // Merge rules - later overrides by name
        for rule in other.rules {
            if let Some(existing) = self.rules.iter_mut().find(|r| r.name == rule.name) {
                *existing = rule;
            } else {
                self.rules.push(rule);
            }
        }

        // Merge filters - later overrides by name
        for filter in other.filters {
            if let Some(existing) = self.filters.iter_mut().find(|f| f.name == filter.name) {
                *existing = filter;
            } else {
                self.filters.push(filter);
            }
        }
    }

    /// Load and merge multiple configuration files.
    pub fn from_files(paths: &[impl AsRef<Path>]) -> Result<Self, ConfigError> {
        let mut config = Config::default();
        for path in paths {
            let other = Config::from_file(path)?;
            config.merge(other);
        }
        validator::validate(&config)?;
        Ok(config)
    }

    fn from_raw(raw: RawConfig) -> Self {
        Self {
            sets: raw.set.unwrap_or_default(),
            rules: raw.rule.unwrap_or_default().into_iter().map(Rule::from).collect(),
            filters: raw.filter.unwrap_or_default().into_iter().map(Filter::from).collect(),
            default_policy: raw
                .default_policy
                .map(|s| s.parse().unwrap_or(Action::Accept))
                .unwrap_or(Action::Accept),
        }
    }

    /// Get a set by name.
    pub fn get_set(&self, name: &str) -> Option<&Set> {
        self.sets.iter().find(|s| s.name == name)
    }

    /// Get a rule by name.
    pub fn get_rule(&self, name: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.name == name)
    }

    /// Get a filter by name.
    pub fn get_filter(&self, name: &str) -> Option<&Filter> {
        self.filters.iter().find(|f| f.name == name)
    }
}

/// Raw TOML structure for deserialization.
#[derive(Debug, serde::Deserialize)]
struct RawConfig {
    #[serde(default)]
    set: Option<Vec<Set>>,
    #[serde(default)]
    rule: Option<Vec<RawRule>>,
    #[serde(default)]
    filter: Option<Vec<RawFilter>>,
    #[serde(default)]
    default_policy: Option<String>,
}
