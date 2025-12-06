//! Configuration validation.

use super::{Action, Config};
use std::collections::HashSet;
use thiserror::Error;

/// Errors that can occur during validation.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("duplicate set name: {0}")]
    DuplicateSet(String),

    #[error("duplicate rule name: {0}")]
    DuplicateRule(String),

    #[error("duplicate filter name: {0}")]
    DuplicateFilter(String),

    #[error("set '{set}' references unknown rule: {rule}")]
    UnknownRule { set: String, rule: String },

    #[error("rule '{rule}' references unknown filter: {filter}")]
    UnknownFilter { rule: String, filter: String },

    #[error("rule '{rule}' has action 'redirect' but no redirect_to specified")]
    MissingRedirectTarget { rule: String },

    #[error("rule '{rule}' has invalid redirect_to format: {target}")]
    InvalidRedirectTarget { rule: String, target: String },

    #[error("multiple errors: {}", .0.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; "))]
    Multiple(Vec<ValidationError>),
}

/// Validate a configuration.
pub fn validate(config: &Config) -> Result<(), ValidationError> {
    let mut errors = Vec::new();

    // Check for duplicate names
    if let Err(e) = check_duplicates(&config.sets.iter().map(|s| &s.name).collect::<Vec<_>>(), "set")
    {
        errors.push(e);
    }
    if let Err(e) =
        check_duplicates(&config.rules.iter().map(|r| &r.name).collect::<Vec<_>>(), "rule")
    {
        errors.push(e);
    }
    if let Err(e) = check_duplicates(
        &config.filters.iter().map(|f| &f.name).collect::<Vec<_>>(),
        "filter",
    ) {
        errors.push(e);
    }

    // Build name sets for reference checking
    let rule_names: HashSet<_> = config.rules.iter().map(|r| r.name.as_str()).collect();
    let filter_names: HashSet<_> = config.filters.iter().map(|f| f.name.as_str()).collect();

    // Check set references
    for set in &config.sets {
        for rule_name in &set.rules {
            if !rule_names.contains(rule_name.as_str()) {
                errors.push(ValidationError::UnknownRule {
                    set: set.name.clone(),
                    rule: rule_name.clone(),
                });
            }
        }
    }

    // Check rule references and redirect_to requirements
    for rule in &config.rules {
        for filter_name in &rule.filters {
            if !filter_names.contains(filter_name.as_str()) {
                errors.push(ValidationError::UnknownFilter {
                    rule: rule.name.clone(),
                    filter: filter_name.clone(),
                });
            }
        }

        // Check redirect_to when redirect is possible
        if needs_redirect_target(rule, config) {
            match &rule.redirect_to {
                None => {
                    errors.push(ValidationError::MissingRedirectTarget {
                        rule: rule.name.clone(),
                    });
                }
                Some(target) if !is_valid_redirect_target(target) => {
                    errors.push(ValidationError::InvalidRedirectTarget {
                        rule: rule.name.clone(),
                        target: target.clone(),
                    });
                }
                _ => {}
            }
        }

        // Validate redirect_to format if present
        if let Some(target) = &rule.redirect_to {
            if !is_valid_redirect_target(target) {
                errors.push(ValidationError::InvalidRedirectTarget {
                    rule: rule.name.clone(),
                    target: target.clone(),
                });
            }
        }
    }

    match errors.len() {
        0 => Ok(()),
        1 => Err(errors.pop().unwrap()),
        _ => Err(ValidationError::Multiple(errors)),
    }
}

fn check_duplicates(names: &[&String], kind: &str) -> Result<(), ValidationError> {
    let mut seen = HashSet::new();
    for name in names {
        if !seen.insert(*name) {
            return Err(match kind {
                "set" => ValidationError::DuplicateSet((*name).clone()),
                "rule" => ValidationError::DuplicateRule((*name).clone()),
                "filter" => ValidationError::DuplicateFilter((*name).clone()),
                _ => unreachable!(),
            });
        }
    }
    Ok(())
}

fn needs_redirect_target(rule: &super::Rule, config: &Config) -> bool {
    // Check if rule action is redirect
    if rule.action == Action::Redirect {
        return true;
    }

    // Check if any filter can trigger redirect
    for filter_name in &rule.filters {
        if let Some(filter) = config.get_filter(filter_name) {
            if filter.on_match == Action::Redirect || filter.on_miss == Action::Redirect {
                return true;
            }
        }
    }

    false
}

fn is_valid_redirect_target(target: &str) -> bool {
    // Format: "ip:port" or "hostname:port"
    let parts: Vec<&str> = target.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return false;
    }

    // Check port
    let port = parts[0];
    if port.parse::<u16>().is_err() {
        return false;
    }

    // Check host (either IP or non-empty string)
    let host = parts[1];
    !host.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Filter, Rule, Set};

    #[test]
    fn test_valid_config() {
        let config = Config {
            sets: vec![Set {
                name: "test".to_string(),
                rules: vec!["rule1".to_string()],
            }],
            rules: vec![Rule {
                name: "rule1".to_string(),
                filters: vec!["filter1".to_string()],
                ..Default::default()
            }],
            filters: vec![Filter {
                name: "filter1".to_string(),
                module: "regex".to_string(),
                ..Default::default()
            }],
            default_policy: Action::Accept,
        };

        assert!(validate(&config).is_ok());
    }

    #[test]
    fn test_duplicate_set() {
        let config = Config {
            sets: vec![
                Set {
                    name: "test".to_string(),
                    rules: vec![],
                },
                Set {
                    name: "test".to_string(),
                    rules: vec![],
                },
            ],
            ..Default::default()
        };

        assert!(matches!(
            validate(&config),
            Err(ValidationError::DuplicateSet(_))
        ));
    }

    #[test]
    fn test_unknown_rule() {
        let config = Config {
            sets: vec![Set {
                name: "test".to_string(),
                rules: vec!["nonexistent".to_string()],
            }],
            ..Default::default()
        };

        assert!(matches!(
            validate(&config),
            Err(ValidationError::UnknownRule { .. })
        ));
    }

    #[test]
    fn test_valid_redirect_target() {
        assert!(is_valid_redirect_target("127.0.0.1:8080"));
        assert!(is_valid_redirect_target("localhost:80"));
        assert!(is_valid_redirect_target("10.0.0.1:9000"));
        assert!(!is_valid_redirect_target("invalid"));
        assert!(!is_valid_redirect_target(":8080"));
        assert!(!is_valid_redirect_target("127.0.0.1:"));
        assert!(!is_valid_redirect_target("127.0.0.1:99999"));
    }
}
