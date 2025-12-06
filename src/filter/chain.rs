//! Filter chain evaluation.

use crate::config::{Action, Config, Filter, Rule};
use crate::filter::modules::{ModuleRegistry, ModuleResult};
use crate::matcher::Packet;

/// Result of filter chain evaluation.
#[derive(Debug, Clone)]
pub struct FilterResult {
    /// Final action decision.
    pub action: Action,
    /// Mirror targets if mirroring is triggered.
    pub mirror_targets: Vec<String>,
    /// Redirect target if redirecting.
    pub redirect_to: Option<String>,
    /// Evaluation steps for explanation.
    pub steps: Vec<FilterStep>,
}

/// A single step in filter evaluation.
#[derive(Debug, Clone)]
pub struct FilterStep {
    pub filter_name: String,
    pub module: String,
    pub result: String,
    pub action_taken: Action,
}

/// Evaluates filter chains for matched rules.
pub struct FilterChain<'a> {
    config: &'a Config,
    registry: ModuleRegistry,
}

impl<'a> FilterChain<'a> {
    /// Create a new filter chain evaluator.
    pub fn new(config: &'a Config) -> Self {
        Self {
            config,
            registry: ModuleRegistry::new(),
        }
    }

    /// Evaluate the filter chain for a matched rule.
    pub fn evaluate(&self, rule: &Rule, packet: &Packet) -> FilterResult {
        let mut steps = Vec::new();
        let mut mirror_targets = Vec::new();

        // Process each filter in order
        for filter_name in &rule.filters {
            let Some(filter) = self.config.get_filter(filter_name) else {
                // Skip unknown filters (should be caught by validation)
                continue;
            };

            let (result, action) = self.evaluate_filter(filter, packet);

            // Collect mirror targets from mirror modules
            if filter.module == "mirror" {
                let targets = self.registry.mirror_targets(filter);
                mirror_targets.extend(targets);
            }

            steps.push(FilterStep {
                filter_name: filter.name.clone(),
                module: filter.module.clone(),
                result: format!("{:?}", result),
                action_taken: action,
            });

            // Check for final action
            if action.is_final() {
                // Collect mirror targets for mirror action
                if action == Action::Mirror && mirror_targets.is_empty() {
                    mirror_targets = self.registry.mirror_targets(filter);
                }

                return FilterResult {
                    action,
                    mirror_targets,
                    redirect_to: rule.redirect_to.clone(),
                    steps,
                };
            }
        }

        // All filters completed with continue/log, use rule's base action
        let action = rule.action;

        // Collect mirror targets if rule action is mirror
        if action == Action::Mirror && mirror_targets.is_empty() {
            // Try to find mirror targets from mirror filters
            for filter_name in &rule.filters {
                if let Some(filter) = self.config.get_filter(filter_name) {
                    if filter.module == "mirror" {
                        mirror_targets = self.registry.mirror_targets(filter);
                        break;
                    }
                }
            }
        }

        FilterResult {
            action,
            mirror_targets,
            redirect_to: rule.redirect_to.clone(),
            steps,
        }
    }

    /// Evaluate a single filter.
    fn evaluate_filter(&self, filter: &Filter, packet: &Packet) -> (ModuleResult, Action) {
        match self.registry.evaluate(filter, packet) {
            Ok(ModuleResult::Match) => (ModuleResult::Match, filter.on_match),
            Ok(ModuleResult::Miss) => (ModuleResult::Miss, filter.on_miss),
            Err(_) => {
                // On error, treat as miss and continue
                (ModuleResult::Miss, Action::Continue)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Filter, Rule, Set};
    use crate::matcher::packet::PacketBuilder;

    fn test_config() -> Config {
        Config {
            sets: vec![Set {
                name: "test".to_string(),
                rules: vec!["test-rule".to_string()],
            }],
            rules: vec![Rule {
                name: "test-rule".to_string(),
                action: Action::Accept,
                filters: vec!["regex-filter".to_string()],
                ..Default::default()
            }],
            filters: vec![Filter {
                name: "regex-filter".to_string(),
                module: "regex".to_string(),
                setup: vec!["secret".to_string()],
                on_match: Action::Drop,
                on_miss: Action::Continue,
            }],
            default_policy: Action::Accept,
        }
    }

    #[test]
    fn test_filter_match_drops() {
        let config = test_config();
        let chain = FilterChain::new(&config);
        let rule = &config.rules[0];

        let packet = PacketBuilder::new()
            .payload_str("secret data")
            .build();

        let result = chain.evaluate(rule, &packet);
        assert_eq!(result.action, Action::Drop);
    }

    #[test]
    fn test_filter_miss_continues() {
        let config = test_config();
        let chain = FilterChain::new(&config);
        let rule = &config.rules[0];

        let packet = PacketBuilder::new()
            .payload_str("public data")
            .build();

        let result = chain.evaluate(rule, &packet);
        assert_eq!(result.action, Action::Accept); // Falls through to rule action
    }

    #[test]
    fn test_mirror_targets_collected() {
        let config = Config {
            sets: vec![],
            rules: vec![Rule {
                name: "mirror-rule".to_string(),
                action: Action::Mirror,
                filters: vec!["mirror-filter".to_string()],
                ..Default::default()
            }],
            filters: vec![Filter {
                name: "mirror-filter".to_string(),
                module: "mirror".to_string(),
                setup: vec!["10.0.0.2:9000".to_string(), "10.0.0.3:9000".to_string()],
                on_match: Action::Mirror,
                on_miss: Action::Continue,
            }],
            default_policy: Action::Accept,
        };

        let chain = FilterChain::new(&config);
        let rule = &config.rules[0];
        let packet = PacketBuilder::new().build();

        let result = chain.evaluate(rule, &packet);
        assert_eq!(result.action, Action::Mirror);
        assert_eq!(result.mirror_targets.len(), 2);
    }
}
