//! Packet evaluation engine.

use crate::config::{Action, Config, Rule};
use crate::filter::FilterChain;
use crate::matcher::{Packet, RuleMatcher};

/// Engine for evaluating packets against configuration.
pub struct Engine {
    config: Config,
}

impl Engine {
    /// Create a new engine with the given configuration.
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Get a reference to the configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Evaluate a packet against active sets.
    pub fn evaluate(&self, packet: &Packet, active_sets: &[String]) -> EvaluationResult {
        let chain = FilterChain::new(&self.config);
        let mut steps = Vec::new();

        // Evaluate each active set in order
        for set_name in active_sets {
            let Some(set) = self.config.get_set(set_name) else {
                steps.push(EvaluationStep::SetNotFound {
                    set_name: set_name.clone(),
                });
                continue;
            };

            steps.push(EvaluationStep::SetStarted {
                set_name: set_name.clone(),
            });

            // Evaluate rules in the set
            for rule_name in &set.rules {
                let Some(rule) = self.config.get_rule(rule_name) else {
                    steps.push(EvaluationStep::RuleNotFound {
                        rule_name: rule_name.clone(),
                    });
                    continue;
                };

                // Check if rule matches the packet
                let match_result = RuleMatcher::match_details(rule, packet);
                steps.push(EvaluationStep::RuleEvaluated {
                    rule_name: rule_name.clone(),
                    matched: match_result.matched,
                    details: match_result.details,
                });

                if !match_result.matched {
                    continue;
                }

                // Rule matched - evaluate filter chain
                let filter_result = chain.evaluate(rule, packet);
                steps.push(EvaluationStep::FilterChainEvaluated {
                    rule_name: rule_name.clone(),
                    filter_steps: filter_result.steps.clone(),
                    result_action: filter_result.action,
                });

                // Check if this provides a final decision
                if filter_result.action.is_final() {
                    return EvaluationResult {
                        decision: Decision::from_action(
                            filter_result.action,
                            filter_result.redirect_to,
                            filter_result.mirror_targets,
                        ),
                        steps,
                    };
                }
            }
        }

        // No rule provided a final decision, use default policy
        EvaluationResult {
            decision: Decision::from_action(self.config.default_policy, None, Vec::new()),
            steps,
        }
    }

    /// Explain how a packet would be evaluated (detailed for CLI).
    pub fn explain(&self, packet: &Packet, active_sets: &[String]) -> Explanation {
        let result = self.evaluate(packet, active_sets);

        Explanation {
            packet_summary: format!(
                "{} {} {}:{} -> {}:{}",
                packet.direction,
                packet.protocol,
                packet.local_addr,
                packet.local_port,
                packet.remote_addr,
                packet.remote_port
            ),
            active_sets: active_sets.to_vec(),
            steps: result.steps,
            final_decision: result.decision,
        }
    }

    /// Get rules that would match a packet (without full evaluation).
    pub fn matching_rules(&self, packet: &Packet, active_sets: &[String]) -> Vec<&Rule> {
        let mut matching = Vec::new();

        for set_name in active_sets {
            let Some(set) = self.config.get_set(set_name) else {
                continue;
            };

            for rule_name in &set.rules {
                if let Some(rule) = self.config.get_rule(rule_name) {
                    if RuleMatcher::matches(rule, packet) {
                        matching.push(rule);
                    }
                }
            }
        }

        matching
    }
}

/// Final decision for a packet.
#[derive(Debug, Clone)]
pub enum Decision {
    Accept,
    Drop,
    Redirect { target: String },
    Mirror { targets: Vec<String> },
}

impl Decision {
    fn from_action(action: Action, redirect_to: Option<String>, mirror_targets: Vec<String>) -> Self {
        match action {
            Action::Accept | Action::Continue | Action::Log => Decision::Accept,
            Action::Drop => Decision::Drop,
            Action::Redirect => Decision::Redirect {
                target: redirect_to.unwrap_or_else(|| "unknown".to_string()),
            },
            Action::Mirror => Decision::Mirror {
                targets: mirror_targets,
            },
        }
    }
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Accept => write!(f, "ACCEPT"),
            Decision::Drop => write!(f, "DROP"),
            Decision::Redirect { target } => write!(f, "REDIRECT to {}", target),
            Decision::Mirror { targets } => {
                write!(f, "MIRROR to {}", targets.join(", "))
            }
        }
    }
}

/// Result of packet evaluation.
#[derive(Debug)]
pub struct EvaluationResult {
    pub decision: Decision,
    pub steps: Vec<EvaluationStep>,
}

/// A step in the evaluation process.
#[derive(Debug, Clone)]
pub enum EvaluationStep {
    SetStarted {
        set_name: String,
    },
    SetNotFound {
        set_name: String,
    },
    RuleNotFound {
        rule_name: String,
    },
    RuleEvaluated {
        rule_name: String,
        matched: bool,
        details: crate::matcher::MatchDetails,
    },
    FilterChainEvaluated {
        rule_name: String,
        filter_steps: Vec<crate::filter::FilterStep>,
        result_action: Action,
    },
}

/// Detailed explanation of packet evaluation.
#[derive(Debug)]
pub struct Explanation {
    pub packet_summary: String,
    pub active_sets: Vec<String>,
    pub steps: Vec<EvaluationStep>,
    pub final_decision: Decision,
}

impl Explanation {
    /// Format the explanation for display.
    pub fn format(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!("Packet: {}\n", self.packet_summary));
        output.push_str(&format!("Active sets: {}\n", self.active_sets.join(", ")));
        output.push_str("\nEvaluation:\n");

        for step in &self.steps {
            match step {
                EvaluationStep::SetStarted { set_name } => {
                    output.push_str(&format!("  Set '{}' started\n", set_name));
                }
                EvaluationStep::SetNotFound { set_name } => {
                    output.push_str(&format!("  Set '{}' not found\n", set_name));
                }
                EvaluationStep::RuleNotFound { rule_name } => {
                    output.push_str(&format!("    Rule '{}' not found\n", rule_name));
                }
                EvaluationStep::RuleEvaluated {
                    rule_name,
                    matched,
                    details,
                } => {
                    let status = if *matched { "MATCH" } else { "no match" };
                    output.push_str(&format!("    Rule '{}': {}\n", rule_name, status));
                    if !matched {
                        // Show which condition failed
                        if !details.direction_match {
                            output.push_str("      - direction mismatch\n");
                        }
                        if !details.protocol_match {
                            output.push_str("      - protocol mismatch\n");
                        }
                        if !details.local_addr_match {
                            output.push_str("      - local_addr mismatch\n");
                        }
                        if !details.remote_addr_match {
                            output.push_str("      - remote_addr mismatch\n");
                        }
                        if !details.local_port_match {
                            output.push_str("      - local_port mismatch\n");
                        }
                        if !details.remote_port_match {
                            output.push_str("      - remote_port mismatch\n");
                        }
                    }
                }
                EvaluationStep::FilterChainEvaluated {
                    rule_name,
                    filter_steps,
                    result_action,
                } => {
                    output.push_str(&format!(
                        "    Rule '{}' filter chain -> {}\n",
                        rule_name, result_action
                    ));
                    for fs in filter_steps {
                        output.push_str(&format!(
                            "      Filter '{}' ({}): {} -> {}\n",
                            fs.filter_name, fs.module, fs.result, fs.action_taken
                        ));
                    }
                }
            }
        }

        output.push_str(&format!("\nFinal decision: {}\n", self.final_decision));
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Direction, Filter, Protocol, Rule, Set};
    use crate::matcher::packet::PacketBuilder;

    fn test_config() -> Config {
        Config {
            sets: vec![Set {
                name: "default".to_string(),
                rules: vec!["block-secret".to_string(), "allow-all".to_string()],
            }],
            rules: vec![
                Rule {
                    name: "block-secret".to_string(),
                    direction: Direction::Any,
                    protocol: Protocol::Any,
                    action: Action::Continue,
                    filters: vec!["secret-filter".to_string()],
                    ..Default::default()
                },
                Rule {
                    name: "allow-all".to_string(),
                    action: Action::Accept,
                    ..Default::default()
                },
            ],
            filters: vec![Filter {
                name: "secret-filter".to_string(),
                module: "regex".to_string(),
                setup: vec!["secret".to_string()],
                on_match: Action::Drop,
                on_miss: Action::Continue,
            }],
            default_policy: Action::Accept,
        }
    }

    #[test]
    fn test_packet_blocked_by_filter() {
        let config = test_config();
        let engine = Engine::new(config);

        let packet = PacketBuilder::new()
            .direction(Direction::In)
            .protocol(Protocol::Tcp)
            .payload_str("contains secret data")
            .build();

        let result = engine.evaluate(&packet, &["default".to_string()]);
        assert!(matches!(result.decision, Decision::Drop));
    }

    #[test]
    fn test_packet_accepted() {
        let config = test_config();
        let engine = Engine::new(config);

        let packet = PacketBuilder::new()
            .direction(Direction::In)
            .protocol(Protocol::Tcp)
            .payload_str("public data")
            .build();

        let result = engine.evaluate(&packet, &["default".to_string()]);
        assert!(matches!(result.decision, Decision::Accept));
    }

    #[test]
    fn test_explanation() {
        let config = test_config();
        let engine = Engine::new(config);

        let packet = PacketBuilder::new()
            .direction(Direction::In)
            .protocol(Protocol::Tcp)
            .local_addr_str("192.168.1.1")
            .unwrap()
            .remote_addr_str("10.0.0.1")
            .unwrap()
            .local_port(80)
            .remote_port(12345)
            .payload_str("public data")
            .build();

        let explanation = engine.explain(&packet, &["default".to_string()]);
        let formatted = explanation.format();

        assert!(formatted.contains("Packet:"));
        assert!(formatted.contains("Final decision:"));
    }
}
