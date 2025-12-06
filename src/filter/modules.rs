//! Filter module implementations.

use crate::config::Filter;
use crate::matcher::Packet;
use regex::Regex;
use std::collections::HashMap;
use thiserror::Error;

/// Errors that can occur in filter modules.
#[derive(Debug, Error)]
pub enum ModuleError {
    #[error("unknown module: {0}")]
    UnknownModule(String),

    #[error("invalid setup for module '{module}': {reason}")]
    InvalidSetup { module: String, reason: String },

    #[error("regex compilation error: {0}")]
    RegexError(#[from] regex::Error),
}

/// Result of a filter module evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleResult {
    /// Filter matched the packet.
    Match,
    /// Filter did not match the packet.
    Miss,
}

/// Trait for filter module implementations.
pub trait FilterModule: Send + Sync {
    /// Get the module name.
    fn name(&self) -> &str;

    /// Evaluate a packet against this module's logic.
    fn evaluate(&self, packet: &Packet, setup: &[String]) -> Result<ModuleResult, ModuleError>;

    /// Get mirror targets if this module provides them.
    fn mirror_targets(&self, setup: &[String]) -> Vec<String> {
        let _ = setup;
        Vec::new()
    }
}

/// Registry of available filter modules.
pub struct ModuleRegistry {
    modules: HashMap<String, Box<dyn FilterModule>>,
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleRegistry {
    /// Create a new registry with built-in modules.
    pub fn new() -> Self {
        let mut registry = Self {
            modules: HashMap::new(),
        };

        // Register built-in modules
        registry.register(Box::new(RegexModule));
        registry.register(Box::new(MirrorModule));
        registry.register(Box::new(CustomModule));

        registry
    }

    /// Register a new module.
    pub fn register(&mut self, module: Box<dyn FilterModule>) {
        self.modules.insert(module.name().to_string(), module);
    }

    /// Get a module by name.
    pub fn get(&self, name: &str) -> Option<&dyn FilterModule> {
        self.modules.get(name).map(|m| m.as_ref())
    }

    /// Evaluate a filter against a packet.
    pub fn evaluate(
        &self,
        filter: &Filter,
        packet: &Packet,
    ) -> Result<ModuleResult, ModuleError> {
        let module = self
            .get(&filter.module)
            .ok_or_else(|| ModuleError::UnknownModule(filter.module.clone()))?;

        module.evaluate(packet, &filter.setup)
    }

    /// Get mirror targets from a filter.
    pub fn mirror_targets(&self, filter: &Filter) -> Vec<String> {
        self.get(&filter.module)
            .map(|m| m.mirror_targets(&filter.setup))
            .unwrap_or_default()
    }
}

/// Regex filter module for content matching.
struct RegexModule;

impl FilterModule for RegexModule {
    fn name(&self) -> &str {
        "regex"
    }

    fn evaluate(&self, packet: &Packet, setup: &[String]) -> Result<ModuleResult, ModuleError> {
        if setup.is_empty() {
            return Err(ModuleError::InvalidSetup {
                module: "regex".to_string(),
                reason: "at least one regex pattern required".to_string(),
            });
        }

        let payload = packet.payload_str();

        // Match if ANY pattern matches
        for pattern in setup {
            let re = Regex::new(pattern)?;
            if re.is_match(&payload) {
                return Ok(ModuleResult::Match);
            }
        }

        Ok(ModuleResult::Miss)
    }
}

/// Mirror filter module for traffic duplication.
struct MirrorModule;

impl FilterModule for MirrorModule {
    fn name(&self) -> &str {
        "mirror"
    }

    fn evaluate(&self, _packet: &Packet, setup: &[String]) -> Result<ModuleResult, ModuleError> {
        // Mirror module always matches if there are targets configured
        if setup.is_empty() {
            Ok(ModuleResult::Miss)
        } else {
            Ok(ModuleResult::Match)
        }
    }

    fn mirror_targets(&self, setup: &[String]) -> Vec<String> {
        // Each setup entry is an "ip:port" target
        setup.to_vec()
    }
}

/// Custom filter module for user-defined logic.
struct CustomModule;

impl FilterModule for CustomModule {
    fn name(&self) -> &str {
        "custom"
    }

    fn evaluate(&self, _packet: &Packet, _setup: &[String]) -> Result<ModuleResult, ModuleError> {
        // Custom module is a placeholder - always continues
        // In a real implementation, this could load external logic
        Ok(ModuleResult::Miss)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::packet::PacketBuilder;

    #[test]
    fn test_regex_module_match() {
        let module = RegexModule;
        let packet = PacketBuilder::new()
            .payload_str("GET /api/secret HTTP/1.1")
            .build();

        let result = module.evaluate(&packet, &["secret".to_string()]).unwrap();
        assert_eq!(result, ModuleResult::Match);
    }

    #[test]
    fn test_regex_module_miss() {
        let module = RegexModule;
        let packet = PacketBuilder::new()
            .payload_str("GET /api/public HTTP/1.1")
            .build();

        let result = module.evaluate(&packet, &["secret".to_string()]).unwrap();
        assert_eq!(result, ModuleResult::Miss);
    }

    #[test]
    fn test_regex_module_complex_pattern() {
        let module = RegexModule;
        // Test base64-like pattern (31 chars followed by =)
        let packet = PacketBuilder::new()
            .payload_str("data: ABCDEFGHIJKLMNOPQRSTUVWXYZ12345= end")
            .build();

        let result = module
            .evaluate(&packet, &["[A-Z0-9]{31}=".to_string()])
            .unwrap();
        assert_eq!(result, ModuleResult::Match);
    }

    #[test]
    fn test_mirror_module() {
        let module = MirrorModule;
        let packet = PacketBuilder::new().build();

        let result = module
            .evaluate(&packet, &["10.0.0.2:9000".to_string()])
            .unwrap();
        assert_eq!(result, ModuleResult::Match);

        let targets = module.mirror_targets(&["10.0.0.2:9000".to_string(), "10.0.0.3:9000".to_string()]);
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn test_registry() {
        let registry = ModuleRegistry::new();

        assert!(registry.get("regex").is_some());
        assert!(registry.get("mirror").is_some());
        assert!(registry.get("custom").is_some());
        assert!(registry.get("nonexistent").is_none());
    }
}
