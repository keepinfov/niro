//! niro - Network Interface Rules Orchestrator
//!
//! Lightweight CLI for managing network rules and filtering packets.

use clap::{Parser, Subcommand};
use niro::config::{Config, ConfigError};
use niro::engine::Engine;
use niro::matcher::packet::PacketBuilder;
use std::path::PathBuf;
use std::process::ExitCode;

/// Network Interface Rules Orchestrator
#[derive(Parser)]
#[command(name = "niro")]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate configuration file(s)
    Validate {
        /// Configuration file(s) to validate
        #[arg(short, long, required = true)]
        config: Vec<PathBuf>,

        /// Output format (text, json)
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Inspect configured sets, rules, and filters
    Inspect {
        /// Configuration file(s) to inspect
        #[arg(short, long, required = true)]
        config: Vec<PathBuf>,

        /// Show only sets
        #[arg(long)]
        sets: bool,

        /// Show only rules
        #[arg(long)]
        rules: bool,

        /// Show only filters
        #[arg(long)]
        filters: bool,

        /// Show specific item by name
        #[arg(short, long)]
        name: Option<String>,
    },

    /// Explain/simulate packet evaluation
    Explain {
        /// Configuration file(s)
        #[arg(short, long, required = true)]
        config: Vec<PathBuf>,

        /// Active set(s) to evaluate
        #[arg(short, long, required = true)]
        set: Vec<String>,

        /// Packet direction (in, out, any)
        #[arg(long, default_value = "any")]
        direction: String,

        /// Protocol (tcp, udp, any)
        #[arg(long, default_value = "any")]
        protocol: String,

        /// Local IP address
        #[arg(long, default_value = "0.0.0.0")]
        local_addr: String,

        /// Remote IP address
        #[arg(long, default_value = "0.0.0.0")]
        remote_addr: String,

        /// Local port
        #[arg(long, default_value = "0")]
        local_port: u16,

        /// Remote port
        #[arg(long, default_value = "0")]
        remote_port: u16,

        /// Packet payload (as string)
        #[arg(long)]
        payload: Option<String>,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Run packet evaluation (simulation mode)
    Run {
        /// Configuration file(s)
        #[arg(short, long, required = true)]
        config: Vec<PathBuf>,

        /// Active set(s) to use
        #[arg(short, long, required = true)]
        set: Vec<String>,

        /// Default policy if no rule matches (accept, drop)
        #[arg(long, default_value = "accept")]
        default_policy: String,

        /// Dry run - don't actually process, just show what would happen
        #[arg(long)]
        dry_run: bool,
    },

    /// Show version and build information
    Version,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Validate { config, format } => cmd_validate(&config, &format),
        Commands::Inspect {
            config,
            sets,
            rules,
            filters,
            name,
        } => cmd_inspect(&config, sets, rules, filters, name.as_deref()),
        Commands::Explain {
            config,
            set,
            direction,
            protocol,
            local_addr,
            remote_addr,
            local_port,
            remote_port,
            payload,
            verbose,
        } => cmd_explain(
            &config,
            &set,
            &direction,
            &protocol,
            &local_addr,
            &remote_addr,
            local_port,
            remote_port,
            payload.as_deref(),
            verbose,
        ),
        Commands::Run {
            config,
            set,
            default_policy,
            dry_run,
        } => cmd_run(&config, &set, &default_policy, dry_run),
        Commands::Version => cmd_version(),
    }
}

fn cmd_validate(config_paths: &[PathBuf], format: &str) -> ExitCode {
    match load_config(config_paths) {
        Ok(config) => {
            let stats = ConfigStats::from(&config);
            match format {
                "json" => {
                    println!(
                        r#"{{"valid":true,"sets":{},"rules":{},"filters":{}}}"#,
                        stats.sets, stats.rules, stats.filters
                    );
                }
                _ => {
                    println!("Configuration is valid");
                    println!("  Sets:    {}", stats.sets);
                    println!("  Rules:   {}", stats.rules);
                    println!("  Filters: {}", stats.filters);
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            match format {
                "json" => {
                    println!(r#"{{"valid":false,"error":"{}"}}"#, escape_json(&e.to_string()));
                }
                _ => {
                    eprintln!("Validation failed: {}", e);
                }
            }
            ExitCode::FAILURE
        }
    }
}

fn cmd_inspect(
    config_paths: &[PathBuf],
    show_sets: bool,
    show_rules: bool,
    show_filters: bool,
    name: Option<&str>,
) -> ExitCode {
    let config = match load_config(config_paths) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // If no specific category requested, show all
    let show_all = !show_sets && !show_rules && !show_filters;

    // If a specific name is requested, find it
    if let Some(name) = name {
        let mut found = false;

        if let Some(set) = config.get_set(name) {
            found = true;
            println!("Set: {}", set.name);
            println!("  Rules: {}", set.rules.join(", "));
        }

        if let Some(rule) = config.get_rule(name) {
            found = true;
            println!("Rule: {}", rule.name);
            println!("  Direction:   {}", rule.direction);
            println!("  Protocol:    {}", rule.protocol);
            println!("  Local addr:  {}", rule.local_addr);
            println!("  Remote addr: {}", rule.remote_addr);
            println!("  Local port:  {}", rule.local_port);
            println!("  Remote port: {}", rule.remote_port);
            println!("  Action:      {}", rule.action);
            if let Some(ref target) = rule.redirect_to {
                println!("  Redirect to: {}", target);
            }
            if !rule.filters.is_empty() {
                println!("  Filters:     {}", rule.filters.join(", "));
            }
        }

        if let Some(filter) = config.get_filter(name) {
            found = true;
            println!("Filter: {}", filter.name);
            println!("  Module:   {}", filter.module);
            println!("  Setup:    {:?}", filter.setup);
            println!("  On match: {}", filter.on_match);
            println!("  On miss:  {}", filter.on_miss);
        }

        if !found {
            eprintln!("Not found: {}", name);
            return ExitCode::FAILURE;
        }

        return ExitCode::SUCCESS;
    }

    // Show categories
    if show_all || show_sets {
        println!("Sets:");
        if config.sets.is_empty() {
            println!("  (none)");
        }
        for set in &config.sets {
            println!("  {} -> [{}]", set.name, set.rules.join(", "));
        }
        println!();
    }

    if show_all || show_rules {
        println!("Rules:");
        if config.rules.is_empty() {
            println!("  (none)");
        }
        for rule in &config.rules {
            println!(
                "  {} ({} {} {}:{} -> {}:{}) -> {}",
                rule.name,
                rule.direction,
                rule.protocol,
                rule.local_addr,
                rule.local_port,
                rule.remote_addr,
                rule.remote_port,
                rule.action
            );
        }
        println!();
    }

    if show_all || show_filters {
        println!("Filters:");
        if config.filters.is_empty() {
            println!("  (none)");
        }
        for filter in &config.filters {
            println!(
                "  {} ({}) match:{} miss:{}",
                filter.name, filter.module, filter.on_match, filter.on_miss
            );
        }
    }

    ExitCode::SUCCESS
}

fn cmd_explain(
    config_paths: &[PathBuf],
    sets: &[String],
    direction: &str,
    protocol: &str,
    local_addr: &str,
    remote_addr: &str,
    local_port: u16,
    remote_port: u16,
    payload: Option<&str>,
    verbose: bool,
) -> ExitCode {
    let config = match load_config(config_paths) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // Build packet from CLI args
    let mut builder = PacketBuilder::new();

    builder = match builder.direction_str(direction) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Invalid direction: {}", e);
            return ExitCode::FAILURE;
        }
    };

    builder = match builder.protocol_str(protocol) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Invalid protocol: {}", e);
            return ExitCode::FAILURE;
        }
    };

    builder = match builder.local_addr_str(local_addr) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Invalid local address: {}", e);
            return ExitCode::FAILURE;
        }
    };

    builder = match builder.remote_addr_str(remote_addr) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Invalid remote address: {}", e);
            return ExitCode::FAILURE;
        }
    };

    builder = builder.local_port(local_port).remote_port(remote_port);

    if let Some(p) = payload {
        builder = builder.payload_str(p);
    }

    let packet = builder.build();
    let engine = Engine::new(config);
    let explanation = engine.explain(&packet, sets);

    if verbose {
        println!("{}", explanation.format());
    } else {
        println!("Packet: {}", explanation.packet_summary);
        println!("Decision: {}", explanation.final_decision);
    }

    ExitCode::SUCCESS
}

fn cmd_run(
    config_paths: &[PathBuf],
    sets: &[String],
    _default_policy: &str,
    dry_run: bool,
) -> ExitCode {
    let config = match load_config(config_paths) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let engine = Engine::new(config);

    if dry_run {
        println!("niro ready (dry run mode)");
        println!("Configuration loaded:");
        println!("  Sets:    {}", engine.config().sets.len());
        println!("  Rules:   {}", engine.config().rules.len());
        println!("  Filters: {}", engine.config().filters.len());
        println!("Active sets: {}", sets.join(", "));
        println!("\nPacket evaluation engine ready.");
        println!("In production mode, niro would intercept and process network traffic.");
        return ExitCode::SUCCESS;
    }

    // In a real implementation, this would:
    // 1. Set up packet capture/interception (e.g., using netfilter/nfqueue, eBPF, etc.)
    // 2. For each packet, call engine.evaluate()
    // 3. Apply the decision (accept, drop, redirect, mirror)
    //
    // For now, we just print a message indicating the engine is ready
    println!("niro v{}", env!("CARGO_PKG_VERSION"));
    println!("Configuration loaded successfully.");
    println!("Active sets: {}", sets.join(", "));
    println!();
    println!("Note: Actual packet interception requires platform-specific setup");
    println!("      (e.g., netfilter/nfqueue on Linux, divert sockets on BSD).");
    println!();
    println!("Use 'niro explain' to simulate packet evaluation.");

    ExitCode::SUCCESS
}

fn cmd_version() -> ExitCode {
    println!("niro {}", env!("CARGO_PKG_VERSION"));
    println!("Network Interface Rules Orchestrator");
    println!();
    println!("Built with Rust {}", rustc_version());
    ExitCode::SUCCESS
}

fn load_config(paths: &[PathBuf]) -> Result<Config, ConfigError> {
    if paths.len() == 1 {
        Config::from_file(&paths[0])
    } else {
        Config::from_files(paths)
    }
}

struct ConfigStats {
    sets: usize,
    rules: usize,
    filters: usize,
}

impl From<&Config> for ConfigStats {
    fn from(config: &Config) -> Self {
        Self {
            sets: config.sets.len(),
            rules: config.rules.len(),
            filters: config.filters.len(),
        }
    }
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn rustc_version() -> &'static str {
    // This is a placeholder - in a real build, you'd capture this at compile time
    "stable"
}

// Re-export packet builder for use in main
pub mod packet {
    pub use niro::matcher::packet::PacketBuilder;
}
