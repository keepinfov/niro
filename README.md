# niro

**Network Interface Rules Orchestrator** - A lightweight, fast, and safe Rust CLI for managing network rules and filtering packets.

## Features

- **Rule-based filtering**: Accept, drop, redirect, or mirror packets based on configurable rules
- **Content filtering**: Filter packets by payload content using regex patterns
- **Traffic mirroring**: Duplicate traffic to multiple destinations for logging/analysis
- **Packet redirection**: Route packets to different targets
- **Rule sets**: Organize rules into named sets for switching policies
- **TOML configuration**: Human-readable configuration format
- **Simulation mode**: Test and explain packet evaluation without actual interception

## Installation

```bash
cargo build --release
```

The binary will be available at `target/release/niro`.

## Quick Start

### 1. Create a configuration file

```toml
# config.toml
default_policy = "accept"

[[set]]
name = "default"
rules = ["allow-http", "block-suspicious"]

[[rule]]
name = "allow-http"
direction = "in"
protocol = "tcp"
local_port = "80"
action = "accept"

[[rule]]
name = "block-suspicious"
direction = "in"
action = "continue"
filters = ["malicious-check"]

[[filter]]
name = "malicious-check"
module = "regex"
setup = ["(?i)eval\\(", "<script>"]
on_match = "drop"
on_miss = "continue"
```

### 2. Validate the configuration

```bash
niro validate -c config.toml
```

### 3. Inspect configured entities

```bash
niro inspect -c config.toml
niro inspect -c config.toml --sets
niro inspect -c config.toml --name allow-http
```

### 4. Simulate packet evaluation

```bash
niro explain -c config.toml -s default \
  --direction in \
  --protocol tcp \
  --local-addr 192.168.1.1 \
  --local-port 80 \
  --remote-addr 10.0.0.1 \
  --remote-port 12345 \
  --payload "GET / HTTP/1.1" \
  --verbose
```

## CLI Commands

### `validate`
Validate configuration file(s) and report any errors.

```bash
niro validate -c config.toml
niro validate -c base.toml -c overrides.toml --format json
```

### `inspect`
Inspect configured sets, rules, and filters.

```bash
niro inspect -c config.toml              # Show all
niro inspect -c config.toml --sets       # Show only sets
niro inspect -c config.toml --rules      # Show only rules
niro inspect -c config.toml --filters    # Show only filters
niro inspect -c config.toml --name foo   # Show specific item
```

### `explain`
Simulate and explain packet evaluation.

```bash
niro explain -c config.toml -s default \
  --direction in \
  --protocol tcp \
  --local-addr 192.168.1.1 \
  --local-port 80 \
  --remote-addr 10.0.0.1 \
  --remote-port 12345 \
  --payload "test data" \
  --verbose
```

### `run`
Run the packet evaluation engine (simulation mode).

```bash
niro run -c config.toml -s default --dry-run
```

## Configuration Reference

### Sets

```toml
[[set]]
name = "production"
rules = ["rule1", "rule2", "rule3"]
```

### Rules

```toml
[[rule]]
name = "example-rule"
direction = "in"       # in | out | any (default: any)
protocol = "tcp"       # tcp | udp | any (default: any)
local_addr = "*"       # * | A.B.C.D | A.B.C.D/NN (default: *)
remote_addr = "*"      # same as local_addr
local_port = "80"      # * | 80 | 6* | *9 (default: *)
remote_port = "*"      # same as local_port
action = "accept"      # accept | drop | redirect | mirror | continue (default: continue)
redirect_to = "127.0.0.1:8080"  # Required when redirect is possible
filters = ["filter1", "filter2"]
```

#### Port Patterns

- `"*"` - any port
- `"80"` - exact port 80
- `"6*"` - ports starting with 6 (6, 60-69, 600-699, 6000-6999)
- `"*9"` - ports ending with 9 (9, 19, 29, ..., 65529)

### Filters

```toml
[[filter]]
name = "content-filter"
module = "regex"
setup = ["pattern1", "pattern2"]
on_match = "drop"      # accept | drop | redirect | mirror | continue | log
on_miss = "continue"   # same options (default: continue)
```

### Modules

#### `regex`
Content matching using regular expressions.

```toml
[[filter]]
name = "flag-detector"
module = "regex"
setup = ["FLAG\\{[^}]+\\}", "[A-Z0-9]{31}="]
on_match = "drop"
```

#### `mirror`
Traffic mirroring to multiple destinations.

```toml
[[filter]]
name = "traffic-logger"
module = "mirror"
setup = ["10.0.0.2:9000", "10.0.0.3:9000"]
on_match = "mirror"
```

#### `custom`
Placeholder for user-defined logic (extensible).

## Evaluation Semantics

1. For each packet, iterate through active sets in order
2. For each set, evaluate rules in the configured order
3. If a rule matches (all conditions satisfied):
   - Process filters in order
   - If a filter provides a final action (accept/drop/redirect/mirror), stop
   - Otherwise, apply the rule's base action
4. If no rule provides a final decision, apply the default policy

## Examples

See the `examples/` directory for sample configurations:

- `basic.toml` - Simple HTTP/HTTPS allow rules with malicious content blocking
- `advanced.toml` - CTF/competition setup with mirroring, honeypots, and injection detection

## Library Usage

niro can also be used as a Rust library:

```rust
use niro::{Config, Engine, Packet};
use niro::config::{Direction, Protocol};
use niro::matcher::packet::PacketBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_file("config.toml")?;
    let engine = Engine::new(config);

    let packet = PacketBuilder::new()
        .direction(Direction::In)
        .protocol(Protocol::Tcp)
        .local_addr_str("192.168.1.1")?
        .local_port(80)
        .payload_str("GET / HTTP/1.1")
        .build();

    let result = engine.evaluate(&packet, &["default".to_string()]);
    println!("Decision: {}", result.decision);

    Ok(())
}
```

## License

MIT
