//! Linux packet interception using netfilter queue (NFQUEUE).
//!
//! This module provides real packet interception on Linux using the
//! netfilter queue mechanism. Packets are sent to userspace via NFQUEUE,
//! where niro evaluates them and returns a verdict (accept/drop).
//!
//! ## Setup
//!
//! Before running niro, you must configure iptables to send packets to NFQUEUE:
//!
//! ```bash
//! # Intercept incoming TCP traffic on port 80
//! sudo iptables -I INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0
//!
//! # Intercept all incoming traffic
//! sudo iptables -I INPUT -j NFQUEUE --queue-num 0
//!
//! # Intercept outgoing traffic
//! sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0
//! ```
//!
//! To remove the rules:
//! ```bash
//! sudo iptables -D INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0
//! ```

use crate::config::{Config, Direction, Protocol};
use crate::engine::{Decision, Engine};
use crate::matcher::Packet;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Statistics for packet processing.
#[derive(Debug, Default)]
pub struct Stats {
    pub packets_processed: u64,
    pub packets_accepted: u64,
    pub packets_dropped: u64,
    pub packets_redirected: u64,
    pub packets_mirrored: u64,
    pub errors: u64,
}

/// Netfilter queue runner for packet interception.
pub struct NfqueueRunner {
    engine: Engine,
    active_sets: Vec<String>,
    queue_num: u16,
    verbose: bool,
}

impl NfqueueRunner {
    /// Create a new NFQUEUE runner.
    pub fn new(config: Config, active_sets: Vec<String>, queue_num: u16, verbose: bool) -> Self {
        Self {
            engine: Engine::new(config),
            active_sets,
            queue_num,
            verbose,
        }
    }

    /// Run the packet interception loop.
    pub fn run(&self) -> Result<Stats, NfqueueError> {
        use nfq::{Queue, Verdict};

        let mut stats = Stats::default();
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        // Set up Ctrl+C handler
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
            eprintln!("\nShutting down...");
        })
        .map_err(|e| NfqueueError::Setup(format!("Failed to set signal handler: {}", e)))?;

        // Open the netfilter queue
        let mut queue = Queue::open()
            .map_err(|e| NfqueueError::Setup(format!("Failed to open NFQUEUE: {}", e)))?;

        queue
            .bind(self.queue_num)
            .map_err(|e| NfqueueError::Setup(format!("Failed to bind to queue {}: {}", self.queue_num, e)))?;

        if self.verbose {
            eprintln!("niro: Listening on NFQUEUE {}", self.queue_num);
            eprintln!("niro: Active sets: {}", self.active_sets.join(", "));
            eprintln!("niro: Press Ctrl+C to stop\n");
        }

        // Main packet processing loop
        while running.load(Ordering::SeqCst) {
            let mut msg = match queue.recv() {
                Ok(msg) => msg,
                Err(e) => {
                    // Check if we're shutting down
                    if !running.load(Ordering::SeqCst) {
                        break;
                    }
                    stats.errors += 1;
                    if self.verbose {
                        eprintln!("niro: Error receiving packet: {}", e);
                    }
                    continue;
                }
            };

            stats.packets_processed += 1;
            let payload = msg.get_payload();

            // Parse the IP packet
            let packet = match parse_ip_packet(payload) {
                Some(p) => p,
                None => {
                    // Can't parse, accept by default
                    msg.set_verdict(Verdict::Accept);
                    queue.verdict(msg).ok();
                    stats.packets_accepted += 1;
                    continue;
                }
            };

            // Evaluate the packet
            let result = self.engine.evaluate(&packet, &self.active_sets);

            // Apply verdict
            let verdict = match &result.decision {
                Decision::Accept => {
                    stats.packets_accepted += 1;
                    if self.verbose {
                        eprintln!(
                            "ACCEPT: {} {} {}:{} -> {}:{}",
                            packet.direction,
                            packet.protocol,
                            packet.local_addr,
                            packet.local_port,
                            packet.remote_addr,
                            packet.remote_port
                        );
                    }
                    Verdict::Accept
                }
                Decision::Drop => {
                    stats.packets_dropped += 1;
                    if self.verbose {
                        eprintln!(
                            "DROP: {} {} {}:{} -> {}:{}",
                            packet.direction,
                            packet.protocol,
                            packet.local_addr,
                            packet.local_port,
                            packet.remote_addr,
                            packet.remote_port
                        );
                    }
                    Verdict::Drop
                }
                Decision::Redirect { target } => {
                    stats.packets_redirected += 1;
                    if self.verbose {
                        eprintln!(
                            "REDIRECT: {} {} {}:{} -> {}:{} => {}",
                            packet.direction,
                            packet.protocol,
                            packet.local_addr,
                            packet.local_port,
                            packet.remote_addr,
                            packet.remote_port,
                            target
                        );
                    }
                    // Note: Actual redirect requires NAT/DNAT rules
                    // For now, we accept and log the redirect intent
                    Verdict::Accept
                }
                Decision::Mirror { targets } => {
                    stats.packets_mirrored += 1;
                    if self.verbose {
                        eprintln!(
                            "MIRROR: {} {} {}:{} -> {}:{} => [{}]",
                            packet.direction,
                            packet.protocol,
                            packet.local_addr,
                            packet.local_port,
                            packet.remote_addr,
                            packet.remote_port,
                            targets.join(", ")
                        );
                    }
                    // Send copies to mirror targets
                    mirror_packet(payload, targets);
                    Verdict::Accept
                }
            };

            msg.set_verdict(verdict);
            if let Err(e) = queue.verdict(msg) {
                stats.errors += 1;
                if self.verbose {
                    eprintln!("niro: Error setting verdict: {}", e);
                }
            }
        }

        if self.verbose {
            eprintln!("\nniro: Stopped");
            eprintln!("Statistics:");
            eprintln!("  Processed: {}", stats.packets_processed);
            eprintln!("  Accepted:  {}", stats.packets_accepted);
            eprintln!("  Dropped:   {}", stats.packets_dropped);
            eprintln!("  Mirrored:  {}", stats.packets_mirrored);
            eprintln!("  Errors:    {}", stats.errors);
        }

        Ok(stats)
    }
}

/// Parse an IP packet from raw bytes into our Packet structure.
fn parse_ip_packet(data: &[u8]) -> Option<Packet> {
    if data.len() < 20 {
        return None; // Too short for IPv4 header
    }

    // Check IP version
    let version = (data[0] >> 4) & 0x0F;
    if version != 4 {
        return None; // Only IPv4 supported for now
    }

    let ihl = (data[0] & 0x0F) as usize * 4;
    if data.len() < ihl {
        return None;
    }

    let protocol_byte = data[9];
    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let (protocol, src_port, dst_port, payload_offset) = match protocol_byte {
        6 => {
            // TCP
            if data.len() < ihl + 20 {
                return None;
            }
            let src_port = u16::from_be_bytes([data[ihl], data[ihl + 1]]);
            let dst_port = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);
            let data_offset = ((data[ihl + 12] >> 4) as usize) * 4;
            (Protocol::Tcp, src_port, dst_port, ihl + data_offset)
        }
        17 => {
            // UDP
            if data.len() < ihl + 8 {
                return None;
            }
            let src_port = u16::from_be_bytes([data[ihl], data[ihl + 1]]);
            let dst_port = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);
            (Protocol::Udp, src_port, dst_port, ihl + 8)
        }
        _ => {
            // Other protocols - treat as any
            (Protocol::Any, 0, 0, ihl)
        }
    };

    // Extract payload
    let payload = if payload_offset < data.len() {
        data[payload_offset..].to_vec()
    } else {
        Vec::new()
    };

    // Determine direction based on packet flow
    // In NFQUEUE INPUT chain: dst_ip is local, src_ip is remote
    // In NFQUEUE OUTPUT chain: src_ip is local, dst_ip is remote
    // We default to "in" for INPUT chain behavior
    Some(Packet {
        direction: Direction::In,
        protocol,
        local_addr: dst_ip,
        remote_addr: src_ip,
        local_port: dst_port,
        remote_port: src_port,
        payload,
    })
}

/// Mirror a packet to the specified targets via UDP.
fn mirror_packet(data: &[u8], targets: &[String]) {
    for target in targets {
        if let Ok(addr) = target.parse::<SocketAddr>() {
            // Create a UDP socket to send the mirrored packet
            if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
                let _ = socket.send_to(data, addr);
            }
        } else if let Some((host, port)) = target.rsplit_once(':') {
            if let (Ok(ip), Ok(port)) = (host.parse::<Ipv4Addr>(), port.parse::<u16>()) {
                let addr = SocketAddr::from((ip, port));
                if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
                    let _ = socket.send_to(data, addr);
                }
            }
        }
    }
}

/// Errors that can occur during NFQUEUE operation.
#[derive(Debug, thiserror::Error)]
pub enum NfqueueError {
    #[error("setup error: {0}")]
    Setup(String),

    #[error("runtime error: {0}")]
    Runtime(String),
}
