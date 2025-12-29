//! mdns-filter CLI entry point.

use clap::Parser;

/// mDNS repeater - repeats mDNS packets between network interfaces.
#[derive(Parser, Debug)]
#[command(name = mdns_filter::PACKAGE)]
#[command(version)]
#[command(about = "A filtering mDNS repeater")]
#[command(
    long_about = "Repeats mDNS packets between network interfaces, enabling mDNS discovery across network segments."
)]
struct Args {
    /// Network interfaces to bridge (minimum 2 required).
    #[arg(required = true, num_args = 2..)]
    interfaces: Vec<String>,

    /// Don't actually forward packets, just log what would happen.
    #[arg(short = 'n', long)]
    dry_run: bool,

    /// Path to YAML filter configuration file.
    #[arg(short = 'c', long = "filter-config")]
    filter_config: Option<std::path::PathBuf>,

    /// Allow pattern (e.g., 'instance:Google-Cast-*,service:_googlecast._tcp').
    #[arg(long = "filter-allow")]
    filter_allow: Vec<String>,

    /// Deny pattern (e.g., 'instance:WiiM-*').
    #[arg(long = "filter-deny")]
    filter_deny: Vec<String>,

    /// Deny packets that don't match any filter rule (default: allow).
    #[arg(long)]
    default_deny: bool,
}

fn main() {
    let args = Args::parse();

    // TODO: Phase 6 - implement actual repeater logic
    println!("mdns-filter starting...");
    println!("Interfaces: {:?}", args.interfaces);
    println!("Dry run: {}", args.dry_run);
    println!("Default deny: {}", args.default_deny);

    if let Some(config_path) = &args.filter_config {
        println!("Filter config: {}", config_path.display());
    }

    if !args.filter_allow.is_empty() {
        println!("Allow patterns: {:?}", args.filter_allow);
    }

    if !args.filter_deny.is_empty() {
        println!("Deny patterns: {:?}", args.filter_deny);
    }
}
