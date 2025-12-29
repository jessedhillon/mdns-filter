//! mdns-filter CLI entry point.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use mdns_filter::config::FilterConfig;
use mdns_filter::mdns::FilterAction;
use mdns_filter::repeater::{MdnsRepeater, RepeaterConfig};

/// mDNS repeater - repeats mDNS packets between network interfaces.
#[derive(Parser, Debug)]
#[command(name = mdns_filter::PACKAGE)]
#[command(version)]
#[command(about = "A filtering mDNS repeater")]
#[command(
    long_about = "Repeats mDNS packets between network interfaces, enabling mDNS discovery across network segments."
)]
#[command(after_help = r#"EXAMPLES:
  # Basic usage - repeat between two interfaces
  mdns-filter eth0 wlan0

  # Dry run - see what would be forwarded without actually doing it
  mdns-filter --dry-run eth0 wlan0 \
    --filter-allow 'instance:Google-Cast-*' \
    --default-deny

  # Allow only Google Cast groups, deny everything else
  mdns-filter eth0 wlan0 \
    --filter-allow 'instance:Google-Cast-*' \
    --default-deny

  # Deny specific devices
  mdns-filter eth0 wlan0 \
    --filter-deny 'instance:WiiM-*'

  # Use a YAML config file for complex rules
  mdns-filter eth0 wlan0 --filter-config /etc/mdns-filter/filters.yaml
"#)]
struct Args {
    /// Network interfaces to bridge (minimum 2 required).
    #[arg(required = true, num_args = 2..)]
    interfaces: Vec<String>,

    /// Don't actually forward packets, just log what would happen.
    #[arg(short = 'n', long)]
    dry_run: bool,

    /// Path to YAML filter configuration file.
    #[arg(short = 'c', long = "filter-config")]
    filter_config: Option<PathBuf>,

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

fn setup_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .init();
}

fn build_filter_config(args: &Args) -> Result<FilterConfig> {
    if let Some(ref config_path) = args.filter_config {
        // Load from file
        if !args.filter_allow.is_empty() || !args.filter_deny.is_empty() {
            anyhow::bail!("Cannot use --filter-config with --filter-allow or --filter-deny");
        }
        FilterConfig::from_yaml_file(config_path).with_context(|| {
            format!(
                "Failed to load filter config from {}",
                config_path.display()
            )
        })
    } else if !args.filter_allow.is_empty() || !args.filter_deny.is_empty() {
        // Build from CLI patterns
        FilterConfig::from_cli_patterns(&args.filter_allow, &args.filter_deny, args.default_deny)
            .context("Failed to parse filter patterns")
    } else {
        // No content filtering
        Ok(FilterConfig {
            default_action: if args.default_deny {
                FilterAction::Deny
            } else {
                FilterAction::Allow
            },
            rules: Vec::new(),
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    setup_logging();

    // Build filter configuration
    let filter_config = build_filter_config(&args)?;

    // Build repeater configuration
    let config = RepeaterConfig {
        interfaces: args.interfaces,
        dry_run: args.dry_run,
        filter_config,
    };

    // Run the repeater
    let repeater = MdnsRepeater::new(config);
    let exit_code = repeater.run().await?;

    std::process::exit(exit_code);
}
