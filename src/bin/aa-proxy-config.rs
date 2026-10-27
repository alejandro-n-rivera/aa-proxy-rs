//! Small runtime configuration generator: no proxy runtime, web metadata or TLS setup.
use aa_proxy_rs::config::AppConfig;
use aa_proxy_rs::system_config;
use clap::{ArgGroup, Parser};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Debug, Parser)]
#[command(version, about = "Generate aa-proxy runtime configuration")]
#[command(group(ArgGroup::new("generation").required(true).multiple(true).args([
    "generate_system_config", "generate_boot_config", "generate_hostapd"
])))]
struct Args {
    /// Config file path (same parsing and defaults as aa-proxy-rs)
    #[arg(short, long, default_value = concat!(aa_proxy_rs::base_config_dir!(), "/config.toml"))]
    config: PathBuf,
    /// Generate system configuration and exit
    #[arg(short, long)]
    generate_system_config: bool,
    /// Generate system and hostapd configuration in one boot invocation
    #[arg(long)]
    generate_boot_config: bool,
    /// Generate hostapd configuration and exit
    #[arg(short = 'o', long)]
    generate_hostapd: bool,
}

fn generate(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    // Reuse the full parser, validation and lazy hardware defaults. A separate
    // narrowed DTO would silently accept malformed unrelated settings.
    let config = AppConfig::load(args.config.clone())?;
    let mode = if args.generate_system_config || args.generate_boot_config {
        system_config::generate_system_configs(&config, &args.config, args.generate_boot_config)?;
        if args.generate_boot_config {
            "boot"
        } else {
            "system"
        }
    } else {
        system_config::generate_hostapd_config(&config, &args.config)?;
        "hostapd"
    };
    eprintln!(
        "aa-proxy-config: generated {mode} configuration in {}ms",
        started.elapsed().as_millis()
    );
    Ok(())
}

fn main() {
    if let Err(error) = generate(Args::parse()) {
        eprintln!("aa-proxy-config: {error}");
        std::process::exit(1);
    }
}
