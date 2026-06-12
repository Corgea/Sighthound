//! Minimal example: scan a directory with embedded rules using the library API.
//!
//! Run with:
//!   cargo run --example basic_scan -- /path/to/project

use anyhow::Result;
use clap::Parser;
use sighthound::{run_auto_detection_scan, Cli};

fn main() -> Result<()> {
    let root_dir = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: basic_scan <directory>");
        std::process::exit(1);
    });

    let cli = Cli::parse_from(["sighthound", &root_dir]);
    let findings = run_auto_detection_scan(&cli, &root_dir, false)?;

    println!("Found {} potential issues", findings.len());
    for finding in &findings {
        println!(
            "  [{}] {}:{} — {}",
            finding.severity, finding.file, finding.line, finding.finding_type
        );
    }

    Ok(())
}
