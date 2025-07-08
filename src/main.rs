use anyhow::Result;
use env_logger;
use log::LevelFilter;
use clap::Parser;
use find_vulns::{Cli, CommonUtils, run_explicit_scan, run_auto_detection_scan, run_taint_analysis};
use find_vulns::scanner::core::{print_findings_json, print_findings_csv, print_findings_text, print_summary};

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logger (respect RUST_LOG or --verbose flag)
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(if cli.verbose { "debug" } else { "info" }))
        .init();
    // Configure threading if specified
    if let Some(threads) = cli.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .map_err(|e| anyhow::anyhow!("Failed to set thread pool size: {}", e))?;
    }

    let start_time = std::time::Instant::now();
    
    // Determine if we should show progress (suppress for structured output formats)
    let show_progress = !matches!(cli.output_format.as_str(), "json" | "csv");
    
    // Handle all vulnerability scanning modes with unified flow
    let findings = if cli.taint_analysis {
        run_taint_analysis(&cli, show_progress)?
    } else {
        // Resolve the actual embedded rules setting (use_file_rules overrides use_embedded_rules)
        let should_use_embedded = cli.use_embedded_rules && !cli.use_file_rules;
        
        // Validate CLI parameters using CommonUtils
        CommonUtils::validate_cli_params(&cli.language, &cli.rules_path, cli.use_embedded_rules, cli.use_file_rules)
            .map_err(|e| anyhow::anyhow!(
                "❌ Invalid parameter combination: {}\n\n\
                Valid usage:\n  \
                • Explicit mode with embedded rules (default): cargo run -- {} <language>\n  \
                • Explicit mode with file rules: cargo run -- {} <language> <rules_path> --use-file-rules\n  \
                • Auto-detection mode with embedded rules (default): cargo run -- {}\n  \
                • Auto-detection mode with file rules: cargo run -- {} --use-file-rules\n  \
                • Custom rules directory: cargo run -- {} --rules-dir <custom_rules_dir> --use-file-rules", 
                e, cli.root_dir, cli.root_dir, cli.root_dir, cli.root_dir, cli.root_dir
            ))?;

        match (&cli.language, &cli.rules_path, should_use_embedded) {
            (Some(_), Some(_), false) => run_explicit_scan(&cli, show_progress)?,
            (Some(_), None, true) => run_explicit_scan(&cli, show_progress)?,
            (None, None, _) => run_auto_detection_scan(&cli, show_progress)?,
            _ => unreachable!(), // Validation above ensures this won't happen
        }
    };

    // Output results
    let duration = start_time.elapsed();
    
    // Only show completion message for text output
    if show_progress {
        println!();
        println!("⏱️  Scan completed in {:.2?}", duration);
        println!();
    }

    match cli.output_format.as_str() {
        "json" => print_findings_json(&findings),
        "csv" => print_findings_csv(&findings),
        "text" | _ => print_findings_text(&findings, cli.verbose, cli.summary_only, duration),
    }

    Ok(())
} 