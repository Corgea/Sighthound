use anyhow::Result;
use clap::Parser;
use sighthound::scanner::core::{print_findings_csv, print_findings_json, print_findings_text};
use sighthound::{
    run_auto_detection_scan, run_explicit_scan, run_taint_analysis,
    run_taint_analysis_with_verbosity, Cli, CommonUtils,
};

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle version flag
    if cli.version {
        println!("sighthound {}", env!("CARGO_PKG_VERSION"));
        println!(
            "Built from commit: {}",
            option_env!("GIT_HASH").unwrap_or("unknown")
        );
        println!(
            "Build date: {}",
            option_env!("BUILD_DATE").unwrap_or("unknown")
        );
        return Ok(());
    }

    // Check if root_dir is provided (required for actual scanning)
    let root_dir = cli.root_dir.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Root directory is required for scanning. Use --help for usage information."
        )
    })?;

    // Initialize logger (respect RUST_LOG or --verbose flag)
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(if cli.verbose { "debug" } else { "info" }),
    )
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

    // Validate CLI parameters
    if cli.taint_analysis && cli.simple_analysis {
        return Err(anyhow::anyhow!("Cannot specify both --taint-analysis and --simple-analysis. Use one or neither (default: both modes)."));
    }

    // Resolve the actual embedded rules setting (use_file_rules overrides use_embedded_rules)
    let should_use_embedded = cli.use_embedded_rules && !cli.use_file_rules;

    // Validate CLI parameters using CommonUtils
    CommonUtils::validate_cli_params(&cli.language, &cli.rules_path, cli.use_embedded_rules, cli.use_file_rules)
        .map_err(|e| anyhow::anyhow!(
            "invalid parameter combination: {}\n\n\
            Valid usage:\n  \
            - Explicit mode with embedded rules (default): sighthound {} <language>\n  \
            - Explicit mode with file rules:               sighthound {} <language> <rules_path> --use-file-rules\n  \
            - Auto-detection mode (default):               sighthound {}\n  \
            - Auto-detection mode with file rules:         sighthound {} --use-file-rules\n  \
            - Custom rules directory:                      sighthound {} --rules-dir <dir> --use-file-rules",
            e, root_dir, root_dir, root_dir, root_dir, root_dir
        ))?;

    // Handle all vulnerability scanning modes with unified flow
    let findings = if cli.taint_analysis {
        // Only taint analysis
        run_taint_analysis(&cli, root_dir, show_progress)?
    } else if cli.simple_analysis {
        // Only simple analysis
        match (&cli.language, &cli.rules_path, should_use_embedded) {
            (Some(_), Some(_), false) => run_explicit_scan(&cli, root_dir, show_progress)?,
            (Some(_), None, true) => run_explicit_scan(&cli, root_dir, show_progress)?,
            (None, None, _) => run_auto_detection_scan(&cli, root_dir, show_progress)?,
            _ => unreachable!(), // Validation above ensures this won't happen
        }
    } else {
        // Default: Run both simple and taint analysis
        // Run simple analysis first
        let mut simple_findings = match (&cli.language, &cli.rules_path, should_use_embedded) {
            (Some(_), Some(_), false) => run_explicit_scan(&cli, root_dir, show_progress)?,
            (Some(_), None, true) => run_explicit_scan(&cli, root_dir, show_progress)?,
            (None, None, _) => run_auto_detection_scan(&cli, root_dir, show_progress)?,
            _ => unreachable!(), // Validation above ensures this won't happen
        };

        // Run taint analysis second (less verbose in combined mode)
        let mut taint_findings =
            run_taint_analysis_with_verbosity(&cli, root_dir, show_progress, false)?;

        // Combine findings
        simple_findings.append(&mut taint_findings);
        simple_findings
    };

    // Output results
    let duration = start_time.elapsed();

    match cli.output_format.as_str() {
        "json" => print_findings_json(&findings),
        "csv" => print_findings_csv(&findings),
        _ => print_findings_text(&findings, cli.verbose, cli.summary_only, duration),
    }

    Ok(())
}
