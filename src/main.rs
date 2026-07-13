use anyhow::Result;
use clap::{CommandFactory, Parser};
use sighthound::scanner::core::{
    print_findings_csv, print_findings_json, print_findings_sarif, print_findings_text,
};
use sighthound::{
    Cli, CommonUtils, run_auto_detection_scan, run_explicit_scan, run_taint_analysis,
    run_taint_analysis_with_verbosity,
};

fn print_version_info() {
    println!("sighthound {}", env!("CARGO_PKG_VERSION"));
    println!("Built from commit: {}", option_env!("GIT_HASH").unwrap_or("unknown"));
    println!("Build date: {}", option_env!("BUILD_DATE").unwrap_or("unknown"));
}

/// Resolve the scan target, or print help and return `None` when invoked without one.
fn resolve_root_dir(cli: &Cli) -> Result<Option<&String>> {
    match cli.root_dir.as_ref() {
        Some(root_dir) => Ok(Some(root_dir)),
        None => {
            Cli::command().print_help()?;
            println!();
            Ok(None)
        }
    }
}

fn init_logging(cli: &Cli) {
    // Initialize logger (respect RUST_LOG or --verbose flag)
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(if cli.verbose {
        "debug"
    } else {
        "info"
    }))
    .init();
}

fn configure_thread_pool(cli: &Cli) -> Result<()> {
    if let Some(threads) = cli.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .map_err(|e| anyhow::anyhow!("Failed to set thread pool size: {}", e))?;
    }
    Ok(())
}

fn validate_scan_flags(cli: &Cli) -> Result<()> {
    if cli.taint_analysis && cli.simple_analysis {
        return Err(anyhow::anyhow!(
            "Cannot specify both --taint-analysis and --simple-analysis. Use one or neither (default: both modes)."
        ));
    }
    Ok(())
}

fn validate_cli_params(cli: &Cli, root_dir: &str) -> Result<()> {
    CommonUtils::validate_cli_params(
        &cli.language,
        &cli.rules_path,
        cli.use_embedded_rules,
        cli.use_file_rules,
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "invalid parameter combination: {}\n\n\
            Valid usage:\n  \
            - Explicit mode with embedded rules (default): sighthound {} <language>\n  \
            - Explicit mode with file rules:               sighthound {} <language> <rules_path> --use-file-rules\n  \
            - Auto-detection mode (default):               sighthound {}\n  \
            - Auto-detection mode with file rules:         sighthound {} --use-file-rules\n  \
            - Custom rules directory:                      sighthound {} --rules-dir <dir> --use-file-rules",
            e, root_dir, root_dir, root_dir, root_dir, root_dir
        )
    })
}

/// Run "simple" (non-taint) analysis using explicit or auto-detected language/rules.
fn run_simple_analysis(
    cli: &Cli,
    root_dir: &str,
    show_progress: bool,
    should_use_embedded: bool,
) -> Result<Vec<sighthound::Finding>> {
    match (&cli.language, &cli.rules_path, should_use_embedded) {
        (Some(_), Some(_), false) => run_explicit_scan(cli, root_dir, show_progress),
        (Some(_), None, true) => run_explicit_scan(cli, root_dir, show_progress),
        (None, None, _) => run_auto_detection_scan(cli, root_dir, show_progress),
        _ => unreachable!(), // Validation above ensures this won't happen
    }
}

/// Dispatch to the requested scan mode(s): taint-only, simple-only, or both (default).
fn run_selected_analysis(
    cli: &Cli,
    root_dir: &str,
    show_progress: bool,
    should_use_embedded: bool,
) -> Result<Vec<sighthound::Finding>> {
    if cli.taint_analysis {
        // Only taint analysis
        return run_taint_analysis(cli, root_dir, show_progress);
    }
    if cli.simple_analysis {
        // Only simple analysis
        return run_simple_analysis(cli, root_dir, show_progress, should_use_embedded);
    }

    // Default: Run both simple and taint analysis
    // Run simple analysis first
    let mut simple_findings =
        run_simple_analysis(cli, root_dir, show_progress, should_use_embedded)?;

    // Run taint analysis second (less verbose in combined mode)
    let mut taint_findings =
        run_taint_analysis_with_verbosity(cli, root_dir, show_progress, false)?;

    // Combine findings
    simple_findings.append(&mut taint_findings);
    Ok(simple_findings)
}

fn output_findings(
    cli: &Cli,
    findings: &[sighthound::Finding],
    duration: std::time::Duration,
) -> Result<()> {
    match cli.output_format.as_str() {
        "json" => print_findings_json(findings)?,
        "csv" => print_findings_csv(findings)?,
        "sarif" => print_findings_sarif(findings)?,
        _ => print_findings_text(findings, cli.verbose, cli.summary_only, duration),
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle version flag
    if cli.version {
        print_version_info();
        return Ok(());
    }

    // Show help when invoked without a scan target.
    let Some(root_dir) = resolve_root_dir(&cli)? else {
        return Ok(());
    };

    init_logging(&cli);
    // Configure threading if specified
    configure_thread_pool(&cli)?;

    let start_time = std::time::Instant::now();

    // Determine if we should show progress (suppress for structured output formats)
    let show_progress = !matches!(cli.output_format.as_str(), "json" | "csv" | "sarif");

    // Validate CLI parameters
    validate_scan_flags(&cli)?;

    // Resolve the actual embedded rules setting (use_file_rules overrides use_embedded_rules)
    let should_use_embedded = cli.use_embedded_rules && !cli.use_file_rules;

    // Validate CLI parameters using CommonUtils
    validate_cli_params(&cli, root_dir)?;

    // Handle all vulnerability scanning modes with unified flow
    let mut findings = run_selected_analysis(&cli, root_dir, show_progress, should_use_embedded)?;

    // Deduplicate findings across all analysis modes (keeps first occurrence order)
    deduplicate_findings(&mut findings);

    // Output results
    let duration = start_time.elapsed();
    output_findings(&cli, &findings, duration)?;

    Ok(())
}

fn deduplicate_findings(findings: &mut Vec<sighthound::Finding>) {
    let mut seen = std::collections::BTreeSet::new();
    findings.retain(|finding| {
        seen.insert((
            finding.file.clone(),
            finding.line,
            finding.end_line,
            finding.finding_type.clone(),
            finding.snippet.clone(),
            finding.severity.clone(),
            finding.description.clone(),
        ))
    });
}
