use anyhow::Result;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::cli::Cli;
use crate::rules::Rules;
use crate::scanner::core::ProgressManager;
use crate::scanner::core::ScanningLogic;
use crate::scanner::{Finding, VulnerabilityScanner};

/// Unified scan configuration and execution context
#[derive(Debug)]
struct ScanContext {
    single_threaded: bool,
    skip_minified: bool,
    discovery_time: std::time::Duration,
    total_files: usize,
    detected_languages: Vec<String>,
}

impl ScanContext {
    /// Initialize scan context with file discovery
    fn new(cli: &Cli, root_dir: &str, show_progress: bool) -> Result<Self> {
        let discovery_start = std::time::Instant::now();

        let parallel = !cli.single_threaded;
        let files_by_language =
            crate::scanner::utils::discover_files_by_language_with_progress_and_options(
                root_dir,
                parallel,
                show_progress,
                cli.include_test_fixtures,
            )?;
        let discovery_time = discovery_start.elapsed();

        if files_by_language.is_empty() {
            if show_progress {
                crate::ui::warn(&format!("no supported source files found in {}", root_dir));
            }
            return Err(anyhow::anyhow!("No supported files found"));
        }

        let detected_languages: Vec<String> = files_by_language.keys().cloned().collect();
        let total_files: usize = files_by_language.values().map(|files| files.len()).sum();

        Ok(Self {
            single_threaded: cli.single_threaded,
            skip_minified: cli.skip_minified.unwrap_or(true),
            discovery_time,
            total_files,
            detected_languages,
        })
    }

    /// Human-readable description of the threading mode, e.g. `parallel (8 threads)`.
    fn mode_display(&self, threads: Option<usize>) -> String {
        if self.single_threaded {
            "single-threaded".to_string()
        } else if let Some(threads) = threads {
            format!("parallel ({} threads)", threads)
        } else {
            "parallel".to_string()
        }
    }

    /// Create and configure progress manager
    fn create_progress_manager(&self) -> ProgressManager {
        ProgressManager::new(self.total_files)
    }

    /// Print throughput stats once a scan completes.
    fn print_performance_summary(&self, rule_count: usize, scan_duration: std::time::Duration) {
        crate::ui::note(&format!(
            "scanned {} files \u{b7} {} rules \u{b7} {} languages",
            self.total_files,
            rule_count,
            self.detected_languages.len()
        ));
        crate::ui::note(&format!(
            "discovery {:.2?} \u{b7} analysis {:.2?}",
            self.discovery_time,
            scan_duration.saturating_sub(self.discovery_time)
        ));
    }
}

/// Resolve whether to use embedded rules (use_file_rules overrides use_embedded_rules)
fn should_use_embedded_rules(cli: &Cli) -> bool {
    cli.use_embedded_rules && !cli.use_file_rules
}

/// Load rules based on CLI configuration
fn load_rules(cli: &Cli, context: &ScanContext) -> Result<Rules> {
    // If using embedded rules, load them directly
    if should_use_embedded_rules(cli) {
        return Rules::load_all_embedded_rules(
            &context.detected_languages,
            cli.code_type.as_deref(),
        );
    }

    match (&cli.language, &cli.rules_path) {
        (Some(_language), Some(rules_path)) => Rules::load_from_path(rules_path),
        (None, None) => {
            // Auto-detect and merge rules from all languages
            let mut all_rules = Vec::new();

            // Determine exclusion pattern type based on code_type
            let pattern_type = if cli.code_type.as_deref() == Some("backend") {
                "backend"
            } else {
                "frontend"
            };

            for language in &context.detected_languages {
                let base_rules_dir = cli.rules_dir.as_deref().unwrap_or("rules");
                let rules_dir = match language.as_str() {
                    "tsx" => format!("{}/javascript", base_rules_dir),
                    _ => format!("{}/{}", base_rules_dir, language),
                };
                if let Ok(rules) =
                    Rules::load_from_directory_with_exclusions(&rules_dir, pattern_type)
                {
                    all_rules.push(rules);
                }

                // Load additional backend rules for JavaScript/TypeScript if code_type is backend or both
                if matches!(language.as_str(), "javascript" | "tsx") {
                    if let Some(code_type) = &cli.code_type {
                        if code_type != "frontend" {
                            let base_rules_dir = cli.rules_dir.as_deref().unwrap_or("rules");
                            let backend_rules_file = format!(
                                "{}/backend_javascript/backend_security.ron",
                                base_rules_dir
                            );
                            if let Ok(backend_rules) = Rules::load_from_file(&backend_rules_file) {
                                all_rules.push(backend_rules);
                            }
                        }
                    }
                }
            }

            if all_rules.is_empty() {
                return Err(anyhow::anyhow!("No rules found for detected languages"));
            }

            Rules::merge_rules(all_rules)
        }
        _ => Err(anyhow::anyhow!("Invalid CLI configuration")),
    }
}

/// Run explicit scan mode (language and rules specified)
pub fn run_explicit_scan(cli: &Cli, root_dir: &str, show_progress: bool) -> Result<Vec<Finding>> {
    let language = cli
        .language
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Language required for explicit scan"))?;

    let mut all_rules = if should_use_embedded_rules(cli) {
        vec![Rules::load_embedded_rules(
            language,
            cli.code_type.as_deref(),
        )?]
    } else {
        let rules_path = cli.rules_path.as_ref().ok_or_else(|| {
            anyhow::anyhow!("Rules path required for explicit scan when not using embedded rules")
        })?;
        vec![Rules::load_from_path(rules_path)?]
    };

    // Load additional backend rules for JavaScript/TypeScript if code_type is backend or both
    // (Note: For embedded rules, backend rules are already loaded in load_embedded_rules)
    if !should_use_embedded_rules(cli) && matches!(language.as_str(), "javascript" | "tsx") {
        if let Some(code_type) = &cli.code_type {
            if code_type != "frontend" {
                let base_rules_dir = cli.rules_dir.as_deref().unwrap_or("rules");
                let backend_rules_file =
                    format!("{}/backend_javascript/backend_security.ron", base_rules_dir);
                if let Ok(backend_rules) = Rules::load_from_file(&backend_rules_file) {
                    all_rules.push(backend_rules);
                }
            }
        }
    }

    let rules = if all_rules.len() == 1 {
        all_rules.into_iter().next().unwrap()
    } else {
        Rules::merge_rules(all_rules)?
    };
    let total_rules = ScanningLogic::count_total_rules(&rules);
    // Configure minified file skipping
    let skip_minified = cli.skip_minified.unwrap_or(true);
    let scanner = VulnerabilityScanner::with_skip_minified(language, rules, skip_minified)?;

    if show_progress {
        let mode = if cli.single_threaded {
            "single-threaded".to_string()
        } else if let Some(threads) = cli.threads {
            format!("parallel ({} threads)", threads)
        } else {
            "parallel".to_string()
        };

        let rules_source = if should_use_embedded_rules(cli) {
            "embedded".to_string()
        } else if let Some(rules_path) = &cli.rules_path {
            rules_path.clone()
        } else {
            "embedded".to_string()
        };

        crate::ui::banner(root_dir);
        crate::ui::field("language", language);
        crate::ui::field("rules", &format!("{} ({})", total_rules, rules_source));
        crate::ui::field("mode", &mode);
        if !skip_minified {
            crate::ui::warn(
                "minified-file skipping disabled; this may slow scans and add false positives",
            );
        }
        println!();
    }

    // Use the new filtering method if filters are specified
    if cli.code_type.is_some() || cli.language_filter.is_some() {
        scanner.find_vulnerabilities_unified_with_filters_and_options(
            root_dir,
            language,
            show_progress,
            cli.code_type.as_deref(),
            cli.language_filter.as_deref(),
            cli.include_test_fixtures,
        )
    } else {
        scanner.find_vulnerabilities_parallel_with_options(
            root_dir,
            language,
            show_progress,
            cli.include_test_fixtures,
        )
    }
}

/// Run auto-detection scan mode (automatically detect languages and load rules)
pub fn run_auto_detection_scan(
    cli: &Cli,
    root_dir: &str,
    show_progress: bool,
) -> Result<Vec<Finding>> {
    let scan_start = std::time::Instant::now();

    // Initialize unified scan context
    let context = ScanContext::new(cli, root_dir, show_progress)?;

    if show_progress {
        crate::ui::banner(root_dir);
        crate::ui::field(
            "languages",
            &format!(
                "{}  {}",
                context.detected_languages.join(", "),
                crate::ui::dim(&format!("(detected in {:.2?})", context.discovery_time))
            ),
        );
        crate::ui::field("mode", &context.mode_display(cli.threads));
    }

    // Rediscover files by language for actual processing (context only used for validation)
    let files_by_language = if cli.single_threaded {
        crate::scanner::utils::discover_files_by_language_with_progress_and_options(
            root_dir,
            false,
            false,
            cli.include_test_fixtures,
        )?
    } else {
        crate::scanner::utils::discover_files_by_language_with_progress_and_options(
            root_dir,
            true,
            false,
            cli.include_test_fixtures,
        )?
    };

    let total_findings = Arc::new(AtomicUsize::new(0));
    let mut progress_manager = if !cli.single_threaded && show_progress {
        Some(context.create_progress_manager())
    } else {
        None
    };

    if show_progress {
        println!();
    }

    // Convert to Vec to own data
    let lang_jobs: Vec<(String, Vec<PathBuf>)> = files_by_language.into_iter().collect();
    let processed_files = Arc::new(AtomicUsize::new(0));

    // Start progress tracking
    if let Some(ref mut progress) = progress_manager {
        progress.start_tracking(Arc::clone(&processed_files), Arc::clone(&total_findings));
    }

    let total_rules_loaded = Arc::new(AtomicUsize::new(0));
    let mut all_findings = Vec::new();

    // Process languages sequentially to avoid nested parallelism deadlocks
    for (language, files) in lang_jobs {
        let base_rules_dir = cli.rules_dir.as_deref().unwrap_or("rules");
        let rules_dir = match language.as_str() {
            "tsx" => format!("{}/javascript", base_rules_dir),
            _ => format!("{}/{}", base_rules_dir, language),
        };

        // Load rules - either embedded or from files
        let mut all_rules = Vec::new();

        if should_use_embedded_rules(cli) {
            // Use embedded rules
            if let Ok(embedded_rules) =
                Rules::load_embedded_rules(&language, cli.code_type.as_deref())
            {
                all_rules.push(embedded_rules);
            }
        } else {
            // Load base rules for the language with centralized exclusions
            // Determine exclusion pattern type based on code_type
            let pattern_type = if cli.code_type.as_deref() == Some("backend") {
                "backend"
            } else {
                "frontend"
            };

            if let Ok(base_rules) =
                Rules::load_from_directory_with_exclusions(&rules_dir, pattern_type)
            {
                all_rules.push(base_rules);
            }

            // Load additional backend rules for JavaScript/TypeScript if code_type is backend or both
            if matches!(language.as_str(), "javascript" | "tsx") {
                if let Some(code_type) = &cli.code_type {
                    if code_type != "frontend" {
                        let backend_rules_dir =
                            format!("{}/backend_javascript/backend_security.ron", base_rules_dir);
                        if let Ok(backend_rules) = Rules::load_from_file(&backend_rules_dir) {
                            all_rules.push(backend_rules);
                        }
                    }
                }
            }
        }

        if all_rules.is_empty() {
            continue; // Skip if no rules found
        }

        let rules = if all_rules.len() == 1 {
            all_rules.into_iter().next().unwrap()
        } else {
            Rules::merge_rules(all_rules)?
        };

        {
            let rule_count = ScanningLogic::count_total_rules(&rules);
            total_rules_loaded.fetch_add(rule_count, Ordering::Relaxed);

            if let Some(ref progress) = progress_manager {
                progress.set_message(format!("scanning {}", language));
            }

            let scanner =
                VulnerabilityScanner::with_skip_minified(&language, rules, context.skip_minified)
                    .expect("scanner");

            let findings_result = if cli.code_type.is_some() || cli.language_filter.is_some() {
                scanner.find_vulnerabilities_unified_with_filters_and_options(
                    root_dir,
                    &language,
                    false, // Never show progress for individual languages in auto-detection
                    cli.code_type.as_deref(),
                    cli.language_filter.as_deref(),
                    cli.include_test_fixtures,
                )
            } else {
                scanner.find_vulnerabilities_parallel_with_options(
                    root_dir,
                    &language,
                    false,
                    cli.include_test_fixtures,
                )
            };

            match findings_result {
                Ok(fnds) => {
                    processed_files.fetch_add(files.len(), Ordering::Relaxed);
                    if !fnds.is_empty() {
                        total_findings.fetch_add(fnds.len(), Ordering::Relaxed);
                    }
                    all_findings.extend(fnds);
                }
                Err(e) => {
                    crate::ui::warn(&format!("failed to scan {}: {}", language, e));
                }
            }
        }
    }

    // Stop progress tracking
    if let Some(mut progress) = progress_manager {
        progress.stop();
    }

    // Use unified performance reporting
    let scan_duration = scan_start.elapsed();
    if show_progress {
        context
            .print_performance_summary(total_rules_loaded.load(Ordering::Relaxed), scan_duration);
    }

    Ok(all_findings)
}

/// Run taint analysis mode
pub fn run_taint_analysis(cli: &Cli, root_dir: &str, show_progress: bool) -> Result<Vec<Finding>> {
    run_taint_analysis_with_verbosity(cli, root_dir, show_progress, true)
}

/// Run taint analysis mode with verbosity control
pub fn run_taint_analysis_with_verbosity(
    cli: &Cli,
    root_dir: &str,
    show_progress: bool,
    verbose_mode: bool,
) -> Result<Vec<Finding>> {
    // When taint runs as the second pass of a combined scan (verbose_mode = false),
    // stay completely silent so we don't duplicate the banner, progress bar, or tallies.
    let report = show_progress && verbose_mode;
    let scan_start = std::time::Instant::now();

    // Initialize unified scan context (reuse existing infrastructure)
    let context = ScanContext::new(cli, root_dir, report)?;

    // Load rules using unified pattern (reuse existing infrastructure)
    let rules = load_rules(cli, &context)?;

    // Check if we have taint flow rules
    let taint_rules_count = rules.rules.iter().filter(|r| r.is_taint_rule()).count();

    if taint_rules_count == 0 {
        return Err(anyhow::anyhow!(
            "No taint flow rules found. Please ensure your rules contain rules with mode='taint'."
        ));
    }
    if show_progress && verbose_mode {
        crate::ui::banner(root_dir);
        crate::ui::field("mode", "taint analysis");
        crate::ui::field("rules", &format!("{} taint-flow rules", taint_rules_count));
        crate::ui::field("files", &context.total_files.to_string());
        println!();
    }
    // Use the unified VulnerabilityScanner infrastructure for massive speedup!
    // This reuses ALL existing optimizations: parallel processing, prefiltering,
    // memory mapping, thread-local parsers, progress tracking, etc.
    // Respect CLI language parameter for proper prefiltering (especially minified file skipping)
    let language = cli.language.as_deref().unwrap_or("");
    let scanner = VulnerabilityScanner::with_skip_minified(language, rules, context.skip_minified)?;

    // When taint runs as the silent second pass of a combined scan, the unified
    // scanner shows no bar of its own (report = false), so drive a spinner here to
    // keep the terminal alive during what is often the slowest phase.
    let mut spinner = if show_progress && !verbose_mode {
        Some(ProgressManager::new_spinner("analyzing data flows"))
    } else {
        None
    };

    let all_findings = if cli.code_type.is_some() || cli.language_filter.is_some() {
        scanner.find_vulnerabilities_unified_with_filters_and_options(
            root_dir,
            language,
            report,
            cli.code_type.as_deref(),
            cli.language_filter.as_deref(),
            cli.include_test_fixtures,
        )?
    } else {
        scanner.find_vulnerabilities_unified_with_filters_and_options(
            root_dir,
            language,
            report,
            None,
            None,
            cli.include_test_fixtures,
        )?
    };

    if let Some(mut spinner) = spinner.take() {
        spinner.stop();
    }

    // Filter to only taint analysis findings
    let taint_findings: Vec<Finding> = all_findings
        .into_iter()
        .filter(|f| {
            f.tags
                .as_ref()
                .is_some_and(|tags| tags.contains(&"taint_analysis".to_string()))
        })
        .collect();

    let scan_duration = scan_start.elapsed();

    if show_progress && verbose_mode {
        // Use unified performance reporting (reuse existing infrastructure)
        context.print_performance_summary(taint_rules_count, scan_duration);

        if !taint_findings.is_empty() {
            let same_file_count = taint_findings
                .iter()
                .filter(|f| {
                    f.tags
                        .as_ref()
                        .is_some_and(|tags| tags.contains(&"same_file".to_string()))
                })
                .count();
            let cross_file_count = taint_findings.len() - same_file_count;

            crate::ui::note(&format!(
                "{} taint flows ({} same-file, {} cross-file)",
                taint_findings.len(),
                same_file_count,
                cross_file_count
            ));
        }
    }

    Ok(taint_findings)
}
