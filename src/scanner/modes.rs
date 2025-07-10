use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::path::PathBuf;

use crate::cli::Cli;
use crate::rules::Rules;
use crate::scanner::{VulnerabilityScanner, Finding};
use crate::scanner::core::ScanningLogic;
use crate::scanner::utils::{discover_files_by_language, discover_files_by_language_parallel, discover_files_by_language_sequential};
use crate::scanner::core::ProgressManager;

/// Unified scan configuration and execution context
#[derive(Debug)]
struct ScanContext {
    root_dir: String,
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
        if show_progress {
            if parallel {
                println!("🚀 Using parallel file discovery for maximum performance...");
            } else {
                println!("🔍 Using sequential file discovery...");
            }
        }
        
        let files_by_language = crate::scanner::utils::discover_files_by_language_with_progress(root_dir, parallel, show_progress)?;
        let discovery_time = discovery_start.elapsed();
        
        if files_by_language.is_empty() {
            if show_progress {
                println!("❌ No supported files found in {}", root_dir);
                println!("   Supported file types: .py, .java, .js, .tsx, .html");
            }
            return Err(anyhow::anyhow!("No supported files found"));
        }
        
        let detected_languages: Vec<String> = files_by_language.keys().cloned().collect();
        let total_files: usize = files_by_language.values().map(|files| files.len()).sum();
        
        if show_progress {
            println!("🔍 Detected languages: {} (in {:.2?})", 
                    detected_languages.join(", "), discovery_time);
        }
        
        Ok(Self {
            root_dir: root_dir.to_string(),
            single_threaded: cli.single_threaded,
            skip_minified: cli.skip_minified.unwrap_or(true),
            discovery_time,
            total_files,
            detected_languages,
        })
    }
    
    /// Get mode information string for display
    fn get_mode_info(&self, threads: Option<usize>) -> (String, String) {
        let mode = if self.single_threaded { "single-threaded" } else { "parallel" };
        let thread_info = if let Some(threads) = threads {
            format!(" with {} threads", threads)
        } else {
            String::new()
        };
        (mode.to_string(), thread_info)
    }
    
    /// Create and configure progress manager
    fn create_progress_manager(&self) -> ProgressManager {
        ProgressManager::new(self.total_files)
    }
    
    /// Print performance summary
    fn print_performance_summary(&self, rule_count: usize, scan_duration: std::time::Duration) {
        println!();
        println!("📊 Scanned {} files total with {} rules across {} languages", 
                self.total_files, rule_count, self.detected_languages.len());
        println!("⚡ File discovery: {:.2?} | Analysis: {:.2?}", 
                self.discovery_time, scan_duration.saturating_sub(self.discovery_time));
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
        return Rules::load_all_embedded_rules(&context.detected_languages, cli.code_type.as_deref());
    }
    
    match (&cli.language, &cli.rules_path) {
        (Some(_language), Some(rules_path)) => Rules::load_from_path(rules_path),
        (None, None) => {
            // Auto-detect and merge rules from all languages
            let mut all_rules = Vec::new();
            
            // Determine exclusion pattern type based on code_type
            let pattern_type = if let Some(code_type) = &cli.code_type {
                if code_type == "backend" {
                    "backend"
                } else if code_type == "frontend" {
                    "frontend"
                } else {
                    "frontend" // default for "both" or other values
                }
            } else {
                "frontend" // default when no code_type specified
            };
            
            for language in &context.detected_languages {
                let base_rules_dir = cli.rules_dir.as_deref().unwrap_or("rules");
                let rules_dir = match language.as_str() {
                    "tsx" => format!("{}/javascript", base_rules_dir),
                    _ => format!("{}/{}", base_rules_dir, language),
                };
                if let Ok(rules) = Rules::load_from_directory_with_exclusions(&rules_dir, pattern_type) {
                    all_rules.push(rules);
                }
                
                // Load additional backend rules for JavaScript/TypeScript if code_type is backend or both
                if matches!(language.as_str(), "javascript" | "tsx") {
                    if let Some(code_type) = &cli.code_type {
                        if code_type != "frontend" {
                            let base_rules_dir = cli.rules_dir.as_deref().unwrap_or("rules");
                            let backend_rules_file = format!("{}/backend_javascript/backend_security.ron", base_rules_dir);
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
    let language = cli.language.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Language required for explicit scan"))?;
    
    let mut all_rules = if should_use_embedded_rules(cli) {
        vec![Rules::load_embedded_rules(language, cli.code_type.as_deref())?]
    } else {
        let rules_path = cli.rules_path.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Rules path required for explicit scan when not using embedded rules"))?;
        vec![Rules::load_from_path(rules_path)?]
    };
    
    // Load additional backend rules for JavaScript/TypeScript if code_type is backend or both
    // (Note: For embedded rules, backend rules are already loaded in load_embedded_rules)
    if !should_use_embedded_rules(cli) && matches!(language.as_str(), "javascript" | "tsx") {
        if let Some(code_type) = &cli.code_type {
            if code_type != "frontend"{
                let base_rules_dir = cli.rules_dir.as_deref().unwrap_or("rules");
                let backend_rules_file = format!("{}/backend_javascript/backend_security.ron", base_rules_dir);
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
    if show_progress {
        println!("🔢 Total number of rules: {}", total_rules);
    }
    // Configure minified file skipping
    let skip_minified = cli.skip_minified.unwrap_or(true);
    let scanner = VulnerabilityScanner::with_skip_minified(
        language, 
        rules, 
        skip_minified
    )?;
    
    if !skip_minified && show_progress {
        println!("⚠️  Minified file skipping disabled - this may increase scan time and false positives");
    }

    if show_progress {
        // Use unified configuration for display
        let mode = if cli.single_threaded { "single-threaded" } else { "parallel" };
        let thread_info = if let Some(threads) = cli.threads {
            format!(" with {} threads", threads)
        } else {
            String::new()
        };
        
        println!("🚀 Starting Explicit Scan ({} mode{})!", mode, thread_info);
        println!("📂 Target directory: {}", root_dir);
        println!("🔧 Language: {}", language);
        
        if should_use_embedded_rules(cli) {
            println!("📋 Using embedded rules");
        } else if let Some(rules_path) = &cli.rules_path {
            let path = std::path::Path::new(rules_path);
            if path.is_dir() {
                println!("📋 Rules directory: {}", rules_path);
            } else {
                println!("📋 Rules file: {}", rules_path);
            }
        }
        
        println!("🔍 Running scan with {} rules", total_rules);
        println!();
    }

    // Use the new filtering method if filters are specified
    if cli.code_type.is_some() || cli.language_filter.is_some() {
        scanner.find_vulnerabilities_unified_with_filters(
            root_dir, 
            language, 
            show_progress,
            cli.code_type.as_deref(),
            cli.language_filter.as_deref()
        )
    } else {
        scanner.find_vulnerabilities_parallel(root_dir, language, show_progress)
    }
}

/// Run auto-detection scan mode (automatically detect languages and load rules)
pub fn run_auto_detection_scan(cli: &Cli, root_dir: &str, show_progress: bool) -> Result<Vec<Finding>> {
    let scan_start = std::time::Instant::now();
    
    // Initialize unified scan context
    let context = ScanContext::new(cli, root_dir, show_progress)?;
    let (mode, thread_info) = context.get_mode_info(cli.threads);
    
    if show_progress {
        println!("🚀 Starting Auto-Detection Scan ({} mode{})!", mode, thread_info);
        println!("📂 Target directory: {}", root_dir);
    }
    
    // Rediscover files by language for actual processing (context only used for validation)
    let files_by_language = if cli.single_threaded {
        crate::scanner::utils::discover_files_by_language_sequential_with_progress(root_dir, false)?
    } else {
        crate::scanner::utils::discover_files_by_language_parallel_with_progress(root_dir, false)?
    };
    
    let total_findings = Arc::new(AtomicUsize::new(0));
    let mut progress_manager = if !cli.single_threaded && show_progress {
        Some(context.create_progress_manager())
    } else { None };
    
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
            if let Ok(embedded_rules) = Rules::load_embedded_rules(&language, cli.code_type.as_deref()) {
                all_rules.push(embedded_rules);
            }
        } else {
            // Load base rules for the language with centralized exclusions
            // Determine exclusion pattern type based on code_type
            let pattern_type = if let Some(code_type) = &cli.code_type {
                if code_type == "backend" {
                    "backend"
                } else if code_type == "frontend" {
                    "frontend"
                } else {
                    "frontend" // default for "both" or other values
                }
            } else {
                "frontend" // default when no code_type specified
            };
            
            if let Ok(base_rules) = Rules::load_from_directory_with_exclusions(&rules_dir, pattern_type) {
                all_rules.push(base_rules);
            }
            
            // Load additional backend rules for JavaScript/TypeScript if code_type is backend or both
            if matches!(language.as_str(), "javascript" | "tsx") {
                if let Some(code_type) = &cli.code_type {
                    if code_type != "frontend" {
                        let backend_rules_dir = format!("{}/backend_javascript/backend_security.ron", base_rules_dir);
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
                    progress.set_message(format!("| scanning {} ({}/{} files)", language, files.len(), context.total_files));
                }
                
                let scanner = VulnerabilityScanner::with_skip_minified(
                    &language, 
                    rules, 
                    context.skip_minified
                ).expect("scanner");
                
                let findings_result = if cli.code_type.is_some() || cli.language_filter.is_some() {
                    scanner.find_vulnerabilities_unified_with_filters(
                        root_dir, 
                        &language, 
                        false, // Never show progress for individual languages in auto-detection
                        cli.code_type.as_deref(),
                        cli.language_filter.as_deref()
                    )
                } else {
                    scanner.find_vulnerabilities_parallel(root_dir, &language, false)
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
                        eprintln!("⚠️  Failed to scan {}: {}", language, e);
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
        context.print_performance_summary(total_rules_loaded.load(Ordering::Relaxed), scan_duration);
    }
    
    Ok(all_findings)
}

/// Run taint analysis mode
pub fn run_taint_analysis(cli: &Cli, root_dir: &str, show_progress: bool) -> Result<Vec<Finding>> {
    run_taint_analysis_with_verbosity(cli, root_dir, show_progress, true)
}

/// Run taint analysis mode with verbosity control
pub fn run_taint_analysis_with_verbosity(cli: &Cli, root_dir: &str, show_progress: bool, verbose_mode: bool) -> Result<Vec<Finding>> {
    if show_progress && verbose_mode {
        println!("🔍 Taint analysis enabled - tracking data flows from sources to sinks");
    }
    
    let scan_start = std::time::Instant::now();
    
    // Initialize unified scan context (reuse existing infrastructure)
    let context = ScanContext::new(cli, root_dir, show_progress)?;
    
    // Load rules using unified pattern (reuse existing infrastructure)
    let rules = load_rules(cli, &context)?;
    
    // Check if we have taint flow rules
    let taint_rules_count = rules.rules.iter().filter(|r| r.is_taint_rule()).count();
    
    if taint_rules_count == 0 {
        return Err(anyhow::anyhow!("No taint flow rules found. Please ensure your rules contain rules with mode='taint'."));
    }
    if show_progress && verbose_mode {
        println!("🔍 Starting Optimized Taint Analysis Mode");
        println!("📂 Target directory: {}", root_dir);
        println!("🔧 Loaded {} taint flow rules", taint_rules_count);
        println!("📁 Total files to analyze: {}", context.total_files);
        println!("⚡ Using parallel processing for maximum performance");
        println!();
    }
    // Use the unified VulnerabilityScanner infrastructure for massive speedup!
    // This reuses ALL existing optimizations: parallel processing, prefiltering, 
    // memory mapping, thread-local parsers, progress tracking, etc.
    // Respect CLI language parameter for proper prefiltering (especially minified file skipping)
    let language = cli.language.as_deref().unwrap_or("");
    let scanner = VulnerabilityScanner::with_skip_minified(
        language,
        rules, 
        context.skip_minified
    )?;
    
    let all_findings = if cli.code_type.is_some() || cli.language_filter.is_some() {
        scanner.find_vulnerabilities_unified_with_filters(
            root_dir, 
            language, 
            show_progress,
            cli.code_type.as_deref(),
            cli.language_filter.as_deref()
        )?
    } else {
        scanner.find_vulnerabilities_unified(root_dir, language, show_progress)?
    };
        
    // Filter to only taint analysis findings 
    let taint_findings: Vec<Finding> = all_findings.into_iter()
        .filter(|f| {
            f.tags.as_ref().map_or(false, |tags| 
                tags.contains(&"taint_analysis".to_string())
            )
        })
        .collect();
    
    let scan_duration = scan_start.elapsed();
    
    if show_progress && verbose_mode {
        // Use unified performance reporting (reuse existing infrastructure)
        context.print_performance_summary(taint_rules_count, scan_duration);
        println!("⏱️  Optimized taint analysis completed in {:.2?}", scan_duration);
        
        if !taint_findings.is_empty() {
            let same_file_count = taint_findings.iter()
                .filter(|f| f.tags.as_ref().map_or(false, |tags| tags.contains(&"same_file".to_string())))
                .count();
            let cross_file_count = taint_findings.len() - same_file_count;
            
            println!("🎯 Found {} taint flows ({} same-file, {} cross-file)", 
                    taint_findings.len(), same_file_count, cross_file_count);
        }
    }
    
    Ok(taint_findings)
}

 