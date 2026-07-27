use anyhow::Result;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
use syntect::easy::HighlightLines;
use syntect::highlighting::{Style, ThemeSet};
use syntect::parsing::SyntaxSet;

use crate::common::CommonUtils;
use crate::models::Finding;

pub fn print_summary(findings: &[Finding], duration: std::time::Duration) {
    crate::ui::section("Summary");

    if findings.is_empty() {
        crate::ui::note(&format!("no vulnerabilities found \u{b7} {:.2?}", duration));
        println!();
        return;
    }

    // Group findings by severity - use BTreeMap for deterministic iteration
    let mut severity_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut finding_types: BTreeMap<String, usize> = BTreeMap::new();
    let mut file_counts: BTreeMap<String, usize> = BTreeMap::new();

    for finding in findings {
        *severity_counts.entry(finding.severity.to_lowercase()).or_insert(0) += 1;
        *finding_types.entry(finding.finding_type.clone()).or_insert(0) += 1;
        *file_counts.entry(finding.file.clone()).or_insert(0) += 1;
    }

    // Severity breakdown, on a single line in fixed order
    let severity_order = ["critical", "high", "medium", "low"];
    let parts: Vec<String> = severity_order
        .iter()
        .filter_map(|sev| {
            severity_counts.get(*sev).map(|count| {
                let bullet = crate::ui::paint(crate::ui::severity_code(sev), "\u{25cf}");
                format!("{} {} {}", bullet, count, sev)
            })
        })
        .collect();
    if !parts.is_empty() {
        println!("  {}", parts.join("   "));
    }

    // Top finding types
    let mut sorted_types: Vec<_> = finding_types.iter().collect();
    sorted_types.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    println!();
    for (finding_type, count) in sorted_types.iter().take(8) {
        println!("  {:>4}  {}", count, finding_type);
    }

    // Most affected files
    let mut sorted_files: Vec<_> = file_counts.iter().collect();
    sorted_files.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    if sorted_files.len() > 1 {
        crate::ui::section("Most affected files");
        for (file_path, count) in sorted_files.iter().take(5) {
            println!("  {:>4}  {}", count, crate::ui::dim(file_path));
        }
    }

    println!();
    println!("  {} findings in {:.2?}", crate::ui::bold(&findings.len().to_string()), duration);
    println!();
}

/// Progress bar management for vulnerability scanning
pub struct ProgressManager {
    bar: ProgressBar,
    should_stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl ProgressManager {
    /// Spinner frames used for all progress indicators (Braille, not emoji).
    const TICK_CHARS: &'static str =
        "\u{280b}\u{2819}\u{2839}\u{2838}\u{283c}\u{2834}\u{2826}\u{2827}\u{2807}\u{280f} ";

    /// Create a determinate progress bar tracking `total` files.
    pub fn new(total: usize) -> Self {
        let bar = ProgressBar::new(total as u64);
        if let Ok(style) = ProgressStyle::with_template(
            "  {spinner:.cyan} [{elapsed_precise}] [{bar:30.cyan/blue}] {pos}/{len} files  {msg}",
        ) {
            bar.set_style(style.progress_chars("=> ").tick_chars(Self::TICK_CHARS));
        }
        bar.set_draw_target(ProgressDrawTarget::stderr());
        // Keep the spinner animating even while the file counter is unchanged,
        // so a long-running pass never looks frozen.
        bar.enable_steady_tick(Duration::from_millis(100));

        Self { bar, should_stop: Arc::new(AtomicBool::new(false)), handle: None }
    }

    /// Create an indeterminate spinner with a static `message`, for phases whose
    /// total work is unknown (e.g. data-flow analysis).
    pub fn new_spinner(message: &str) -> Self {
        let bar = ProgressBar::new_spinner();
        if let Ok(style) =
            ProgressStyle::with_template("  {spinner:.cyan} {msg} [{elapsed_precise}]")
        {
            bar.set_style(style.tick_chars(Self::TICK_CHARS));
        }
        bar.set_draw_target(ProgressDrawTarget::stderr());
        bar.set_message(message.to_string());
        bar.enable_steady_tick(Duration::from_millis(100));

        Self { bar, should_stop: Arc::new(AtomicBool::new(false)), handle: None }
    }

    /// Start tracking progress with counters
    pub fn start_tracking(&mut self, processed: Arc<AtomicUsize>, findings: Arc<AtomicUsize>) {
        let bar_clone = self.bar.clone();
        let stop_clone = Arc::clone(&self.should_stop);

        self.handle = Some(std::thread::spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                let val = processed.load(Ordering::Relaxed) as u64;
                bar_clone.set_position(val);
                let vulns = findings.load(Ordering::Relaxed);
                bar_clone.set_message(format!("{} findings", vulns));
                std::thread::sleep(Duration::from_millis(
                    crate::config::ScanDefaults::PROGRESS_INTERVAL_MS,
                ));
            }
        }));
    }

    /// Update progress bar message
    pub fn set_message(&self, message: String) {
        self.bar.set_message(message);
    }

    /// Stop progress tracking
    pub fn stop(&mut self) {
        self.should_stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.bar.finish_and_clear();
    }
}

/// Print findings in JSON format
pub fn print_findings_json(findings: &[Finding]) -> Result<()> {
    let json = serde_json::to_string_pretty(findings)?;
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    writeln!(out, "{}", json)?;
    out.flush()?;
    Ok(())
}

/// Map a finding severity to a SARIF result `level` and the GitHub-recognized
/// `security-severity` score. GitHub Code Scanning reads `security-severity`
/// (a CVSS-style number) to bucket alerts; `level` drives the icon/state.
fn sarif_severity(severity: &str) -> (&'static str, &'static str, u8) {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => ("error", "9.5", 4),
        "high" => ("error", "8.9", 3),
        "medium" => ("warning", "5.5", 2),
        "low" => ("note", "2.0", 1),
        _ => ("warning", "5.5", 2),
    }
}

fn sarif_uri(file: &str, repository_root: Option<&Path>) -> String {
    let path = Path::new(file);
    let relative_path =
        repository_root.and_then(|root| path.strip_prefix(root).ok()).unwrap_or(path);
    let relative_path = relative_path.strip_prefix(".").unwrap_or(relative_path);
    relative_path.to_string_lossy().replace('\\', "/")
}

/// Build a SARIF 2.1.0 log for GitHub Code Scanning and other SARIF consumers
/// (GitLab, Azure DevOps, the VS Code SARIF viewer).
///
/// Produces a single run with a deduplicated `rules` array (one reporting
/// descriptor per finding type / CWE) and one `results` entry per finding.
fn build_sarif_log(findings: &[Finding]) -> serde_json::Value {
    let repository_root = std::env::current_dir().ok();

    // Stable rule id: prefer the CWE id, fall back to a slug of the finding type.
    let rule_id_for = |f: &Finding| -> String {
        match &f.cwe_id {
            Some(cwe) if !cwe.is_empty() => cwe.to_ascii_lowercase(),
            _ => f
                .finding_type
                .to_ascii_lowercase()
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                .collect(),
        }
    };

    // Deduplicate rules by id, preserving first-seen order for deterministic output.
    let mut rule_index: BTreeMap<String, usize> = BTreeMap::new();
    let mut rules: Vec<serde_json::Value> = Vec::new();
    let mut rule_severity_ranks = Vec::new();
    for finding in findings {
        let id = rule_id_for(finding);
        let (_, security_severity, severity_rank) = sarif_severity(&finding.severity);
        if let Some(&index) = rule_index.get(&id) {
            if severity_rank > rule_severity_ranks[index] {
                rules[index]["properties"]["security-severity"] =
                    serde_json::json!(security_severity);
                rule_severity_ranks[index] = severity_rank;
            }
            continue;
        }
        rule_index.insert(id.clone(), rules.len());
        rule_severity_ranks.push(severity_rank);

        let mut tags = vec![serde_json::json!("security")];
        let mut rule = serde_json::json!({
            "id": id,
            "name": finding.finding_type,
            "shortDescription": { "text": finding.finding_type },
            "fullDescription": {
                "text": finding.description.clone().unwrap_or_else(|| finding.finding_type.clone())
            },
        });
        if let Some(cwe) = &finding.cwe_id {
            if !cwe.is_empty() {
                tags.push(serde_json::json!(format!("external/cwe/{}", id)));
                // cwe ids look like "cwe-78"; derive the numeric part for the help URI.
                if let Some(num) = cwe.rsplit('-').next() {
                    if num.chars().all(|c| c.is_ascii_digit()) && !num.is_empty() {
                        rule["helpUri"] = serde_json::json!(format!(
                            "https://cwe.mitre.org/data/definitions/{}.html",
                            num
                        ));
                    }
                }
            }
        }
        rule["properties"] = serde_json::json!({
            "tags": tags,
            "security-severity": security_severity,
        });
        rules.push(rule);
    }

    // One SARIF result per finding.
    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|finding| {
            let rule_id = rule_id_for(finding);
            let rule_index = rule_index[&rule_id];
            let (level, _, _) = sarif_severity(&finding.severity);
            // SARIF regions are 1-based; clamp so a 0 line never emits invalid output.
            let start_line = finding.line.max(1);
            let end_line = finding.end_line.max(start_line);
            let start_column = finding.column.max(1);
            let end_column = finding.end_column.max(start_column);
            serde_json::json!({
                "ruleId": rule_id,
                "ruleIndex": rule_index,
                "level": level,
                "message": {
                    "text": finding.description.clone().unwrap_or_else(|| finding.finding_type.clone())
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": sarif_uri(&finding.file, repository_root.as_deref())
                        },
                        "region": {
                            "startLine": start_line,
                            "startColumn": start_column,
                            "endLine": end_line,
                            "endColumn": end_column,
                            "snippet": { "text": finding.snippet }
                        }
                    }
                }]
            })
        })
        .collect();

    serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Sighthound",
                    "informationUri": "https://github.com/Corgea/Sighthound",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules
                }
            },
            "results": results
        }]
    })
}

/// Print findings as a SARIF 2.1.0 log to stdout.
pub fn print_findings_sarif(findings: &[Finding]) -> Result<()> {
    let json = serde_json::to_string_pretty(&build_sarif_log(findings))?;
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    writeln!(out, "{}", json)?;
    out.flush()?;
    Ok(())
}

/// Print findings in CSV format
pub fn print_findings_csv(findings: &[Finding]) -> Result<()> {
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    writeln!(out, "file,line,function,finding_type,code,severity,confidence,cwe_id,source_type,source_context,sink_type,sink_function,traces")?;
    for finding in findings {
        let code = finding.snippet.replace('"', "\"\"");
        let source_type =
            finding.source_info.as_ref().map(|s| s.source_type.as_str()).unwrap_or("");
        let source_context = finding.source_info.as_ref().map(|s| s.context.as_str()).unwrap_or("");
        let sink_type = finding.sink_info.as_ref().map(|s| s.sink_type.as_str()).unwrap_or("");
        let sink_function =
            finding.sink_info.as_ref().map(|s| s.function_name.as_str()).unwrap_or("");
        let cwe_id = finding.cwe_id.as_deref().unwrap_or("");

        let traces = if let Some(traces) = &finding.traces {
            traces
                .iter()
                .map(|t| format!("{}:{}:{}", t.line, t.variable, t.operation))
                .collect::<Vec<_>>()
                .join(";")
        } else {
            String::new()
        };

        writeln!(
            out,
            "{},{},{},{},\"{}\",{},{},{},{},{},{},{},\"{}\"",
            finding.file,
            finding.line,
            finding.function,
            finding.finding_type,
            code,
            finding.severity,
            finding.confidence,
            cwe_id,
            source_type,
            source_context,
            sink_type,
            sink_function,
            traces
        )?;
    }
    out.flush()?;
    Ok(())
}

/// Print findings in text format with syntax highlighting
/// Print the header line for a single finding: bullet, type, optional CWE id, line number.
fn print_finding_header(finding: &Finding, line_num: usize) {
    let cwe_info = if let Some(ref cwe_id) = finding.cwe_id {
        format!(" ({})", cwe_id)
    } else {
        String::new()
    };
    let bullet = crate::ui::paint(crate::ui::severity_code(&finding.severity), "\u{25cf}");
    println!(
        "    {} {}{} {}",
        bullet,
        finding.finding_type,
        cwe_info,
        crate::ui::dim(&format!("line {}", line_num))
    );
}

/// Print the source/sink info lines for a finding, when present.
fn print_finding_source_sink(finding: &Finding) {
    if let Some(source_info) = &finding.source_info {
        println!(
            "    {} {} ({})",
            crate::ui::dim("source"),
            source_info.source_type,
            source_info.context
        );
    }

    if let Some(sink_info) = &finding.sink_info {
        println!(
            "    {} {} ({})",
            crate::ui::dim("sink  "),
            sink_info.sink_type,
            sink_info.function_name
        );
        if let Some(var) = &sink_info.variable {
            println!("           {} {}", crate::ui::dim("var"), var);
        }
    }
}

/// Print the taint-flow trace lines for a finding, when present.
fn print_finding_traces(finding: &Finding) {
    let Some(traces) = &finding.traces else {
        return;
    };
    if traces.is_empty() {
        return;
    }
    println!("    {}", crate::ui::dim("flow"));
    for (i, trace) in traces.iter().enumerate() {
        println!(
            "       {}. {}:{} - {} ({}) in {}",
            i + 1,
            trace.line,
            trace.variable,
            trace.operation,
            trace.code.chars().take(50).collect::<String>(),
            trace.function
        );
    }
}

/// Marker string for a source-context line: highlighted `>>` for the hit line, blank otherwise.
fn context_line_marker(is_hit: bool, color: bool) -> &'static str {
    if !is_hit {
        "  "
    } else if color {
        "\x1b[31m>>\x1b[0m"
    } else {
        ">>"
    }
}

/// Print the source lines surrounding a finding, with syntax highlighting when available.
fn print_finding_code_context(
    lines: &[&str],
    syntax: Option<&syntect::parsing::SyntaxReference>,
    theme: &syntect::highlighting::Theme,
    ps: &SyntaxSet,
    start_line: usize,
    end_line: usize,
    line_num: usize,
) {
    let color = crate::ui::color_enabled();
    if let (Some(syntax), true) = (syntax, color) {
        let mut h = HighlightLines::new(syntax, theme);
        for (i, &line) in lines.iter().enumerate().take(end_line).skip(start_line) {
            let ranges: Vec<(Style, &str)> = h.highlight_line(line, ps).unwrap_or_default();
            print!("    {}{:4} | ", context_line_marker(i + 1 == line_num, color), i + 1);

            for (style, text) in ranges {
                let fg = style.foreground;
                print!("\x1b[38;2;{};{};{}m{}\x1b[0m", fg.r, fg.g, fg.b, text);
            }
            println!();
        }
    } else {
        // Plain text when highlighting is unavailable or color is disabled
        for (i, &line) in lines.iter().enumerate().take(end_line).skip(start_line) {
            println!("    {}{:4} | {}", context_line_marker(i + 1 == line_num, color), i + 1, line);
        }
    }
}

/// Print one finding: header, source/sink info, traces, and surrounding source context.
fn print_single_finding(
    finding: &Finding,
    lines: &[&str],
    syntax: Option<&syntect::parsing::SyntaxReference>,
    theme: &syntect::highlighting::Theme,
    ps: &SyntaxSet,
) {
    let line_num = finding.line;
    let start_line = line_num.saturating_sub(3);
    let end_line = (line_num + 3).min(lines.len());

    println!();
    print_finding_header(finding, line_num);
    print_finding_source_sink(finding);
    print_finding_traces(finding);

    println!();
    print_finding_code_context(lines, syntax, theme, ps, start_line, end_line, line_num);
    println!();
}

pub fn print_findings_text(
    findings: &[Finding],
    _verbose: bool,
    summary_only: bool,
    duration: std::time::Duration,
) {
    if !summary_only && !findings.is_empty() {
        crate::ui::section("Findings");

        // Initialize syntax highlighting
        let ps = SyntaxSet::load_defaults_newlines();
        let ts = ThemeSet::load_defaults();
        let theme = &ts.themes["base16-ocean.dark"];

        // Pre-sort findings by file and severity for better grouping
        let mut sorted_findings: Vec<_> = findings.iter().collect();
        sorted_findings.sort_by(|a, b| {
            a.file.cmp(&b.file).then(a.severity.cmp(&b.severity)).then(a.line.cmp(&b.line))
        });

        // Group findings by file
        let mut current_file = None;
        let mut file_contents: String;
        let mut lines = Vec::new();
        let mut syntax = None;

        for finding in sorted_findings {
            // Only read file when it changes
            if current_file != Some(&finding.file) {
                current_file = Some(&finding.file);
                file_contents = match fs::read_to_string(&finding.file) {
                    Ok(contents) => contents,
                    Err(_) => continue,
                };
                lines = file_contents.lines().collect();

                // Set up syntax highlighting for the new file
                let syntax_name = CommonUtils::detect_syntax(&finding.file);
                syntax = ps.find_syntax_by_name(syntax_name);

                println!();
                println!("{}", crate::ui::bold(&crate::ui::blue(&finding.file)));
            }

            print_single_finding(finding, &lines, syntax, theme, &ps);
        }
    }
    print_summary(findings, duration);
}

#[cfg(test)]
mod sarif_tests {
    use super::{build_sarif_log, sarif_uri};
    use crate::models::Finding;
    use std::path::Path;

    fn finding(finding_type: &str, severity: &str, cwe: Option<&str>, line: usize) -> Finding {
        Finding {
            file: "src/app.py".to_string(),
            line,
            column: 5,
            end_line: line,
            end_column: 30,
            function: "os.system".to_string(),
            finding_type: finding_type.to_string(),
            snippet: "os.system(cmd)".to_string(),
            severity: severity.to_string(),
            confidence: "Medium".to_string(),
            description: Some("OS command execution sink".to_string()),
            cwe_id: cwe.map(str::to_string),
            source_info: None,
            sink_info: None,
            traces: None,
            tags: None,
        }
    }

    #[test]
    fn emits_valid_sarif_shape() {
        let findings = vec![
            finding("Command Injection", "High", Some("cwe-78"), 6),
            finding("Command Injection", "High", Some("cwe-78"), 15),
            finding("SQL Injection", "Medium", Some("cwe-89"), 9),
        ];
        let log = build_sarif_log(&findings);

        assert_eq!(log["version"], "2.1.0");
        assert!(log["$schema"].as_str().unwrap().contains("sarif-schema-2.1.0"));

        let run = &log["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "Sighthound");

        // One result per finding.
        assert_eq!(run["results"].as_array().unwrap().len(), 3);

        // Rules are deduplicated by CWE: two distinct rules for three findings.
        let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);

        // First result maps severity, region, and location correctly.
        let first = &run["results"][0];
        assert_eq!(first["ruleId"], "cwe-78");
        assert_eq!(first["ruleIndex"], 0);
        assert_eq!(first["level"], "error");
        let region = &first["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["startLine"], 6);
        assert_eq!(region["startColumn"], 5);
        assert_eq!(
            first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/app.py"
        );

        // CWE rule carries the GitHub security-severity property and cwe tag.
        let cwe_rule = rules.iter().find(|r| r["id"] == "cwe-78").expect("cwe-78 rule present");
        assert_eq!(cwe_rule["properties"]["security-severity"], "8.9");
        let tags = cwe_rule["properties"]["tags"].as_array().unwrap();
        assert!(tags.iter().any(|t| t == "external/cwe/cwe-78"));
    }

    #[test]
    fn clamps_zero_line_to_valid_region() {
        let findings = vec![Finding {
            line: 0,
            column: 0,
            end_line: 0,
            end_column: 0,
            ..finding("Unknown", "Low", None, 0)
        }];
        let log = build_sarif_log(&findings);
        let region = &log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
        // SARIF requires startLine >= 1; a 0-line finding must still be valid.
        assert_eq!(region["startLine"], 1);
        assert_eq!(region["startColumn"], 1);
    }

    #[test]
    fn normalizes_cwe_ids_and_assigns_deduplicated_rule_indexes() {
        let findings = vec![
            finding("Command Injection", "High", Some("CWE-78"), 6),
            finding("Command Injection", "High", Some("cwe-78"), 15),
            finding("SQL Injection", "Medium", Some("CWE-89"), 9),
        ];
        let log = build_sarif_log(&findings);
        let run = &log["runs"][0];
        let rules = run["tool"]["driver"]["rules"].as_array().unwrap();

        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["id"], "cwe-78");
        assert_eq!(run["results"][0]["ruleId"], "cwe-78");
        assert_eq!(run["results"][0]["ruleIndex"], 0);
        assert_eq!(run["results"][1]["ruleId"], "cwe-78");
        assert_eq!(run["results"][1]["ruleIndex"], 0);
        assert_eq!(run["results"][2]["ruleIndex"], 1);
    }

    #[test]
    fn uses_maximum_security_severity_for_a_shared_rule() {
        for (first, second) in [("Low", "Critical"), ("Critical", "Low")] {
            let findings = vec![
                finding("Cross-site Scripting", first, Some("cwe-79"), 6),
                finding("Cross-site Scripting", second, Some("cwe-79"), 15),
            ];
            let log = build_sarif_log(&findings);
            let rule = &log["runs"][0]["tool"]["driver"]["rules"][0];

            assert_eq!(rule["properties"]["security-severity"], "9.5");
        }
    }

    #[test]
    fn emits_repository_relative_uris() {
        let repository_root = Path::new("/repo");

        assert_eq!(sarif_uri("./src/app.py", Some(repository_root)), "src/app.py");
        assert_eq!(sarif_uri("/repo/src/app.py", Some(repository_root)), "src/app.py");
        assert_eq!(sarif_uri("backend/src/app.py", Some(repository_root)), "backend/src/app.py");
    }
}
