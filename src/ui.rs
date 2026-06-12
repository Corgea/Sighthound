//! Small, dependency-free helpers for Sighthound's terminal output.
//!
//! Styling is applied only when stdout is a TTY and `NO_COLOR` is unset, so
//! piped/redirected output stays clean. No emojis are used anywhere here.

use std::io::IsTerminal;
use std::sync::OnceLock;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const RED_BOLD: &str = "\x1b[31;1m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const CYAN: &str = "\x1b[36m";

/// Whether ANSI styling should be emitted.
pub fn color_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED
        .get_or_init(|| std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal())
}

/// Wrap `text` in an ANSI code when color is enabled.
pub fn paint(code: &str, text: &str) -> String {
    if color_enabled() {
        format!("{}{}{}", code, text, RESET)
    } else {
        text.to_string()
    }
}

pub fn bold(t: &str) -> String {
    paint(BOLD, t)
}
pub fn dim(t: &str) -> String {
    paint(DIM, t)
}
pub fn cyan(t: &str) -> String {
    paint(CYAN, t)
}
pub fn blue(t: &str) -> String {
    paint(BLUE, t)
}
pub fn yellow(t: &str) -> String {
    paint(YELLOW, t)
}

/// Color for a severity name (case-insensitive). Returns the raw code so callers
/// can combine it with other styling; use [`severity`] for a ready string.
pub fn severity_code(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" => RED_BOLD,
        "high" => RED,
        "medium" => YELLOW,
        "low" => GREEN,
        _ => "",
    }
}

/// A severity label painted in its conventional color.
pub fn severity(severity: &str) -> String {
    paint(severity_code(severity), severity)
}

/// Top banner shown when a scan starts, e.g. `sighthound  scanning <target>`.
pub fn banner(target: &str) {
    println!();
    println!(
        "{}  {}",
        bold(&cyan("sighthound")),
        dim(&format!("scanning {}", target))
    );
}

/// An aligned `label  value` line under the banner.
pub fn field(label: &str, value: &str) {
    println!("  {} {}", dim(&format!("{:<11}", label)), value);
}

/// A bold section heading (e.g. `Findings`, `Summary`).
pub fn section(title: &str) {
    println!();
    println!("{}", bold(title));
}

/// A dim, indented informational line.
pub fn note(msg: &str) {
    println!("  {}", dim(msg));
}

/// A warning line (stderr).
pub fn warn(msg: &str) {
    eprintln!("  {} {}", paint(YELLOW, "warning:"), msg);
}

/// An error line (stderr).
pub fn error_line(msg: &str) {
    eprintln!("  {} {}", paint(RED_BOLD, "error:"), msg);
}
