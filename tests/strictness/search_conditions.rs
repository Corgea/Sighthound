//! Tier 2: search-mode condition strictness (subprocess shell=True, Java XSS escaping).

use super::helpers::*;
use sighthound::rules::Rules;

#[test]
#[cfg(feature = "python")]
fn subprocess_without_shell_true_is_not_flagged() {
    let staging = stage_dir();

    write_staged_file(
        staging.path(),
        "app.py",
        r#"
import subprocess

def safe_list_arg(user_input):
    subprocess.run(["ls", user_input])

def safe_no_shell(user_input):
    subprocess.Popen(["echo", user_input], shell=False)

def unsafe_shell(user_input):
    subprocess.Popen(user_input, shell=True)

def safe_literal():
    subprocess.Popen(["echo", "hi"])
"#,
    );

    let findings = scan_python_simple_with_rules(staging.path(), load_production_python_rules());
    let cmd_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.finding_type.contains("Command Injection"))
        .collect();

    assert_eq!(
        cmd_findings.len(),
        1,
        "only shell=True subprocess should be flagged, got: {:?}",
        cmd_findings
            .iter()
            .map(|f| (f.line, f.snippet.as_str()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        cmd_findings[0].line, 11,
        "unsafe_shell should be on line 11"
    );
}

#[test]
#[cfg(feature = "java")]
fn java_xss_html_escape_suppresses_finding() {
    let rules = Rules::load_from_file("rules/java/xss.ron").expect("load java xss rules");
    let staging = stage_dir();

    write_staged_file(
        staging.path(),
        "src/views/UserView.java",
        r#"
public class UserView {
    public void renderUnsafe(String userInput, StringBuilder sb) {
        sb.append(userInput);
    }

    public void renderSafe(String userInput, StringBuilder sb) {
        sb.append(Html.escape(userInput));
    }

    public void renderLiteral(StringBuilder sb) {
        sb.append("<div>static</div>");
    }
}
"#,
    );

    let findings = scan_java_simple_with_rules(staging.path(), rules);
    let xss: Vec<_> = findings
        .iter()
        .filter(|f| f.finding_type.contains("Cross-Site Scripting"))
        .collect();

    assert_eq!(
        xss.len(),
        1,
        "only unescaped dynamic append should be flagged, got: {:?}",
        xss.iter()
            .map(|f| (f.line, f.snippet.as_str()))
            .collect::<Vec<_>>()
    );
    assert_eq!(xss[0].line, 4, "unsafe append should be on line 4");
}
