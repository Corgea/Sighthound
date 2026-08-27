//! Tier 1: AST-grounded provenance (Python).
//!
//! Structural assignment shapes must resolve to their real sources instead of
//! text-scan approximations: multiline/annotated/augmented/chained/tuple
//! assignments must not hide taint (false negatives), and docstring text or a
//! same-named variable in another function must not donate taint (false
//! positives).

use super::helpers::*;

const CMD_TAINT_RULES: &str = "tests/strictness/fixtures/command_injection_taint.ron";

#[test]
#[cfg(feature = "python")]
fn multiline_parenthesized_taint_assignment_is_detected() {
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "cli.py",
        r#"import os


def run_cli():
    cmd = (
        input()
    )
    os.system(cmd)
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_findings_in_range(
        &findings,
        8,
        8,
        1,
        "multiline parenthesized assignment: input() -> os.system must be reported",
    );
}

#[test]
#[cfg(feature = "python")]
fn annotated_taint_assignment_is_detected() {
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "annotated.py",
        r#"import os


def run_annotated():
    cmd: str = input()
    os.system(cmd)
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_findings_in_range(
        &findings,
        6,
        6,
        1,
        "annotated assignment: input() -> os.system must be reported",
    );
}

#[test]
#[cfg(feature = "python")]
fn augmented_taint_assignment_is_detected() {
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "augmented.py",
        r#"import os


def run_augmented():
    cmd = "echo "
    cmd += input()
    os.system(cmd)
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_findings_in_range(
        &findings,
        7,
        7,
        1,
        "augmented assignment: cmd += input() -> os.system must be reported",
    );
}

#[test]
#[cfg(feature = "python")]
fn chained_taint_assignment_is_detected() {
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "chained.py",
        r#"import os


def run_chained():
    first = second = input()
    os.system(second)
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_findings_in_range(
        &findings,
        6,
        6,
        1,
        "chained assignment: the inner chained target must carry taint to os.system",
    );
}

#[test]
#[cfg(feature = "python")]
fn tuple_taint_assignment_is_detected() {
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "tuple_target.py",
        r#"import os


def run_tuple():
    cmd, log_name = input(), "app.log"
    os.system(cmd)
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_findings_in_range(
        &findings,
        6,
        6,
        1,
        "tuple assignment: tainted tuple element -> os.system must be reported",
    );
}

#[test]
#[cfg(feature = "python")]
fn tuple_safe_sibling_is_not_flagged() {
    // The tainted element (`cmd`) and a safe sibling (`log_name`) are unpacked
    // from the same statement. Using the SAFE sibling at the sink must not be
    // flagged — positional pairing keeps `input()` from bleeding onto `log_name`.
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "tuple_sibling.py",
        r#"import os


def run_tuple():
    cmd, log_name = input(), "app.log"
    os.system(log_name)
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_no_findings_in_range(
        &findings,
        1,
        20,
        "safe tuple sibling (log_name = literal) must not inherit the tainted element's value",
    );
}

#[test]
#[cfg(feature = "python")]
fn docstring_text_does_not_taint_real_assignment() {
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "documented.py",
        r#"import os


def run_documented():
    """Usage:

    cmd = input()
    """
    cmd = "uptime"
    os.system(cmd)
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_no_findings_in_range(
        &findings,
        1,
        20,
        "docstring example text must not be treated as the variable's assignment",
    );
}

#[test]
#[cfg(feature = "python")]
fn same_named_variable_in_other_function_does_not_donate_taint() {
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "scoped.py",
        r#"import os


def collect_input():
    data = input()
    return data


async def report_status():
    data = "uptime"
    os.system("status " + data)
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_no_findings_in_range(
        &findings,
        9,
        20,
        "async function's safe local must not inherit taint from another function's same-named variable",
    );
}

#[test]
#[cfg(feature = "python")]
fn iteration_over_literal_collection_is_not_tainted() {
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "allowlist.py",
        r#"import os


def touch_flags():
    for flag_name in ["beta", "dark_mode", "canary"]:
        os.system("touch /tmp/flag_" + flag_name)
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_no_findings_in_range(
        &findings,
        1,
        20,
        "loop variable bound to a literal allowlist must not be treated as attacker-controlled",
    );
}

#[test]
#[cfg(feature = "python")]
fn starred_taint_element_reaches_star_target() {
    // `head, *tail = "safe", input()` binds the tainted element to `tail`;
    // using `tail` at the sink must be reported even though the star defeats
    // one-to-one pairing.
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "starred.py",
        r#"import os


def run_starred():
    head, *tail = "safe", input("c: ")
    os.system(" ".join(tail))
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_findings_in_range(
        &findings,
        4,
        7,
        1,
        "starred assignment: the tainted element bound to *tail must reach os.system",
    );
}

#[test]
#[cfg(feature = "python")]
fn starred_safe_prefix_is_not_flagged() {
    // The fixed target before the star receives only its own constant; the
    // tainted element belongs to `*tail` and must not bleed onto `head`.
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "starred_safe.py",
        r#"import os


def run_starred():
    head, *tail = "safe", input("c: ")
    os.system(head)
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_no_findings_in_range(
        &findings,
        1,
        20,
        "safe fixed target before the star must not inherit the starred element's taint",
    );
}

#[test]
#[cfg(feature = "python")]
fn loop_carried_taint_is_still_detected() {
    // The tainted assignment sits below the sink, but the enclosing loop
    // carries it back on the next iteration — reachability filtering must not
    // suppress it.
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "loop_carried.py",
        r#"import os


def run_loop():
    cmd = "status"
    while True:
        os.system(cmd)
        cmd = input("c: ")
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_findings_in_range(
        &findings,
        4,
        9,
        1,
        "assignment below the sink inside the same loop must still be reported",
    );
}

// Regression guards: these real injections are caught by the text-based engine;
// the AST provenance path must not lose them. An empty-collection initializer
// (`cfg = {}` / `parts = []`) followed by a tainted write must still reach the
// sink.

#[test]
#[cfg(feature = "python")]
fn attribute_assignment_taint_is_detected() {
    // Attribute targets carry no structural facts, so the text tracker must
    // keep covering them: dropping the fallback loses this real injection.
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "attribute.py",
        r#"import os


class Runner:
    def run(self):
        self.cmd = input("c: ")
        os.system(self.cmd)
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_findings_in_range(
        &findings,
        5,
        8,
        1,
        "attribute assignment: self.cmd = input() -> os.system must be reported",
    );
}

#[test]
#[cfg(feature = "python")]
fn subscript_overwrite_of_literal_collection_is_detected() {
    // The literal initializer proves nothing once a later write replaces an
    // element: `cfg` must not be classified definitely-safe.
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "literal_overwrite.py",
        r#"import os


def run_overwrite():
    cfg = ["ls", "pwd"]
    cfg[0] = input("cmd: ")
    os.system(cfg[0])
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_findings_in_range(
        &findings,
        4,
        8,
        1,
        "tainted subscript write over a literal collection must still reach the sink",
    );
}

#[test]
#[cfg(feature = "python")]
fn subscript_write_of_taint_is_detected() {
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "subscript.py",
        r#"import os


def run_subscript():
    cfg = {}
    cfg["cmd"] = input("cmd: ")
    os.system(cfg["cmd"])
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_findings_in_range(
        &findings,
        4,
        7,
        1,
        "tainted subscript write into an empty dict must still reach the sink",
    );
}

#[test]
#[cfg(feature = "python")]
fn collection_mutation_with_taint_is_detected() {
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "mutation.py",
        r#"import os


def run_mutation():
    parts = []
    parts.append(input("part: "))
    os.system(" ".join(parts))
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_findings_in_range(
        &findings,
        4,
        7,
        1,
        "appending tainted data to an empty list must still reach the sink",
    );
}

#[test]
#[cfg(feature = "python")]
fn list_literal_safe_sibling_is_not_flagged() {
    // `cmd, log_name = [input(), "app.log"]` unpacks the list positionally just
    // like a tuple, so the safe sibling `log_name` must not inherit `input()`.
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "list_sibling.py",
        r#"import os


def run_list():
    cmd, log_name = [input(), "app.log"]
    os.system(log_name)
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_no_findings_in_range(
        &findings,
        1,
        20,
        "safe sibling from a list-literal unpack must not inherit the tainted element's value",
    );
}

#[test]
#[cfg(feature = "python")]
fn list_literal_tainted_element_is_detected() {
    // The positional pairing must not drop taint: the tainted element bound to
    // `cmd` still has to reach the sink.
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "list_tainted.py",
        r#"import os


def run_list():
    cmd, log_name = [input(), "app.log"]
    os.system(cmd)
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_findings_in_range(
        &findings,
        4,
        7,
        1,
        "list-literal unpack: the tainted element bound to cmd must reach os.system",
    );
}

#[test]
#[cfg(feature = "python")]
fn collection_mutation_over_literal_list_is_detected() {
    // A NON-EMPTY literal initializer must not prove the collection safe once a
    // tainting mutator adds attacker data — the literal `["prefix"]` no longer
    // clears the sink after `parts.append(input())`.
    let staging = stage_dir();
    write_staged_file(
        staging.path(),
        "literal_mutation.py",
        r#"import os


def run_mutation():
    parts = ["prefix"]
    parts.append(input("part: "))
    os.system(" ".join(parts))
"#,
    );

    let findings = scan_python_taint(staging.path(), CMD_TAINT_RULES);
    assert_findings_in_range(
        &findings,
        4,
        8,
        1,
        "tainting mutator over a non-empty literal collection must still reach the sink",
    );
}
