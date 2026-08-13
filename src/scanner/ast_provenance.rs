//! AST-grounded variable provenance for Python.
//!
//! Resolves "where does this variable get its value?" from the tree-sitter AST
//! instead of scanning source lines as text. This makes provenance robust to
//! shapes the text scan cannot see (multiline, annotated, augmented, chained,
//! and tuple assignments; `for` targets) and immune to shapes the text scan
//! wrongly matches (assignment-like text inside docstrings, same-named
//! variables in other functions).
//!
//! The resolver reports structural facts only — classification of an RHS as
//! safe or tainted stays in [`crate::scanner::dataflow`]. Any construct it
//! does not model yields `None`, and callers fall back to the existing text
//! path, so unsupported shapes keep today's behavior. The one exception is
//! [`AstResolution::Ambiguous`]: when the resolver positively knows a bare
//! function name is defined more than once, falling back would guess, so
//! callers must treat the variable as unknown instead.

use crate::parser::{get_node_text_slice, LanguageParser};
use tree_sitter::Node;

/// How a variable received a value, in source order within one function.
#[derive(Debug, Clone)]
pub(crate) struct AssignmentFact {
    /// Simple identifier target this fact is recorded for.
    pub(crate) target: String,
    /// Whitespace-normalized text of the assigned value expression.
    pub(crate) rhs: String,
    /// 1-based file line of the assignment statement.
    pub(crate) line: usize,
    /// `x += ...`: the value depends on the prior value of `x` as well.
    pub(crate) augmented: bool,
    /// The RHS is a collection literal containing only literals, so every
    /// value the target can take is developer-controlled.
    pub(crate) literal_collection: bool,
    /// The RHS is a literal expression or a literal collection: the assigned
    /// value itself is developer-controlled (though the variable may still
    /// receive other values through other assignments).
    pub(crate) literal_value: bool,
    /// Inclusive 1-based line span of the outermost `for`/`while` loop
    /// enclosing the assignment, if any. A loop carries the assigned value
    /// back to lines above the assignment on the next iteration.
    pub(crate) enclosing_loop: Option<(usize, usize)>,
}

impl AssignmentFact {
    /// Whether this assignment can flow into a use at `line`: it appears at or
    /// before that line, or an enclosing loop's next iteration carries the
    /// value back to an earlier line within the loop.
    pub(crate) fn reaches(&self, line: usize) -> bool {
        self.line <= line
            || self.enclosing_loop.is_some_and(|(start, end)| line >= start && line <= end)
    }
}

/// Outcome of resolving one variable within one function.
#[derive(Debug)]
pub(crate) enum AstResolution {
    /// All assignments to the variable in the function body, in source order.
    Assignments(Vec<AssignmentFact>),
    /// The variable is the function's parameter at `index`.
    Parameter { index: usize },
    /// The bare function name is defined more than once in the file, so any
    /// resolution would be a guess. Callers must treat the variable as
    /// unknown — falling back to a text scan would just guess the first
    /// definition and reintroduce cross-definition mixing.
    Ambiguous,
}

#[derive(Debug, Clone)]
struct FunctionFacts {
    parameters: Vec<String>,
    assignments: Vec<AssignmentFact>,
}

#[derive(Debug)]
struct FileFacts {
    /// First definition in document order wins, matching the text path.
    functions: std::collections::BTreeMap<String, FunctionFacts>,
    /// Bare names defined more than once in the file (e.g. `run` on two
    /// classes). The caller resolves a variable by the sink's *bare* function
    /// name, so for such names we cannot know which definition is meant and
    /// refuse to guess — see [`PythonAstProvenance::resolve_variable`].
    ambiguous: std::collections::BTreeSet<String>,
}

/// Per-file cache of extracted Python function facts. `None` entries record
/// files that could not be read or parsed so they are not retried.
#[derive(Debug, Default)]
pub(crate) struct PythonAstProvenance {
    file_cache: std::collections::HashMap<String, Option<FileFacts>>,
}

impl PythonAstProvenance {
    /// Resolve `variable_name` within `function_name` of a Python file with no
    /// usage-line filtering — every recorded assignment is reported. Returns
    /// `None` for non-Python files, unparseable files, unknown functions, or
    /// variables the model does not cover.
    #[cfg(test)]
    pub(crate) fn resolve_variable(
        &mut self,
        file_path: &str,
        function_name: &str,
        variable_name: &str,
    ) -> Option<AstResolution> {
        self.resolve_variable_reaching(file_path, function_name, variable_name, None)
    }

    /// Like [`Self::resolve_variable`], but when `usage_line` is given, only
    /// assignments that can reach that line are reported (see
    /// [`AssignmentFact::reaches`]): an assignment below the usage cannot be
    /// the value the usage observes unless a loop carries it back around. When
    /// no assignment reaches the usage, a matching parameter wins — the
    /// parameter is exactly what the variable still holds at that point.
    pub(crate) fn resolve_variable_reaching(
        &mut self,
        file_path: &str,
        function_name: &str,
        variable_name: &str,
        usage_line: Option<usize>,
    ) -> Option<AstResolution> {
        if !has_python_extension(file_path) {
            return None;
        }
        let facts = self.file_facts(file_path)?;
        // The sink gives us only a bare function name. If that name is defined
        // more than once (e.g. `run` on two different classes), resolving it
        // could attribute one definition's assignments to another. Report that
        // explicitly instead of deferring: a text fallback keyed on the first
        // matching definition would guess exactly as wrongly.
        if facts.ambiguous.contains(function_name) {
            return Some(AstResolution::Ambiguous);
        }
        let function = facts.functions.get(function_name)?;

        let assignments: Vec<AssignmentFact> = function
            .assignments
            .iter()
            .filter(|fact| fact.target == variable_name)
            .filter(|fact| usage_line.is_none_or(|line| fact.reaches(line)))
            .cloned()
            .collect();
        if !assignments.is_empty() {
            return Some(AstResolution::Assignments(assignments));
        }

        let index = function.parameters.iter().position(|name| name == variable_name)?;
        Some(AstResolution::Parameter { index })
    }

    fn file_facts(&mut self, file_path: &str) -> Option<&FileFacts> {
        if !self.file_cache.contains_key(file_path) {
            let facts = parse_file_facts(file_path);
            self.file_cache.insert(file_path.to_string(), facts);
        }
        self.file_cache.get(file_path)?.as_ref()
    }
}

/// Whether AST-grounded Python provenance applies to this file.
pub(crate) fn is_python_source(file_path: &str) -> bool {
    has_python_extension(file_path)
}

/// Assignment facts carried by a single `assignment`/`augmented_assignment`
/// node. Any other node kind carries none — text that merely looks like an
/// assignment (docstrings, string literals) never yields a fact.
pub(crate) fn assignment_facts_for_node(node: Node, source: &[u8]) -> Vec<AssignmentFact> {
    let mut out = Vec::new();
    match node.kind() {
        "assignment" => record_assignment(node, source, &mut out),
        "augmented_assignment" => record_augmented_assignment(node, source, &mut out),
        _ => {}
    }
    out
}

/// Augmented-assignment facts inside a statement wrapper. Plain `assignment`
/// children are deliberately excluded: node collection surfaces those as
/// standalone nodes, so extracting them here as well would double-record.
pub(crate) fn augmented_facts_in_statement(node: Node, source: &[u8]) -> Vec<AssignmentFact> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "augmented_assignment" {
            record_augmented_assignment(child, source, &mut out);
        }
    }
    out
}

fn has_python_extension(file_path: &str) -> bool {
    std::path::Path::new(file_path)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext, "py" | "pyw" | "pyi"))
}

fn parse_file_facts(file_path: &str) -> Option<FileFacts> {
    let source = std::fs::read(file_path).ok()?;
    let mut parser = LanguageParser::new("python").ok()?;
    let tree = parser.parse(&source).ok()?;

    let mut functions = std::collections::BTreeMap::new();
    let mut ambiguous = std::collections::BTreeSet::new();
    collect_functions(tree.root_node(), &source, &mut functions, &mut ambiguous);
    Some(FileFacts { functions, ambiguous })
}

/// Preorder walk recording every `def` (sync or async, top-level, nested, or
/// method) by name; the first definition in document order wins, and any name
/// seen more than once is recorded as ambiguous.
fn collect_functions(
    node: Node,
    source: &[u8],
    functions: &mut std::collections::BTreeMap<String, FunctionFacts>,
    ambiguous: &mut std::collections::BTreeSet<String>,
) {
    if node.kind() == "function_definition" {
        record_function(node, source, functions, ambiguous);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_functions(child, source, functions, ambiguous);
    }
}

fn record_function(
    node: Node,
    source: &[u8],
    functions: &mut std::collections::BTreeMap<String, FunctionFacts>,
    ambiguous: &mut std::collections::BTreeSet<String>,
) {
    let Some(name_node) = node.child_by_field_name("name") else { return };
    let name = get_node_text_slice(&name_node, source).to_string();
    if functions.contains_key(&name) {
        ambiguous.insert(name);
        return;
    }

    let parameters = node
        .child_by_field_name("parameters")
        .map(|p| parameter_names(p, source))
        .unwrap_or_default();
    let mut assignments = Vec::new();
    if let Some(body) = node.child_by_field_name("body") {
        collect_assignments(body, source, &mut assignments);
    }
    functions.insert(name, FunctionFacts { parameters, assignments });
}

fn parameter_names(parameters: Node, source: &[u8]) -> Vec<String> {
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter_map(|child| parameter_name(child, source))
        .collect()
}

fn parameter_name(node: Node, source: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => Some(get_node_text_slice(&node, source).to_string()),
        "default_parameter" | "typed_default_parameter" => {
            let name = node.child_by_field_name("name")?;
            Some(get_node_text_slice(&name, source).to_string())
        }
        "typed_parameter" | "list_splat_pattern" | "dictionary_splat_pattern" => {
            let mut cursor = node.walk();
            let name = node.named_children(&mut cursor).find(|c| c.kind() == "identifier")?;
            Some(get_node_text_slice(&name, source).to_string())
        }
        _ => None,
    }
}

/// Collect assignment facts within a function body in source order. Nested
/// `def`/`class`/`lambda` scopes are skipped: their locals are not this
/// function's locals.
fn collect_assignments(node: Node, source: &[u8], out: &mut Vec<AssignmentFact>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_definition" | "class_definition" | "lambda" => {}
            "assignment" => record_assignment(child, source, out),
            "augmented_assignment" => record_augmented_assignment(child, source, out),
            "for_statement" => {
                record_for_targets(child, source, out);
                collect_assignments(child, source, out);
            }
            // A collection-mutating call (`x.append(v)`) is not an assignment
            // node, so record it here against the mutated variable, then keep
            // descending to catch nested statements/mutations.
            "call" => {
                record_collection_mutation(child, source, out);
                collect_assignments(child, source, out);
            }
            _ => collect_assignments(child, source, out),
        }
    }
}

fn record_assignment(node: Node, source: &[u8], out: &mut Vec<AssignmentFact>) {
    let Some(left) = node.child_by_field_name("left") else { return };
    // A bare annotation (`x: int`) has no right side and assigns nothing.
    let Some(right) = node.child_by_field_name("right") else { return };

    // Chained assignment (`a = b = value`) nests as assignment-in-assignment;
    // every intermediate target receives the innermost value.
    let mut targets = vec![left];
    let mut value = right;
    while value.kind() == "assignment" {
        let Some(inner_left) = value.child_by_field_name("left") else { return };
        let Some(inner_right) = value.child_by_field_name("right") else { return };
        targets.push(inner_left);
        value = inner_right;
    }

    push_target_facts(node, &targets, value, false, source, out);
}

fn record_augmented_assignment(node: Node, source: &[u8], out: &mut Vec<AssignmentFact>) {
    let Some(left) = node.child_by_field_name("left") else { return };
    let Some(right) = node.child_by_field_name("right") else { return };
    push_target_facts(node, &[left], right, true, source, out);
}

/// Record a collection-mutating method call (`x.append(v)`, `x.extend(v)`, …)
/// as a fact against the mutated variable `x`. The mutation adds `v` to the
/// collection, so — like an augmented assignment — it is inconclusive on its
/// own but must not be dropped: a tainted argument taints `x`, and any
/// non-literal argument denies a later "literal collection is safe" verdict
/// that would otherwise clear the sink. Without this fact a resolver seeing
/// only `parts = ["prefix"]` would call `parts` definitely-safe even after
/// `parts.append(input())`. Mirrors the forward tracker's use of
/// `collection_mutation_target`.
fn record_collection_mutation(node: Node, source: &[u8], out: &mut Vec<AssignmentFact>) {
    let Some((base, args)) = collection_mutation_target(node, source) else {
        return;
    };
    let line = node.start_position().row + 1;
    let enclosing_loop = outermost_loop_span(node);
    // The mutation keeps the collection developer-controlled only when every
    // argument is itself literal (`parts.append("x")`); anything else defeats
    // the literal-collection safety proof.
    let literal_value = node.child_by_field_name("arguments").is_some_and(|arguments| {
        all_named_children(arguments, |c| is_literal_expr(c) || is_literal_collection(c))
    });
    out.push(AssignmentFact {
        target: base,
        rhs: args,
        line,
        augmented: true,
        literal_collection: false,
        literal_value,
        enclosing_loop,
    });
}

fn record_for_targets(node: Node, source: &[u8], out: &mut Vec<AssignmentFact>) {
    let Some(left) = node.child_by_field_name("left") else { return };
    let Some(iterable) = node.child_by_field_name("right") else { return };
    // The loop variable's provenance is the iterable: tainted iterables yield
    // tainted elements, literal collections yield developer-controlled ones.
    // Positional pairing must NOT apply here — `for a, b in x, y:` iterates the
    // tuple `(x, y)` and unpacks EACH element into `(a, b)`, so every target
    // can receive values from every element; each keeps the whole iterable.
    let line = node.start_position().row + 1;
    let enclosing_loop = outermost_loop_span(node);
    for name in target_identifiers(left, source) {
        out.push(AssignmentFact {
            target: name,
            rhs: normalized_text(iterable, source),
            line,
            augmented: false,
            literal_collection: is_literal_collection(iterable),
            literal_value: is_literal_expr(iterable) || is_literal_collection(iterable),
            enclosing_loop,
        });
    }
}

/// Inclusive 1-based line span of the outermost `for`/`while` loop enclosing
/// `node` within its function (the node itself counts — a `for` statement is
/// its own loop). `None` for straight-line code: there, an assignment can only
/// flow to lines at or below it.
fn outermost_loop_span(node: Node) -> Option<(usize, usize)> {
    let mut span = None;
    let mut current = Some(node);
    while let Some(n) = current {
        match n.kind() {
            "function_definition" | "lambda" | "module" => break,
            "for_statement" | "while_statement" => {
                span = Some((n.start_position().row + 1, n.end_position().row + 1));
            }
            _ => {}
        }
        current = n.parent();
    }
    span
}

fn push_target_facts(
    statement: Node,
    targets: &[Node],
    value: Node,
    augmented: bool,
    source: &[u8],
    out: &mut Vec<AssignmentFact>,
) {
    let line = statement.start_position().row + 1;
    let enclosing_loop = outermost_loop_span(statement);
    for target in targets {
        // Each (name, value_node) pair carries the *specific* value that reaches
        // that name: for tuple unpacking this is the positionally-matched element,
        // not the whole right-hand side, so a safe sibling can't inherit a
        // tainted element's value.
        for (name, value_node) in target_value_pairs(*target, value, source) {
            out.push(AssignmentFact {
                target: name,
                rhs: normalized_text(value_node, source),
                line,
                augmented,
                literal_collection: is_literal_collection(value_node),
                literal_value: is_literal_expr(value_node) || is_literal_collection(value_node),
                enclosing_loop,
            });
        }
    }
}

/// Map an assignment target to the value node(s) that actually reach it.
///
/// For `a, b = x, y` this pairs positionally (`a`←`x`, `b`←`y`), and a single
/// starred target pairs around the star (`head, *tail = x, y, z` gives
/// `head`←`x` and `tail`←each of `y`, `z`). Pairing applies only when both
/// sides are sequences, non-starred targets are plain identifiers, and the
/// value side has no splat of unknown arity; any other shape (nesting,
/// subscript element, a non-sequence RHS such as `a, b = f()`, or an arity
/// mismatch) conservatively falls back to attributing the whole value to
/// every name in the target — including names inside starred or nested
/// patterns — never dropping taint, only avoiding cross-element bleed.
fn target_value_pairs<'a>(
    target: Node<'a>,
    value: Node<'a>,
    source: &[u8],
) -> Vec<(String, Node<'a>)> {
    if matches!(target.kind(), "pattern_list" | "tuple_pattern") {
        if let Some(pairs) = positional_pairs(target, value, source) {
            return pairs;
        }
    }
    target_identifiers(target, source).into_iter().map(|name| (name, value)).collect()
}

fn positional_pairs<'a>(
    target: Node<'a>,
    value: Node<'a>,
    source: &[u8],
) -> Option<Vec<(String, Node<'a>)>> {
    let targets = sequence_elements(target)?;
    let values = sequence_elements(value)?;
    // A splat on the VALUE side (`a, b = *x, y`) expands to an unknown number
    // of elements, so no positional pairing is possible.
    if values.iter().any(|v| matches!(v.kind(), "list_splat" | "list_splat_pattern")) {
        return None;
    }

    let star = targets.iter().position(|t| t.kind() == "list_splat_pattern");
    match star {
        None => {
            if targets.len() != values.len() {
                return None;
            }
            let mut pairs = Vec::with_capacity(targets.len());
            for (t, v) in targets.iter().zip(values.iter()) {
                // Only plain identifiers pair cleanly; a nested/subscript element
                // means we cannot line values up one-to-one, so give up on pairing
                // and let the caller fall back to whole-value attribution.
                if t.kind() != "identifier" {
                    return None;
                }
                pairs.push((get_node_text_slice(t, source).to_string(), *v));
            }
            Some(pairs)
        }
        Some(star) => starred_pairs(&targets, &values, star, source),
    }
}

/// Positional pairing for a target list with one starred element, mirroring
/// Python's unpacking: targets before the star take values from the left,
/// targets after it take values from the right, and the starred name absorbs
/// every value in between (one fact per absorbed value, so taint in any of
/// them is preserved).
fn starred_pairs<'a>(
    targets: &[Node<'a>],
    values: &[Node<'a>],
    star: usize,
    source: &[u8],
) -> Option<Vec<(String, Node<'a>)>> {
    // A second star is a syntax error in Python; bail out to the fallback.
    if targets.iter().skip(star + 1).any(|t| t.kind() == "list_splat_pattern") {
        return None;
    }
    // Every fixed target must have a value (the star itself may take zero).
    if values.len() < targets.len() - 1 {
        return None;
    }
    let star_name = {
        let mut cursor = targets[star].walk();
        let id = targets[star].named_children(&mut cursor).find(|c| c.kind() == "identifier")?;
        get_node_text_slice(&id, source).to_string()
    };
    let after = targets.len() - star - 1;
    let mut pairs = Vec::with_capacity(values.len());
    for (t, v) in targets[..star].iter().zip(values.iter()) {
        if t.kind() != "identifier" {
            return None;
        }
        pairs.push((get_node_text_slice(t, source).to_string(), *v));
    }
    for (t, v) in targets[star + 1..].iter().zip(values[values.len() - after..].iter()) {
        if t.kind() != "identifier" {
            return None;
        }
        pairs.push((get_node_text_slice(t, source).to_string(), *v));
    }
    for v in &values[star..values.len() - after] {
        pairs.push((star_name.clone(), *v));
    }
    Some(pairs)
}

/// Named elements of a sequence node on either side of an assignment: a target
/// list/tuple pattern, or a value tuple, list literal, or bare `a, b`
/// expression list. A `list` value unpacks positionally exactly like a `tuple`,
/// so `a, b = [x, y]` pairs each name with its own element just as
/// `a, b = x, y` does — without it the whole list bleeds onto every target.
fn sequence_elements(node: Node) -> Option<Vec<Node>> {
    match node.kind() {
        "pattern_list" | "tuple_pattern" | "tuple" | "list" | "expression_list" => {
            let mut cursor = node.walk();
            Some(node.named_children(&mut cursor).filter(|c| c.kind() != "comment").collect())
        }
        _ => None,
    }
}

/// Identifier targets of an assignment left side. A subscript target
/// (`d[key] = v`) attributes the value to the container `d` — the container
/// received tainted data, matching the coverage the text scan provided
/// (per-key precision is future work :p ). Attribute targets (`obj.field`) are not
/// yet modeled. Tuple targets conservatively attribute the whole RHS to every
/// name they bind, descending into starred (`*rest`) and nested patterns so a
/// name is never silently dropped.
fn target_identifiers(node: Node, source: &[u8]) -> Vec<String> {
    match node.kind() {
        "identifier" => vec![get_node_text_slice(&node, source).to_string()],
        "pattern_list" | "tuple_pattern" | "list_pattern" | "list_splat_pattern" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .flat_map(|child| target_identifiers(child, source))
                .collect()
        }
        "subscript" => node
            .child_by_field_name("value")
            .filter(|value| value.kind() == "identifier")
            .map(|value| vec![get_node_text_slice(&value, source).to_string()])
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// For a mutating method call on a simple variable — `x.append(v)`, `x.add(v)`,
/// `x.extend(v)`, `x.update(v)`, `x.insert(i, v)` — return `(x, args_text)`.
/// Mutating a collection with tainted data taints the collection; callers
/// classify `args_text` to decide whether the mutation carries taint.
pub(crate) fn collection_mutation_target(node: Node, source: &[u8]) -> Option<(String, String)> {
    if node.kind() != "call" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    if function.kind() != "attribute" {
        return None;
    }
    let object = function.child_by_field_name("object")?;
    if object.kind() != "identifier" {
        return None;
    }
    let method_node = function.child_by_field_name("attribute")?;
    const MUTATORS: [&str; 5] = ["append", "add", "extend", "update", "insert"];
    if !MUTATORS.contains(&get_node_text_slice(&method_node, source)) {
        return None;
    }
    let arguments = node.child_by_field_name("arguments")?;
    let base = get_node_text_slice(&object, source).to_string();
    Some((base, normalized_text(arguments, source)))
}

fn normalized_text(node: Node, source: &[u8]) -> String {
    get_node_text_slice(&node, source).split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A string/number/bool/None literal. F-strings with interpolations are NOT
/// literals: their value embeds arbitrary expressions.
fn is_literal_expr(node: Node) -> bool {
    match node.kind() {
        "integer" | "float" | "true" | "false" | "none" => true,
        "string" => !has_interpolation(node),
        "concatenated_string" | "unary_operator" | "parenthesized_expression" => {
            all_named_children(node, is_literal_expr)
        }
        _ => false,
    }
}

/// A NON-EMPTY list/tuple/set/dict literal whose elements are all literals (or
/// nested literal collections): every possible value is developer-controlled.
/// Empty collections (`[]`, `{}`) are excluded — they carry no values and are
/// typically populated later (e.g. by a tainted subscript write or `.append`),
/// so treating them as safe would suppress that taint.
fn is_literal_collection(node: Node) -> bool {
    match node.kind() {
        "list" | "tuple" | "set" => {
            has_named_children(node)
                && all_named_children(node, |c| is_literal_expr(c) || is_literal_collection(c))
        }
        "dictionary" => {
            has_named_children(node)
                && all_named_children(node, |pair| {
                    pair.kind() == "pair" && all_named_children(pair, is_literal_expr)
                })
        }
        "parenthesized_expression" => all_named_children(node, is_literal_collection),
        _ => false,
    }
}

fn has_named_children(node: Node) -> bool {
    let mut cursor = node.walk();
    let any = node.named_children(&mut cursor).any(|c| c.kind() != "comment");
    any
}

fn all_named_children(node: Node, predicate: impl Fn(Node) -> bool) -> bool {
    let mut cursor = node.walk();
    let all = node.named_children(&mut cursor).filter(|c| c.kind() != "comment").all(&predicate);
    all
}

fn has_interpolation(node: Node) -> bool {
    if node.kind() == "interpolation" {
        return true;
    }
    let mut cursor = node.walk();
    let found = node.children(&mut cursor).any(has_interpolation);
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn staged(content: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("module.py");
        let mut file = std::fs::File::create(&path).expect("create fixture");
        file.write_all(content.as_bytes()).expect("write fixture");
        (dir, path.to_string_lossy().into_owned())
    }

    fn assignments(resolution: AstResolution) -> Vec<AssignmentFact> {
        match resolution {
            AstResolution::Assignments(facts) => facts,
            other => panic!("expected assignments, got {other:?}"),
        }
    }

    #[test]
    fn resolves_multiline_and_annotated_assignments() {
        let (_dir, path) =
            staged("def run():\n    cmd = (\n        input()\n    )\n    other: str = input()\n");
        let mut provenance = PythonAstProvenance::default();

        let cmd = assignments(provenance.resolve_variable(&path, "run", "cmd").unwrap());
        assert_eq!(cmd.len(), 1);
        assert_eq!(cmd[0].rhs, "( input() )");
        assert_eq!(cmd[0].line, 2);

        let other = assignments(provenance.resolve_variable(&path, "run", "other").unwrap());
        assert_eq!(other[0].rhs, "input()");
    }

    #[test]
    fn resolves_augmented_chained_and_tuple_targets() {
        let (_dir, path) = staged(
            "def run():\n    cmd = \"echo\"\n    cmd += input()\n    a = b = input()\n    x, y = input(), \"log\"\n",
        );
        let mut provenance = PythonAstProvenance::default();

        let cmd = assignments(provenance.resolve_variable(&path, "run", "cmd").unwrap());
        assert_eq!(cmd.len(), 2);
        assert!(!cmd[0].augmented);
        assert!(cmd[1].augmented);
        assert_eq!(cmd[1].rhs, "input()");

        let chained = assignments(provenance.resolve_variable(&path, "run", "b").unwrap());
        assert_eq!(chained[0].rhs, "input()");

        // Tuple unpacking pairs positionally: `x` gets `input()`, not the whole RHS.
        let tuple = assignments(provenance.resolve_variable(&path, "run", "x").unwrap());
        assert_eq!(tuple[0].rhs, "input()");
    }

    #[test]
    fn tuple_unpacking_pairs_each_target_with_its_own_value() {
        let (_dir, path) = staged("def run():\n    cmd, log_name = input(), \"app.log\"\n");
        let mut provenance = PythonAstProvenance::default();

        // The tainted element reaches `cmd`; the safe sibling `log_name` gets
        // only its own constant and must not inherit `input()`.
        let cmd = assignments(provenance.resolve_variable(&path, "run", "cmd").unwrap());
        assert_eq!(cmd[0].rhs, "input()");
        let log_name = assignments(provenance.resolve_variable(&path, "run", "log_name").unwrap());
        assert_eq!(log_name[0].rhs, "\"app.log\"");
    }

    #[test]
    fn tuple_unpacking_falls_back_conservatively_on_mismatch() {
        // RHS is a single call (not a sequence) and arity differs: both targets
        // conservatively receive the whole value so no taint is dropped.
        let (_dir, path) = staged("def run():\n    a, b = fetch_pair()\n    c, d, e = x, y\n");
        let mut provenance = PythonAstProvenance::default();

        let a = assignments(provenance.resolve_variable(&path, "run", "a").unwrap());
        assert_eq!(a[0].rhs, "fetch_pair()");
        let b = assignments(provenance.resolve_variable(&path, "run", "b").unwrap());
        assert_eq!(b[0].rhs, "fetch_pair()");
        let c = assignments(provenance.resolve_variable(&path, "run", "c").unwrap());
        assert_eq!(c[0].rhs, "x, y");
    }

    #[test]
    fn list_literal_rhs_pairs_positionally() {
        // A list literal on the RHS unpacks positionally exactly like a tuple:
        // `log_name` receives only its own constant and must not inherit
        // `input()` from the whole right-hand side.
        let (_dir, path) = staged("def run():\n    cmd, log_name = [input(), \"app.log\"]\n");
        let mut provenance = PythonAstProvenance::default();

        let cmd = assignments(provenance.resolve_variable(&path, "run", "cmd").unwrap());
        assert_eq!(cmd[0].rhs, "input()");
        let log_name = assignments(provenance.resolve_variable(&path, "run", "log_name").unwrap());
        assert_eq!(log_name[0].rhs, "\"app.log\"");
    }

    #[test]
    fn collection_mutation_is_recorded_as_reaching_fact() {
        // A non-empty literal initializer followed by a mutating call yields TWO
        // facts for `parts`: the literal init and the (augmented, non-literal)
        // `append`, so the resolver can no longer prove `parts` definitely-safe.
        let (_dir, path) =
            staged("def run():\n    parts = [\"prefix\"]\n    parts.append(input())\n");
        let mut provenance = PythonAstProvenance::default();

        let parts = assignments(provenance.resolve_variable(&path, "run", "parts").unwrap());
        assert_eq!(parts.len(), 2);
        assert!(parts[0].literal_collection && parts[0].literal_value);
        assert!(
            parts[1].augmented,
            "a mutation is inconclusive on its own, like an augmented write"
        );
        assert!(!parts[1].literal_value, "a tainted mutation is not developer-controlled");
        assert!(parts[1].rhs.contains("input("));
    }

    #[test]
    fn literal_collection_mutation_stays_literal() {
        // `parts.append("suffix")` keeps every value developer-controlled, so the
        // mutation fact stays literal and must not lose the safe verdict.
        let (_dir, path) =
            staged("def run():\n    parts = [\"prefix\"]\n    parts.append(\"suffix\")\n");
        let mut provenance = PythonAstProvenance::default();

        let parts = assignments(provenance.resolve_variable(&path, "run", "parts").unwrap());
        assert_eq!(parts.len(), 2);
        assert!(parts[1].augmented && parts[1].literal_value);
    }

    #[test]
    fn starred_targets_pair_around_the_star() {
        let (_dir, path) = staged(
            "def run():\n    head, *tail = \"safe\", input()\n    first, *mid, last = a, b, c, d\n",
        );
        let mut provenance = PythonAstProvenance::default();

        // `head` takes only its own element; the starred `tail` absorbs the
        // rest, one fact per absorbed value, so `input()` reaches `tail` and
        // never bleeds onto `head`.
        let head = assignments(provenance.resolve_variable(&path, "run", "head").unwrap());
        assert_eq!(head[0].rhs, "\"safe\"");
        let tail = assignments(provenance.resolve_variable(&path, "run", "tail").unwrap());
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].rhs, "input()");

        // Fixed targets after the star pair from the right; the star takes the
        // middle values.
        let first = assignments(provenance.resolve_variable(&path, "run", "first").unwrap());
        assert_eq!(first[0].rhs, "a");
        let last = assignments(provenance.resolve_variable(&path, "run", "last").unwrap());
        assert_eq!(last[0].rhs, "d");
        let mid = assignments(provenance.resolve_variable(&path, "run", "mid").unwrap());
        assert_eq!(mid.iter().map(|f| f.rhs.as_str()).collect::<Vec<_>>(), ["b", "c"]);
    }

    #[test]
    fn starred_fallback_never_drops_names() {
        // A non-sequence RHS defeats pairing; the whole value must then be
        // attributed to EVERY name in the target — including the starred one,
        // which a plain-identifier filter would silently drop.
        let (_dir, path) = staged("def run():\n    head, *tail = fetch_pair()\n");
        let mut provenance = PythonAstProvenance::default();

        let head = assignments(provenance.resolve_variable(&path, "run", "head").unwrap());
        assert_eq!(head[0].rhs, "fetch_pair()");
        let tail = assignments(provenance.resolve_variable(&path, "run", "tail").unwrap());
        assert_eq!(tail[0].rhs, "fetch_pair()");
    }

    #[test]
    fn value_side_splat_defeats_pairing() {
        // `*x` on the value side expands to an unknown number of elements, so
        // positions cannot be lined up; both targets keep the whole RHS.
        let (_dir, path) = staged("def run():\n    a, b = *x, y\n");
        let mut provenance = PythonAstProvenance::default();

        let a = assignments(provenance.resolve_variable(&path, "run", "a").unwrap());
        assert_eq!(a[0].rhs, "*x, y");
        let b = assignments(provenance.resolve_variable(&path, "run", "b").unwrap());
        assert_eq!(b[0].rhs, "*x, y");
    }

    #[test]
    fn assignments_below_the_usage_line_do_not_reach() {
        let (_dir, path) =
            staged("def run():\n    cmd = \"safe\"\n    os.system(cmd)\n    cmd = input()\n");
        let mut provenance = PythonAstProvenance::default();

        // At the sink on line 3 only the line-2 initializer has happened; the
        // later `cmd = input()` cannot be the value the sink observes.
        let at_sink = assignments(
            provenance.resolve_variable_reaching(&path, "run", "cmd", Some(3)).unwrap(),
        );
        assert_eq!(at_sink.len(), 1);
        assert_eq!(at_sink[0].rhs, "\"safe\"");

        // A use below the tainted assignment sees both facts.
        let below = assignments(
            provenance.resolve_variable_reaching(&path, "run", "cmd", Some(4)).unwrap(),
        );
        assert_eq!(below.len(), 2);
    }

    #[test]
    fn loop_carried_assignment_reaches_earlier_lines() {
        // The next iteration of the `while` carries line 4's value back to the
        // line-3 sink, so straight-line ordering must not filter it out.
        let (_dir, path) =
            staged("def run():\n    while True:\n        os.system(cmd)\n        cmd = input()\n");
        let mut provenance = PythonAstProvenance::default();

        let at_sink = assignments(
            provenance.resolve_variable_reaching(&path, "run", "cmd", Some(3)).unwrap(),
        );
        assert_eq!(at_sink.len(), 1);
        assert_eq!(at_sink[0].rhs, "input()");
    }

    #[test]
    fn parameter_wins_when_no_assignment_reaches_the_usage() {
        // At line 2 `cmd` still holds the parameter; the line-3 assignment has
        // not happened yet and no loop carries it back.
        let (_dir, path) = staged("def run(cmd):\n    os.system(cmd)\n    cmd = input()\n");
        let mut provenance = PythonAstProvenance::default();

        assert!(matches!(
            provenance.resolve_variable_reaching(&path, "run", "cmd", Some(2)),
            Some(AstResolution::Parameter { index: 0 })
        ));
    }

    #[test]
    fn literal_value_distinguishes_literal_and_variable_writes() {
        let (_dir, path) = staged(
            "def run():\n    cfg = [\"ls\", \"pwd\"]\n    cfg[0] = \"uptime\"\n    cfg[1] = user_supplied\n",
        );
        let mut provenance = PythonAstProvenance::default();

        let cfg = assignments(provenance.resolve_variable(&path, "run", "cfg").unwrap());
        assert_eq!(cfg.len(), 3);
        assert!(cfg[0].literal_collection && cfg[0].literal_value);
        assert!(cfg[1].literal_value, "a literal subscript write stays developer-controlled");
        assert!(!cfg[2].literal_value, "a variable subscript write is not developer-controlled");
    }

    #[test]
    fn for_loop_targets_keep_the_whole_iterable() {
        // `for a, b in x, y:` iterates the tuple (x, y), unpacking EACH element
        // into (a, b) — `a` can receive values from both `x` and `y`, so
        // positional pairing must not apply; each target keeps the whole
        // iterable and taint from either element is preserved.
        let (_dir, path) = staged("def run():\n    for a, b in x, input():\n        pass\n");
        let mut provenance = PythonAstProvenance::default();

        let a = assignments(provenance.resolve_variable(&path, "run", "a").unwrap());
        assert_eq!(a[0].rhs, "x, input()");
        let b = assignments(provenance.resolve_variable(&path, "run", "b").unwrap());
        assert_eq!(b[0].rhs, "x, input()");
    }

    #[test]
    fn duplicate_function_names_resolve_as_ambiguous() {
        let (_dir, path) = staged(
            "class Unsafe:\n    def run(self):\n        cmd = input()\nclass Safe:\n    def run(self):\n        cmd = \"uptime\"\n",
        );
        let mut provenance = PythonAstProvenance::default();

        // `run` is defined twice; the resolver reports Ambiguous explicitly so
        // callers treat the variable as unknown instead of falling back to a
        // text scan that would guess the first definition.
        assert!(matches!(
            provenance.resolve_variable(&path, "run", "cmd"),
            Some(AstResolution::Ambiguous)
        ));

        // A uniquely-named function still resolves normally.
        let (_dir2, path2) = staged("def only(self):\n    cmd = input()\n");
        assert!(matches!(
            provenance.resolve_variable(&path2, "only", "cmd"),
            Some(AstResolution::Assignments(_))
        ));
    }

    #[test]
    fn docstring_text_is_not_an_assignment() {
        let (_dir, path) = staged(
            "def run():\n    \"\"\"Usage:\n\n    cmd = input()\n    \"\"\"\n    cmd = \"uptime\"\n",
        );
        let mut provenance = PythonAstProvenance::default();

        let cmd = assignments(provenance.resolve_variable(&path, "run", "cmd").unwrap());
        assert_eq!(cmd.len(), 1);
        assert_eq!(cmd[0].rhs, "\"uptime\"");
        assert_eq!(cmd[0].line, 6);
    }

    #[test]
    fn async_functions_and_for_targets_resolve() {
        let (_dir, path) = staged(
            "async def report():\n    for flag in [\"beta\", \"canary\"]:\n        print(flag)\n",
        );
        let mut provenance = PythonAstProvenance::default();

        let flag = assignments(provenance.resolve_variable(&path, "report", "flag").unwrap());
        assert!(flag[0].literal_collection);
        assert_eq!(flag[0].rhs, "[\"beta\", \"canary\"]");
    }

    #[test]
    fn literal_collections_exclude_fstrings_and_variables() {
        let (_dir, path) = staged(
            "def run():\n    safe = [\"a\", 1, (\"b\",)]\n    unsafe_var = [name]\n    unsafe_fstring = [f\"{name}\"]\n",
        );
        let mut provenance = PythonAstProvenance::default();

        let safe = assignments(provenance.resolve_variable(&path, "run", "safe").unwrap());
        assert!(safe[0].literal_collection);
        let by_var = assignments(provenance.resolve_variable(&path, "run", "unsafe_var").unwrap());
        assert!(!by_var[0].literal_collection);
        let by_fstring =
            assignments(provenance.resolve_variable(&path, "run", "unsafe_fstring").unwrap());
        assert!(!by_fstring[0].literal_collection);
    }

    #[test]
    fn parameters_resolve_by_index_with_annotations_and_defaults() {
        let (_dir, path) = staged(
            "def handler(self, request: dict, timeout: int = 5, *args, **kwargs):\n    pass\n",
        );
        let mut provenance = PythonAstProvenance::default();

        for (name, index) in
            [("self", 0), ("request", 1), ("timeout", 2), ("args", 3), ("kwargs", 4)]
        {
            match provenance.resolve_variable(&path, "handler", name) {
                Some(AstResolution::Parameter { index: found }) => assert_eq!(found, index),
                other => panic!("{name} should resolve as parameter, got {other:?}"),
            }
        }
    }

    #[test]
    fn nested_function_locals_stay_out_of_the_outer_scope() {
        let (_dir, path) =
            staged("def outer():\n    def inner():\n        cmd = input()\n    cmd = \"safe\"\n");
        let mut provenance = PythonAstProvenance::default();

        let outer = assignments(provenance.resolve_variable(&path, "outer", "cmd").unwrap());
        assert_eq!(outer.len(), 1);
        assert_eq!(outer[0].rhs, "\"safe\"");
    }

    #[test]
    fn unknown_shapes_and_non_python_files_yield_none() {
        let (_dir, path) = staged("def run():\n    with open(\"f\") as handle:\n        pass\n");
        let mut provenance = PythonAstProvenance::default();

        assert!(provenance.resolve_variable(&path, "run", "handle").is_none());
        assert!(provenance.resolve_variable(&path, "missing_fn", "handle").is_none());
        assert!(provenance.resolve_variable("module.rb", "run", "handle").is_none());
    }

    #[test]
    fn subscript_target_attributes_value_to_the_container() {
        let (_dir, path) = staged("def run():\n    cfg = {}\n    cfg[\"name\"] = input(\"n: \")\n");
        let mut provenance = PythonAstProvenance::default();

        // `cfg` carries both the `{}` initializer and the tainted subscript write.
        let cfg = assignments(provenance.resolve_variable(&path, "run", "cfg").unwrap());
        assert_eq!(cfg.len(), 2);
        assert_eq!(cfg[0].rhs, "{}");
        assert!(!cfg[0].literal_collection, "empty dict must not be a literal collection");
        assert_eq!(cfg[1].rhs, "input(\"n: \")");
    }

    #[test]
    fn empty_collections_are_not_literal_collections() {
        let (_dir, path) =
            staged("def run():\n    a = []\n    b = {}\n    c = [\"x\"]\n    d = {\"k\": 1}\n");
        let mut provenance = PythonAstProvenance::default();

        for (name, expected) in [("a", false), ("b", false), ("c", true), ("d", true)] {
            let facts = assignments(provenance.resolve_variable(&path, "run", name).unwrap());
            assert_eq!(facts[0].literal_collection, expected, "{name} literal-collection");
        }
    }

    #[test]
    fn collection_mutation_targets_are_recognized() {
        let (_dir, path) = staged(
            "def run():\n    parts = []\n    parts.append(input(\"p: \"))\n    parts.extend(x)\n    other = obj.compute(y)\n",
        );
        let source = std::fs::read(&path).unwrap();
        let mut parser = LanguageParser::new("python").unwrap();
        let tree = parser.parse(&source).unwrap();

        let mut calls = Vec::new();
        collect_calls(tree.root_node(), &mut calls);
        let mutations: Vec<(String, String)> =
            calls.iter().filter_map(|c| collection_mutation_target(*c, &source)).collect();

        // append + extend are mutators; obj.compute is not.
        assert_eq!(mutations.len(), 2);
        assert_eq!(mutations[0], ("parts".to_string(), "(input(\"p: \"))".to_string()));
        assert_eq!(mutations[1].0, "parts");
    }

    fn collect_calls<'a>(node: Node<'a>, out: &mut Vec<Node<'a>>) {
        if node.kind() == "call" {
            out.push(node);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            collect_calls(child, out);
        }
    }
}
