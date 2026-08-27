use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::common::CommonUtils;

#[derive(Debug, Clone)]
pub(crate) struct TaintRuleDeduplicator {
    /// Mapping from (source_pattern, sink_pattern) to the rule that should handle it
    rule_mapping: std::collections::BTreeMap<(String, String), crate::rules::UnifiedRule>,
    /// Consolidated source patterns across all rules
    source_patterns: std::collections::BTreeSet<String>,
    /// Consolidated sink patterns across all rules
    pub(crate) sink_patterns: std::collections::BTreeSet<String>,
    /// Precalculated u64 hash fingerprint identifying this deduplicator rule set
    fingerprint: u64,
}

impl TaintRuleDeduplicator {
    /// Create a new deduplicator from a list of taint rules
    pub(crate) fn new(taint_rules: &[&crate::rules::UnifiedRule]) -> Self {
        let mut hasher = DefaultHasher::new();

        let mut deduplicator = Self {
            rule_mapping: std::collections::BTreeMap::new(),
            source_patterns: std::collections::BTreeSet::new(),
            sink_patterns: std::collections::BTreeSet::new(),
            fingerprint: 0,
        };

        // Process each rule and create specific source-sink mappings
        for rule in taint_rules {
            rule.id.hash(&mut hasher);
            rule.mode.hash(&mut hasher);
            if let Some(sources) = &rule.sources {
                sources.hash(&mut hasher);
            }
            if let Some(sinks) = &rule.sinks {
                sinks.hash(&mut hasher);
            }

            if let (Some(sources), Some(sinks)) = (&rule.sources, &rule.sinks) {
                // Add all patterns to consolidated sets
                for source in sources {
                    deduplicator.source_patterns.insert(source.clone());
                }
                for sink in sinks {
                    deduplicator.sink_patterns.insert(sink.clone());
                }

                // Create specific mappings for this rule's source-sink combinations
                for source in sources {
                    for sink in sinks {
                        let key = (source.clone(), sink.clone());
                        deduplicator.rule_mapping.insert(key, (*rule).clone());
                    }
                }
            }
        }

        deduplicator.fingerprint = hasher.finish();
        deduplicator
    }

    /// Return the precomputed rule set fingerprint
    pub(crate) fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    /// Get the specific rule for a source-sink combination
    pub(crate) fn get_rule_for_combination(
        &self,
        source_pattern: &str,
        sink_pattern: &str,
    ) -> Option<&crate::rules::UnifiedRule> {
        let key = (source_pattern.to_string(), sink_pattern.to_string());
        let result = self.rule_mapping.get(&key);

        if let Some(rule) = result {
            log::debug!("[RULE_SELECTION] Found rule for source='{}' + sink='{}' -> rule_id={:?}, finding_type={:?}", 
                source_pattern, sink_pattern, rule.id, rule.finding_type);
        } else {
            log::debug!("[RULE_SELECTION] No rule found for source='{}' + sink='{}'. Showing up to 5 mappings", 
                source_pattern, sink_pattern);
            for ((src, snk), rule) in self.rule_mapping.iter().take(5) {
                log::debug!("   - ('{}', '{}') -> {:?}", src, snk, rule.finding_type);
            }
            if self.rule_mapping.len() > 5 {
                log::debug!("   ... and {} more mappings", self.rule_mapping.len() - 5);
            }
        }

        result
    }

    /// Check if a pattern matches any source
    pub(crate) fn matches_source_pattern(&self, text: &str) -> Option<String> {
        log::debug!("[SOURCE_MATCH] Checking text: '{}'", text);
        for pattern in &self.source_patterns {
            if Self::is_bare_call_source_pattern(pattern)
                && !Self::matches_bare_call_source(pattern, text)
            {
                continue;
            }

            if CommonUtils::matches_taint_pattern(pattern, text) {
                log::debug!("[SOURCE_MATCH] Matched pattern: '{}' in text: '{}'", pattern, text);
                return Some(pattern.clone());
            }
        }
        log::debug!("[SOURCE_MATCH] No patterns matched for text: '{}'", text);
        None
    }

    /// Check if a pattern matches a source that is paired with the active sink
    pub(crate) fn matches_source_pattern_for_sink(
        &self,
        text: &str,
        sink_pattern: &str,
    ) -> Option<String> {
        if sink_pattern.is_empty() {
            return self.matches_source_pattern(text);
        }

        log::debug!("[SOURCE_MATCH] Checking text: '{}' for sink: '{}'", text, sink_pattern);
        for pattern in &self.source_patterns {
            if Self::is_bare_call_source_pattern(pattern)
                && !Self::matches_bare_call_source(pattern, text)
            {
                continue;
            }

            if CommonUtils::matches_taint_pattern(pattern, text) {
                // Verify this source-sink combination is valid in the deduplicator rules
                if self.get_rule_for_combination(pattern, sink_pattern).is_some() {
                    log::debug!(
                        "[SOURCE_MATCH] Matched pattern: '{}' for sink: '{}'",
                        pattern,
                        sink_pattern
                    );
                    return Some(pattern.clone());
                }
            }
        }
        log::debug!(
            "[SOURCE_MATCH] No patterns matched for text: '{}' and sink: '{}'",
            text,
            sink_pattern
        );
        None
    }

    fn is_bare_call_source_pattern(pattern: &str) -> bool {
        let Some(name) = pattern.strip_suffix('(') else {
            return false;
        };

        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || "_".contains(c))
    }

    fn matches_bare_call_source(pattern: &str, text: &str) -> bool {
        // Module qualifiers that alias Python builtins (e.g. `builtins.input(`,
        // `six.moves.input(`). These read as the bare source even though they
        // carry a dotted prefix, so they must survive the identifier-prefix guard.
        const BUILTIN_QUALIFIERS: [&str; 2] = ["builtins.", "six.moves."];

        let mut search_start = 0;
        while let Some(relative_pos) = text[search_start..].find(pattern) {
            let pos = search_start + relative_pos;
            let before = &text[..pos];
            let has_identifier_prefix = before
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() || "_.".contains(c));

            if !has_identifier_prefix || Self::has_builtin_qualifier(before, &BUILTIN_QUALIFIERS) {
                return true;
            }

            search_start = pos + pattern.len();
        }

        false
    }

    /// Whether the text preceding a bare-call pattern ends with a whitelisted
    /// builtin module qualifier that is itself bare. `builtins.input(` and
    /// `six.moves.input(` match; `obj.input(` and `mybuiltins.input(` do not.
    fn has_builtin_qualifier(before: &str, qualifiers: &[&str]) -> bool {
        qualifiers.iter().any(|qualifier| {
            before.strip_suffix(qualifier).is_some_and(|head| {
                head.chars()
                    .next_back()
                    .is_none_or(|c| !c.is_ascii_alphanumeric() && !"_.".contains(c))
            })
        })
    }

    /// Check if a pattern matches any sink
    pub(crate) fn matches_sink_pattern(&self, text: &str) -> Option<String> {
        log::debug!("[SINK_MATCH] Checking text: '{}'", text);
        for pattern in &self.sink_patterns {
            if CommonUtils::matches_taint_pattern(pattern, text) {
                log::debug!("[SINK_MATCH] Matched pattern: '{}' in text: '{}'", pattern, text);
                return Some(pattern.clone());
            }
        }
        log::debug!("[SINK_MATCH] No patterns matched for text: '{}'", text);
        None
    }
}

pub(crate) struct TaintExpressionUtils;

impl TaintExpressionUtils {
    pub(crate) fn normalize_variable(expression: &str) -> String {
        let trimmed =
            expression.trim().trim_end_matches(';').split_whitespace().last().unwrap_or("").trim();
        let trimmed = trimmed.trim_start_matches('$');
        let name: String =
            trimmed.chars().take_while(|c| c.is_ascii_alphanumeric() || "_".contains(*c)).collect();

        if CommonUtils::is_valid_variable_name(&name) {
            name
        } else {
            String::new()
        }
    }

    pub(crate) fn extract_php_variables(expression: &str) -> Vec<String> {
        let mut variables = Vec::new();
        let chars: Vec<char> = expression.chars().collect();
        let mut index = 0;

        while index < chars.len() {
            if chars[index] == '$' {
                let start = index + 1;
                let mut end = start;
                while end < chars.len()
                    && (chars[end].is_ascii_alphanumeric() || "_".contains(chars[end]))
                {
                    end += 1;
                }

                if end > start {
                    let name: String = chars[start..end].iter().collect();
                    if CommonUtils::is_valid_variable_name(&name) {
                        variables.push(name);
                    }
                }

                index = end;
            } else {
                index += 1;
            }
        }

        variables.sort();
        variables.dedup();
        variables
    }

    pub(crate) fn expression_has_sanitizer(
        rule: &crate::rules::UnifiedRule,
        expression: &str,
    ) -> bool {
        rule.sanitizers.as_ref().is_some_and(|sanitizers| {
            sanitizers.iter().any(|sanitizer| {
                let matched = expression.contains(sanitizer);
                if matched {
                    log::debug!(
                        "[SANITIZER_CHECK] Found sanitizer '{}' in sink: '{}'",
                        sanitizer,
                        expression
                    );
                }
                matched
            })
        })
    }

    pub(crate) fn expression_has_any_sanitizer(
        rules: &[&crate::rules::UnifiedRule],
        expression: &str,
    ) -> bool {
        rules.iter().any(|rule| Self::expression_has_sanitizer(rule, expression))
    }

    pub(crate) fn strip_inline_comment(expression: &str) -> &str {
        expression.split_once('#').map(|(code, _)| code.trim()).unwrap_or_else(|| expression.trim())
    }

    pub(crate) fn expression_references_variable(expression: &str, variable: &str) -> bool {
        let mut start = 0;
        while let Some(relative_pos) = expression[start..].find(variable) {
            let pos = start + relative_pos;
            let before = expression[..pos].chars().next_back();
            let after = expression[pos + variable.len()..].chars().next();
            let before_boundary =
                before.is_none_or(|c| !(c.is_ascii_alphanumeric() || "_".contains(c)));
            let after_boundary =
                after.is_none_or(|c| !(c.is_ascii_alphanumeric() || "_".contains(c)));

            if before_boundary && after_boundary {
                return true;
            }

            start = pos + variable.len();
        }

        false
    }
}
