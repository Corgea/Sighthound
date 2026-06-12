use crate::language::{get_language_support, LanguageSupport};
use anyhow::{Context, Result};
use tree_sitter::{Node, Parser as TSParser, Tree};

pub struct LanguageParser {
    parser: TSParser,
    language_support: Box<dyn LanguageSupport>,
}

impl LanguageParser {
    pub fn new(language_name: &str) -> Result<Self> {
        let language_support = get_language_support(language_name)?;
        let language = language_support.tree_sitter_language();
        let mut parser = TSParser::new();
        parser
            .set_language(&language)
            .context("Failed to set language")?;

        Ok(Self {
            parser,
            language_support,
        })
    }

    pub fn parse(&mut self, source: &[u8]) -> Result<Tree> {
        self.parser
            .parse(source, None)
            .context("Failed to parse file")
    }

    pub fn file_extension(&self) -> &str {
        self.language_support.file_extension()
    }

    pub fn language_support(&self) -> &dyn LanguageSupport {
        self.language_support.as_ref()
    }
}

// Generic function to get node text
pub fn get_node_text(node: &Node, source: &[u8]) -> String {
    let start = node.start_byte();
    let end = node.end_byte();
    String::from_utf8_lossy(&source[start..end]).to_string()
}

// Memory-optimized version that returns a string slice instead of owned String
pub fn get_node_text_slice<'a>(node: &Node, source: &'a [u8]) -> &'a str {
    let start = node.start_byte();
    let end = node.end_byte();
    std::str::from_utf8(&source[start..end]).unwrap_or("")
}

// Language-agnostic tree traversal
pub fn traverse_calls_only<'a>(
    node: Node<'a>,
    language_support: &'a dyn LanguageSupport,
) -> impl Iterator<Item = Node<'a>> + 'a {
    let call_types = language_support.call_node_types();
    TreeCallIterator::new(node, call_types)
}

struct TreeCallIterator<'a> {
    stack: Vec<Node<'a>>,
    call_types: &'a [&'static str],
}

impl<'a> TreeCallIterator<'a> {
    fn new(root: Node<'a>, call_types: &'a [&'static str]) -> Self {
        Self {
            stack: vec![root],
            call_types,
        }
    }
}

impl<'a> Iterator for TreeCallIterator<'a> {
    type Item = Node<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(node) = self.stack.pop() {
            // Add children to stack for traversal
            let mut cursor = node.walk();
            if cursor.goto_first_child() {
                loop {
                    self.stack.push(cursor.node());
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }

            // Return if this node type is a call node for the current language
            if self.call_types.contains(&node.kind()) {
                return Some(node);
            }
        }
        None
    }
}
