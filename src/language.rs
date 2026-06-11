use anyhow::Result;
use tree_sitter::{Language, Node};
use crate::parser::get_node_text_slice;

pub trait LanguageSupport: Send + Sync {
    fn name(&self) -> &'static str;
    fn file_extension(&self) -> &'static str;
    fn tree_sitter_language(&self) -> Language;
    fn call_node_types(&self) -> &[&'static str];
    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str>;
    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>>;
}

pub fn get_language_support(language_name: &str) -> Result<Box<dyn LanguageSupport>> {
    match language_name.to_lowercase().as_str() {
        #[cfg(feature = "python")]
        "python" => Ok(Box::new(PythonLanguage)),
        #[cfg(feature = "java")]
        "java" => Ok(Box::new(JavaLanguage)),
        #[cfg(feature = "javascript")]
        "javascript" | "js" | "jsx" => Ok(Box::new(JavaScriptLanguage)),
        #[cfg(feature = "tsx")]
        "tsx" | "typescript-jsx" => Ok(Box::new(TSXLanguage)),
        #[cfg(feature = "typescript")]
        "typescript" => Ok(Box::new(TypeScriptLanguage)),
        #[cfg(feature = "go")]
        "go" => Ok(Box::new(GoLanguage)),
        #[cfg(feature = "ruby")]
        "ruby" => Ok(Box::new(RubyLanguage)),
        #[cfg(feature = "csharp")]
        "csharp" => Ok(Box::new(CSharpLanguage)),
        #[cfg(feature = "html")]
        "html" => Ok(Box::new(HTMLLanguage)),
        #[cfg(feature = "django")]
        "django" | "django-html" => Ok(Box::new(DjangoTemplateLanguage)),
        #[cfg(feature = "php")]
        "php" => Ok(Box::new(PHPLanguage)),
        _ => {
            let mut supported = Vec::new();
            #[cfg(feature = "python")]
            supported.push("python");
            #[cfg(feature = "java")]
            supported.push("java");
            #[cfg(feature = "javascript")]
            supported.push("javascript");
            #[cfg(feature = "tsx")]
            supported.push("tsx");
            #[cfg(feature = "typescript")]
            supported.push("typescript");
            #[cfg(feature = "go")]
            supported.push("go");
            #[cfg(feature = "ruby")]
            supported.push("ruby");
            #[cfg(feature = "csharp")]
            supported.push("csharp");
            #[cfg(feature = "html")]
            supported.push("html");
            #[cfg(feature = "django")]
            supported.push("django");
            #[cfg(feature = "php")]
            supported.push("php");

            anyhow::bail!(
                "Unsupported language: {}. Supported languages: {}",
                language_name,
                supported.join(", ")
            )
        }
    }
}

// Python Implementation
#[cfg(feature = "python")]
pub struct PythonLanguage;

#[cfg(feature = "python")]
impl LanguageSupport for PythonLanguage {
    fn name(&self) -> &'static str { "python" }
    fn file_extension(&self) -> &'static str { ".py" }
    fn tree_sitter_language(&self) -> Language { tree_sitter_python::LANGUAGE.into() }
    fn call_node_types(&self) -> &[&'static str] { &["call"] }

    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        node.child_by_field_name("function")
            .map(|child| get_node_text_slice(&child, source))
    }

    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        node.child_by_field_name("arguments")
    }
}

// Java Implementation
#[cfg(feature = "java")]
pub struct JavaLanguage;

#[cfg(feature = "java")]
impl LanguageSupport for JavaLanguage {
    fn name(&self) -> &'static str { "java" }
    fn file_extension(&self) -> &'static str { ".java" }
    fn tree_sitter_language(&self) -> Language { tree_sitter_java::LANGUAGE.into() }
    fn call_node_types(&self) -> &[&'static str] {
        &["method_invocation", "object_creation_expression"]
    }

    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        match node.kind() {
            "method_invocation" => {
                node.child_by_field_name("name")
                    .map(|child| get_node_text_slice(&child, source))
            }
            "object_creation_expression" => {
                node.child_by_field_name("type")
                    .map(|child| get_node_text_slice(&child, source))
            }
            _ => None
        }
    }

    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        node.child_by_field_name("arguments")
    }
}

// JavaScript Implementation
#[cfg(feature = "javascript")]
pub struct JavaScriptLanguage;

#[cfg(feature = "javascript")]
impl LanguageSupport for JavaScriptLanguage {
    fn name(&self) -> &'static str { "javascript" }
    fn file_extension(&self) -> &'static str { ".js" }
    fn tree_sitter_language(&self) -> Language { tree_sitter_javascript::LANGUAGE.into() }
    fn call_node_types(&self) -> &[&'static str] {
        &["call_expression", "new_expression"]
    }

    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        match node.kind() {
            "call_expression" => {
                node.child_by_field_name("function")
                    .map(|child| get_node_text_slice(&child, source))
            }
            "new_expression" => {
                node.child_by_field_name("constructor")
                    .map(|child| get_node_text_slice(&child, source))
            }
            _ => None
        }
    }

    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        node.child_by_field_name("arguments")
    }
}

// TSX Implementation
#[cfg(feature = "tsx")]
pub struct TSXLanguage;

#[cfg(feature = "tsx")]
impl LanguageSupport for TSXLanguage {
    fn name(&self) -> &'static str { "tsx" }
    fn file_extension(&self) -> &'static str { ".tsx" } // Primary extension, but handles both .ts and .tsx
    fn tree_sitter_language(&self) -> Language { tree_sitter_typescript::LANGUAGE_TSX.into() }
    fn call_node_types(&self) -> &[&'static str] {
        &["call_expression", "new_expression", "jsx_expression", "jsx_attribute"]
    }

    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        match node.kind() {
            "jsx_attribute" => {
                node.child_by_field_name("name")
                    .map(|child| get_node_text_slice(&child, source))
            }
            "call_expression" => {
                node.child_by_field_name("function")
                    .map(|child| get_node_text_slice(&child, source))
            }
            "new_expression" => {
                node.child_by_field_name("constructor")
                    .map(|child| get_node_text_slice(&child, source))
            }
            _ => None
        }
    }

    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        node.child_by_field_name("arguments")
            .or_else(|| node.child_by_field_name("value"))
    }
}

// TypeScript Implementation
#[cfg(feature = "typescript")]
pub struct TypeScriptLanguage;

#[cfg(feature = "typescript")]
impl LanguageSupport for TypeScriptLanguage {
    fn name(&self) -> &'static str { "typescript" }
    fn file_extension(&self) -> &'static str { ".ts" }
    fn tree_sitter_language(&self) -> Language { tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into() }
    fn call_node_types(&self) -> &[&'static str] {
        &["call_expression", "new_expression"]
    }

    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        match node.kind() {
            "call_expression" => {
                node.child_by_field_name("function")
                    .map(|child| get_node_text_slice(&child, source))
            }
            "new_expression" => {
                node.child_by_field_name("constructor")
                    .map(|child| get_node_text_slice(&child, source))
            }
            _ => None
        }
    }

    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        node.child_by_field_name("arguments")
    }
}

// Go Implementation
#[cfg(feature = "go")]
pub struct GoLanguage;

#[cfg(feature = "go")]
impl LanguageSupport for GoLanguage {
    fn name(&self) -> &'static str { "go" }
    fn file_extension(&self) -> &'static str { ".go" }
    fn tree_sitter_language(&self) -> Language { tree_sitter_go::LANGUAGE.into() }
    fn call_node_types(&self) -> &[&'static str] { &["call_expression"] }

    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        node.child_by_field_name("function").map(|function| {
            if function.kind() == "selector_expression" {
                function
                    .child_by_field_name("field")
                    .map(|field| get_node_text_slice(&field, source))
                    .unwrap_or_else(|| get_node_text_slice(&function, source))
            } else {
                get_node_text_slice(&function, source)
            }
        })
    }

    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        node.child_by_field_name("arguments")
    }
}

// Ruby Implementation
#[cfg(feature = "ruby")]
pub struct RubyLanguage;

#[cfg(feature = "ruby")]
impl LanguageSupport for RubyLanguage {
    fn name(&self) -> &'static str { "ruby" }
    fn file_extension(&self) -> &'static str { ".rb" }
    fn tree_sitter_language(&self) -> Language { tree_sitter_ruby::LANGUAGE.into() }
    fn call_node_types(&self) -> &[&'static str] { &["method_call", "call"] }

    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        match node.kind() {
            "method_call" | "call" => {
                node.child_by_field_name("method")
                    .map(|child| get_node_text_slice(&child, source))
            }
            _ => None
        }
    }

    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        node.child_by_field_name("arguments")
    }
}

// C# Implementation
#[cfg(feature = "csharp")]
pub struct CSharpLanguage;

#[cfg(feature = "csharp")]
impl LanguageSupport for CSharpLanguage {
    fn name(&self) -> &'static str { "csharp" }
    fn file_extension(&self) -> &'static str { ".cs" }
    fn tree_sitter_language(&self) -> Language { tree_sitter_c_sharp::LANGUAGE.into() }
    fn call_node_types(&self) -> &[&'static str] {
        &["invocation_expression", "object_creation_expression"]
    }

    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        match node.kind() {
            // `invocation_expression` exposes the callee under the `function` field
            // (there is no `name` field). For `obj.Method(...)` the function is a
            // `member_access_expression`; resolve its `name` child so method-name
            // rules match. Plain `Method(...)` has an identifier function.
            "invocation_expression" => {
                node.child_by_field_name("function").map(|func| {
                    if func.kind() == "member_access_expression" {
                        func.child_by_field_name("name")
                            .map(|name| get_node_text_slice(&name, source))
                            .unwrap_or_else(|| get_node_text_slice(&func, source))
                    } else {
                        get_node_text_slice(&func, source)
                    }
                })
            }
            "object_creation_expression" => {
                node.child_by_field_name("type")
                    .map(|child| get_node_text_slice(&child, source))
            }
            _ => None
        }
    }

    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        node.child_by_field_name("argument_list")
    }
}

// PHP Implementation
#[cfg(feature = "php")]
pub struct PHPLanguage;

#[cfg(feature = "php")]
impl LanguageSupport for PHPLanguage {
    fn name(&self) -> &'static str { "php" }
    fn file_extension(&self) -> &'static str { ".php" }
    fn tree_sitter_language(&self) -> Language { tree_sitter_php::LANGUAGE_PHP.into() }
    fn call_node_types(&self) -> &[&'static str] {
        &[
            "function_call_expression",
            "member_call_expression",
            "nullsafe_member_call_expression",
            "scoped_call_expression",
            "object_creation_expression",
        ]
    }

    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        match node.kind() {
            // foo(...) / namespaced\foo(...)
            "function_call_expression" => node
                .child_by_field_name("function")
                .map(|child| get_node_text_slice(&child, source)),
            // $obj->method(...) / $obj?->method(...) / Class::method(...)
            "member_call_expression"
            | "nullsafe_member_call_expression"
            | "scoped_call_expression" => node
                .child_by_field_name("name")
                .map(|child| get_node_text_slice(&child, source)),
            // new Class(...)
            "object_creation_expression" => node
                .named_child(0)
                .map(|child| get_node_text_slice(&child, source)),
            _ => None,
        }
    }

    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        node.child_by_field_name("arguments")
    }
}

// HTML Implementation
#[cfg(feature = "html")]
pub struct HTMLLanguage;

#[cfg(feature = "html")]
impl LanguageSupport for HTMLLanguage {
    fn name(&self) -> &'static str { "html" }
    fn file_extension(&self) -> &'static str { ".html" }
    fn tree_sitter_language(&self) -> Language { tree_sitter_html::LANGUAGE.into() }
    fn call_node_types(&self) -> &[&'static str] {
        &["attribute", "start_tag", "script_element", "element"]
    }

    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        // The tree-sitter HTML grammar (v0.23) does not label child nodes with
        // fields, so `child_by_field_name` returns None for attributes/tags. Fall
        // back to the named child (`attribute_name` / `tag_name`) so directive
        // names like `th:utext`, `th:replace`, or tag names like `textarea`
        // resolve as the matchable "function" name for search rules.
        match node.kind() {
            "attribute" => {
                node.child_by_field_name("name")
                    .or_else(|| crate::common::CommonUtils::find_child(node, |c| c.kind() == "attribute_name"))
                    .map(|child| get_node_text_slice(&child, source))
            }
            "start_tag" | "element" => {
                node.child_by_field_name("name")
                    .or_else(|| crate::common::CommonUtils::find_child(node, |c| c.kind() == "tag_name"))
                    .map(|child| get_node_text_slice(&child, source))
            }
            "script_element" => {
                Some("script")
            }
            _ => None
        }
    }

    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        if node.kind() == "attribute" {
            if let Some(value_node) = node.child_by_field_name("value") {
                return Some(value_node);
            }

            // Fallback: look for value-like children
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    match child.kind() {
                        "attribute_value" | "quoted_attribute_value" | "string" => {
                            return Some(child);
                        }
                        _ => continue,
                    }
                }
            }
        }

        node.child_by_field_name("value")
    }
}

// Django Template Implementation
#[cfg(feature = "django")]
pub struct DjangoTemplateLanguage;

#[cfg(feature = "django")]
impl LanguageSupport for DjangoTemplateLanguage {
    fn name(&self) -> &'static str { "django" }
    fn file_extension(&self) -> &'static str { ".html" }
    fn tree_sitter_language(&self) -> Language { tree_sitter_html::LANGUAGE.into() }
    fn call_node_types(&self) -> &[&'static str] {
        &["attribute", "text", "script_element"]
    }

    fn get_function_name<'a>(&self, node: &Node, source: &'a [u8]) -> Option<&'a str> {
        match node.kind() {
            "text" => {
                let text = get_node_text_slice(node, source);

                // Check for Django template patterns (return static strings for consistent lifetimes)
                if text.contains("|safe") {
                    Some("|safe")
                } else if text.contains("|mark_safe") {
                    Some("|mark_safe")
                } else if text.contains("{% autoescape off %}") {
                    Some("{% autoescape off %}")
                } else if text.contains("{{") && text.contains("}}") {
                    Some("{{")}
                else if text.contains("{% include") {
                    Some("{% include")
                } else if text.contains("{{") || text.contains("{%") {
                    Some("django_template")
                } else {
                    None
                }
            }
            "attribute" => {
                node.child_by_field_name("name")
                    .map(|child| get_node_text_slice(&child, source))
            }
            "script_element" => {
                Some("script")
            }
            _ => None
        }
    }

    fn get_arguments_node<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        match node.kind() {
            "text" => Some(*node),
            "attribute" => {
                if let Some(value_node) = node.child_by_field_name("value") {
                    return Some(value_node);
                }
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        match child.kind() {
                            "attribute_value" | "quoted_attribute_value" | "string" => {
                                return Some(child);
                            }
                            _ => continue,
                        }
                    }
                }
                None
            }
            _ => node.child_by_field_name("value")
        }
    }
}