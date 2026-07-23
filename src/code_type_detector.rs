use crate::parser;
use std::collections::{HashMap, HashSet};
use tree_sitter::{Node, Tree};

#[derive(Debug, Clone, PartialEq)]
pub enum CodeType {
    Frontend,
    Backend,
    Both,
    Unknown,
}

impl CodeType {
    pub fn from_string(s: &str) -> Option<CodeType> {
        match s.to_lowercase().as_str() {
            "frontend" => Some(CodeType::Frontend),
            "backend" => Some(CodeType::Backend),
            "both" => Some(CodeType::Both),
            _ => None,
        }
    }

    pub fn matches_filter(&self, filter: &CodeType) -> bool {
        match filter {
            CodeType::Both => true,
            CodeType::Unknown => true,
            _ => self == filter || *self == CodeType::Both,
        }
    }
}

pub struct FrameworkRegistry {
    frameworks: HashMap<&'static str, FrameworkInfo>,
}

#[derive(Debug, Clone)]
struct FrameworkInfo {
    signatures: Vec<&'static str>,
    code_type: CodeType,
}

impl Default for FrameworkRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Signature list for frontend frameworks, keyed by framework name.
fn frontend_framework_signatures() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        ("React", vec!["react", "react-dom"]),
        ("Next.js", vec!["next/link", "next/router", "next/head", "@next/"]),
        ("Angular", vec!["@angular/core"]),
        ("Vue", vec!["vue", "vue-router"]),
        ("Nuxt.js", vec!["nuxt", "@nuxtjs", "@nuxt/"]),
        ("Svelte", vec!["svelte"]),
        ("SvelteKit", vec!["@sveltejs/kit"]),
        ("SolidJS", vec!["solid-js"]),
        ("Qwik", vec!["@builder.io/qwik"]),
        ("Ember", vec!["@ember"]),
        ("Remix", vec!["@remix-run"]),
        ("Astro", vec!["astro", "@astrojs/"]),
        ("Gatsby", vec!["gatsby"]),
        ("jQuery", vec!["jquery"]),
        ("HTMX", vec!["htmx", "hx-"]),
        ("Alpine.js", vec!["alpinejs", "alpine.js", "x-data"]),
        ("Stimulus", vec!["@hotwired/stimulus"]),
        ("TailwindCSS", vec!["tailwindcss"]),
        ("Styled Components", vec!["styled-components"]),
        ("Emotion", vec!["@emotion"]),
        ("Material-UI", vec!["@mui/material", "@material-ui/core"]),
        ("Ant Design", vec!["antd"]),
        ("Chakra UI", vec!["@chakra-ui"]),
        ("Redux", vec!["redux", "@reduxjs/toolkit"]),
        ("Zustand", vec!["zustand"]),
        ("Jotai", vec!["jotai"]),
        ("Recoil", vec!["recoil"]),
        ("MobX", vec!["mobx"]),
        ("Pinia", vec!["pinia"]),
        ("TanStack Query", vec!["@tanstack/react-query", "@tanstack/vue-query"]),
        ("SWR", vec!["swr"]),
        ("Vite", vec!["vite", "@vitejs/"]),
        ("Webpack", vec!["webpack"]),
        ("Rollup", vec!["rollup"]),
        ("Parcel", vec!["parcel"]),
        ("esbuild", vec!["esbuild"]),
        ("SWC", vec!["@swc/"]),
        ("Turbopack", vec!["turbopack"]),
        ("Rspack", vec!["@rspack/"]),
        ("Jest", vec!["jest"]),
        ("Vitest", vec!["vitest", "@vitest/"]),
        ("Cypress", vec!["cypress"]),
        ("Playwright", vec!["playwright"]),
        ("Testing Library", vec!["@testing-library/"]),
        ("Storybook", vec!["@storybook/"]),
        ("TensorFlow.js", vec!["@tensorflow/tfjs"]),
        ("ML5.js", vec!["ml5"]),
        ("Brain.js", vec!["brain.js"]),
        ("Synaptic", vec!["synaptic"]),
        ("Web3.js", vec!["web3"]),
        ("Ethers.js", vec!["ethers"]),
        ("Wagmi", vec!["wagmi"]),
        ("RainbowKit", vec!["@rainbow-me/rainbowkit"]),
        ("Moralis", vec!["moralis"]),
        ("React Native", vec!["react-native"]),
        ("Expo", vec!["expo", "@expo/"]),
        ("Tauri", vec!["@tauri-apps/tauri"]),
        ("Capacitor", vec!["@capacitor/core"]),
        ("D3", vec!["d3"]),
        ("Backbone", vec!["backbone"]),
        ("Underscore", vec!["underscore"]),
        ("Tipped", vec!["tipped"]),
    ]
}

/// Signature list for backend frameworks, keyed by framework name.
fn backend_framework_signatures() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        ("Express", vec!["express"]),
        ("Koa", vec!["koa"]),
        ("Fastify", vec!["fastify"]),
        ("NestJS", vec!["@nestjs/common", "@nestjs/core"]),
        ("Hapi", vec!["@hapi/hapi"]),
        ("Hono", vec!["hono"]),
        ("tRPC", vec!["@trpc/server", "@trpc/client"]),
        ("Elysia", vec!["elysia"]),
        ("Prisma", vec!["prisma", "@prisma/client"]),
        ("Drizzle", vec!["drizzle-orm"]),
        ("TypeORM", vec!["typeorm"]),
        ("Sequelize", vec!["sequelize"]),
        ("Mongoose", vec!["mongoose"]),
        ("Knex", vec!["knex"]),
        ("MikroORM", vec!["@mikro-orm/core"]),
        ("Vercel", vec!["@vercel/node", "@vercel/edge"]),
        ("Netlify", vec!["@netlify/functions"]),
        ("Cloudflare Workers", vec!["@cloudflare/workers-types"]),
        ("AWS Lambda", vec!["aws-lambda"]),
        ("Auth0", vec!["auth0", "@auth0/nextjs-auth0"]),
        ("Supabase", vec!["@supabase/supabase-js"]),
        ("Firebase", vec!["firebase"]),
        ("Clerk", vec!["@clerk/nextjs"]),
        ("NextAuth", vec!["next-auth"]),
        ("Cheerio", vec!["cheerio"]),
    ]
}

impl FrameworkRegistry {
    pub fn new() -> Self {
        let mut frameworks = HashMap::new();

        for (name, sigs) in frontend_framework_signatures() {
            frameworks
                .insert(name, FrameworkInfo { signatures: sigs, code_type: CodeType::Frontend });
        }

        for (name, sigs) in backend_framework_signatures() {
            frameworks
                .insert(name, FrameworkInfo { signatures: sigs, code_type: CodeType::Backend });
        }

        Self { frameworks }
    }

    pub fn get_frontend_signatures(&self) -> HashSet<String> {
        self.frameworks
            .values()
            .filter(|info| info.code_type == CodeType::Frontend)
            .flat_map(|info| info.signatures.iter())
            .map(|s| s.to_lowercase())
            .collect()
    }

    pub fn get_backend_signatures(&self) -> HashSet<String> {
        self.frameworks
            .values()
            .filter(|info| info.code_type == CodeType::Backend)
            .flat_map(|info| info.signatures.iter())
            .map(|s| s.to_lowercase())
            .collect()
    }

    pub fn detect_from_frameworks(&self, imports: &[String]) -> CodeType {
        let mut frontend_matches = 0;
        let mut backend_matches = 0;

        for info in self.frameworks.values() {
            let has_match = info.signatures.iter().any(|sig| {
                imports.iter().any(|imp| imp.to_lowercase().contains(&sig.to_lowercase()))
            });

            if has_match {
                match info.code_type {
                    CodeType::Frontend => frontend_matches += 1,
                    CodeType::Backend => backend_matches += 1,
                    _ => {}
                }
            }
        }

        if frontend_matches > 0 && backend_matches == 0 {
            CodeType::Frontend
        } else if backend_matches > 0 && frontend_matches == 0 {
            CodeType::Backend
        } else if frontend_matches > 0 && backend_matches > 0 {
            CodeType::Both
        } else {
            CodeType::Unknown
        }
    }
}

pub struct CodeTypeDetector {
    framework_registry: FrameworkRegistry,
}

impl CodeTypeDetector {
    pub fn new() -> Self {
        Self { framework_registry: FrameworkRegistry::new() }
    }

    pub fn detect_code_type(&self, _file_path: &str, content: &str, language: &str) -> CodeType {
        // First try framework detection
        let imports = self.extract_imports(content, language);
        let framework_result = self.framework_registry.detect_from_frameworks(&imports);

        if framework_result != CodeType::Unknown {
            return framework_result;
        }

        // Then try AST analysis for JavaScript/TypeScript
        if matches!(language.to_lowercase().as_str(), "javascript" | "typescript" | "tsx") {
            if let Ok(mut parser) = crate::parser::LanguageParser::new(language) {
                if let Ok(tree) = parser.parse(content.as_bytes()) {
                    let ast_result = self.detect_from_ast(&tree, content.as_bytes());
                    if ast_result != CodeType::Unknown {
                        return ast_result;
                    }
                }
            }
        }

        // Import-based detection
        let import_result = self.detect_from_imports(&imports);
        if import_result != CodeType::Unknown {
            return import_result;
        }

        // Default fallback based on language
        match language.to_lowercase().as_str() {
            "javascript" | "typescript" | "tsx" | "jsx" => CodeType::Frontend,
            "python" | "java" | "rust" | "go" | "php" | "ruby" | "objectscript" | "c" | "cpp"
            | "c#" | "csharp" => CodeType::Backend,
            _ => CodeType::Unknown,
        }
    }

    fn extract_imports(&self, content: &str, _language: &str) -> Vec<String> {
        let mut imports = Vec::new();

        // Extract require() calls
        let require_patterns = vec![
            regex::Regex::new(r#"require\(\s*['"]([^'"]+)['"]\s*\)"#).unwrap(),
            regex::Regex::new(r#"import\s+.*from\s+['"]([^'"]+)['"]"#).unwrap(),
            regex::Regex::new(r#"import\s*\(\s*['"]([^'"]+)['"]\s*\)"#).unwrap(),
        ];

        for pattern in require_patterns {
            for cap in pattern.captures_iter(content) {
                if let Some(module) = cap.get(1) {
                    imports.push(module.as_str().to_lowercase());
                }
            }
        }

        imports
    }

    fn detect_from_ast(&self, tree: &Tree, source: &[u8]) -> CodeType {
        let mut frontend_score = 0;
        let mut backend_score = 0;

        // Frontend signals
        frontend_score += self.score_frontend_signals(tree, source);

        // Backend signals
        backend_score += self.score_backend_signals(tree, source);

        if frontend_score > 0 && backend_score == 0 {
            CodeType::Frontend
        } else if backend_score > 0 && (frontend_score == 0 || backend_score > frontend_score) {
            CodeType::Backend
        } else if frontend_score > backend_score {
            CodeType::Frontend
        } else {
            CodeType::Unknown
        }
    }

    fn score_frontend_signals(&self, tree: &Tree, source: &[u8]) -> i32 {
        let mut score = 0;
        let root_node = tree.root_node();

        // DOM methods
        let dom_methods = vec![
            "getElementById",
            "getElementsByClassName",
            "querySelector",
            "querySelectorAll",
            "createElement",
            "appendChild",
            "addEventListener",
        ];

        // Browser objects
        let browser_objects = vec![
            "document",
            "window",
            "navigator",
            "localStorage",
            "sessionStorage",
            "location",
            "history",
            "screen",
        ];

        // React hooks
        let react_hooks =
            vec!["useState", "useEffect", "useContext", "useReducer", "useMemo", "useCallback"];

        // Check for call expressions
        Self::walk_tree(&root_node, &mut |node| {
            if node.kind() == "call_expression" {
                let text = parser::get_node_text(&node, source);

                // Check for DOM methods
                for method in &dom_methods {
                    if text.contains(method) {
                        score += 2;
                    }
                }

                // Check for React hooks
                for hook in &react_hooks {
                    if text.contains(hook) {
                        score += 2;
                    }
                }

                // Check for jQuery
                if text.starts_with("$") || text.contains("jQuery") {
                    score += 2;
                }
            }

            // Check for member expressions with browser objects
            if node.kind() == "member_expression" {
                let text = parser::get_node_text(&node, source);
                for obj in &browser_objects {
                    if text.starts_with(obj) {
                        score += 1;
                    }
                }
            }

            // Check for JSX
            if node.kind().starts_with("jsx_") {
                score += 3;
            }
        });

        score
    }

    fn score_backend_signals(&self, tree: &Tree, source: &[u8]) -> i32 {
        let mut score = 0;
        let root_node = tree.root_node();

        // Node.js core modules
        let core_modules = vec!["fs", "path", "http", "https", "crypto", "os", "util", "events"];

        // Node.js globals
        let node_globals = vec!["__dirname", "__filename", "module", "exports", "process"];

        // Server methods
        let server_methods = vec!["get", "post", "put", "delete", "patch", "use", "listen"];

        Self::walk_tree(&root_node, &mut |node| {
            if node.kind() == "call_expression" {
                let text = parser::get_node_text(&node, source);

                // Check for require calls with core modules
                if text.starts_with("require(") {
                    for module in &core_modules {
                        if text.contains(&format!("'{}'", module))
                            || text.contains(&format!("\"{}\"", module))
                        {
                            score += 3;
                        }
                    }
                }

                // Check for server methods
                for method in &server_methods {
                    if text.contains(&format!(".{}(", method)) {
                        score += 2;
                    }
                }
            }

            // Check for Node.js globals
            if node.kind() == "identifier" {
                let text = parser::get_node_text(&node, source);
                for global in &node_globals {
                    if text == *global {
                        score += 1;
                    }
                }
            }
        });

        score
    }

    fn detect_from_imports(&self, imports: &[String]) -> CodeType {
        let frontend_sigs = self.framework_registry.get_frontend_signatures();
        let backend_sigs = self.framework_registry.get_backend_signatures();

        let frontend_matches =
            imports.iter().filter(|imp| frontend_sigs.iter().any(|sig| imp.contains(sig))).count();

        let backend_matches =
            imports.iter().filter(|imp| backend_sigs.iter().any(|sig| imp.contains(sig))).count();

        if frontend_matches > 0 && backend_matches == 0 {
            CodeType::Frontend
        } else if backend_matches > 0 && frontend_matches == 0 {
            CodeType::Backend
        } else if frontend_matches > 0 && backend_matches > 0 {
            CodeType::Both
        } else {
            CodeType::Unknown
        }
    }

    fn walk_tree<F>(node: &Node, callback: &mut F)
    where
        F: FnMut(Node),
    {
        callback(*node);

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            Self::walk_tree(&child, callback);
        }
    }
}

impl Default for CodeTypeDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `detect_from_imports` is only reached from `detect_code_type` after framework
    // detection already returned `Unknown` for the very same imports, which (given
    // both use the same signature pool) means its non-Unknown branches are not
    // reachable through the public entry point. Call it directly to cover them.

    #[test]
    fn detect_from_imports_frontend_only() {
        let detector = CodeTypeDetector::new();
        let imports = vec!["react".to_string()];
        assert_eq!(detector.detect_from_imports(&imports), CodeType::Frontend);
    }

    #[test]
    fn detect_from_imports_backend_only() {
        let detector = CodeTypeDetector::new();
        let imports = vec!["express".to_string()];
        assert_eq!(detector.detect_from_imports(&imports), CodeType::Backend);
    }

    #[test]
    fn detect_from_imports_both() {
        let detector = CodeTypeDetector::new();
        let imports = vec!["react".to_string(), "express".to_string()];
        assert_eq!(detector.detect_from_imports(&imports), CodeType::Both);
    }

    #[test]
    fn detect_from_imports_unknown_when_no_signature_matches() {
        let detector = CodeTypeDetector::new();
        let imports = vec!["totally-unrelated-package".to_string()];
        assert_eq!(detector.detect_from_imports(&imports), CodeType::Unknown);
    }

    #[test]
    fn detect_from_ast_finds_nested_backend_signal() {
        let source = br#"
            function loadConfig() {
                if (process.env.NODE_ENV) {
                    return require("fs").readFileSync("config.json");
                }
            }
        "#;
        let mut parser = crate::parser::LanguageParser::new("javascript").unwrap();
        let tree = parser.parse(source).unwrap();
        let detector = CodeTypeDetector::new();

        assert_eq!(detector.detect_from_ast(&tree, source), CodeType::Backend);
    }
}
