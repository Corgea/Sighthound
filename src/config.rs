/// Centralized configuration constants for the scanner
pub struct ScanDefaults;

impl ScanDefaults {
    /// Chunk size for parallel file processing (tuned for disk I/O)
    pub const CHUNK_SIZE: usize = 64;

    /// Progress update interval in milliseconds
    pub const PROGRESS_INTERVAL_MS: u64 = 100;

    /// Estimated files per language for capacity planning
    pub const ESTIMATED_FILES_PER_LANG: usize = 50;

    /// Maximum AST traversal depth to prevent infinite recursion
    pub const MAX_AST_DEPTH: usize = 20;

    /// Maximum file size to process (10MB)
    pub const MAX_FILE_SIZE: usize = 10 * 1024 * 1024;

    /// Estimated languages for HashMap capacity
    pub const ESTIMATED_LANGUAGES: usize = 6;
}

/// File and directory filtering patterns for scanning
pub mod filters {
    /// Directories to skip during file discovery
    pub const SKIP_DIRS: &[&str] = &[
        "venv",
        "env",
        ".venv",
        ".env",
        "node_modules",
        ".git",
        "__pycache__",
        ".pytest_cache",
        "target",
        "build",
        "dist",
        ".idea",
        ".vscode",
        "tests",
        "test",   // Skip test directories
        "vendor", // Composer/PHP and other third-party dependency trees
        "wp-includes",
        "wp-admin", // WordPress core (third-party CMS code)
    ];

    /// File patterns for minified/bundled JavaScript files
    pub const SKIP_MINIFIED_PATTERNS: &[&str] = &[
        "*.min.js",
        "*.min.jsx",
        "*.min.ts",
        "*.min.tsx",
        "*.bundle.js",
        "*.chunk.js",
        "*.vendor.js",
        "*.webpack.js",
        "*-min.js",
        "*-bundle.js",
        "*-compiled.js",
        "*-uglified.js",
        "*-compressed.js",
        "*.pack.js",
        "*.prod.js",
    ];

    /// Test file patterns to skip during taint analysis
    /// NOTE: Currently unused - candidate for removal
    pub const SKIP_TEST_PATTERNS: &[&str] = &[
        "test_*.py",
        "*_test.py",
        "test*.py",
        "test_*.js",
        "*_test.js",
        "*.test.js",
        "*.spec.js",
        "*.spec.py",
        "conftest.py",
        "**/tests/**",
        "**/test/**",
        "**/*test*/**",
    ];
}
