# LLM Rule Writing Guide for Sighthound

This guide helps LLMs understand how to write effective security rules for the Sighthound vulnerability scanner. The scanner uses RON (Rusty Object Notation) format and supports both pattern-based search and taint flow analysis.

## Table of Contents
1. [Rule Modes Overview](#rule-modes-overview)
2. [Basic Rule Structure](#basic-rule-structure)
3. [Search Mode Rules](#search-mode-rules)
4. [Taint Mode Rules](#taint-mode-rules)
5. [Reducing False Positives](#reducing-false-positives)
6. [Reducing False Negatives](#reducing-false-negatives)
7. [Best Practices](#best-practices)
8. [Common Patterns](#common-patterns)
9. [Examples](#examples)

## Rule Modes Overview

The scanner operates in two main modes:

### Search Mode (Default)
- **Purpose**: Direct pattern matching for known vulnerability patterns
- **Best for**: Static patterns, dangerous function calls, simple vulnerabilities
- **Performance**: Fast, efficient for large codebases
- **Use when**: You know the exact pattern that indicates a vulnerability

### Taint Mode
- **Purpose**: Data flow analysis from sources (user input) to sinks (dangerous functions)
- **Best for**: Complex vulnerabilities requiring data flow tracking
- **Performance**: More compute-intensive but catches subtle vulnerabilities
- **Use when**: Vulnerabilities depend on user input reaching dangerous functions

## Basic Rule Structure

All rules use the `UnifiedRule` structure in RON format:

```ron
(
    rules: [
        (
            // Required fields
            mode: "search", // or "taint"
            
            // Optional but recommended metadata
            id: Some("unique-rule-id"),
            name: Some("Human readable name"),
            category: Some("vulnerability-category"),
            description: Some("What this rule detects"),
            
            // Severity and confidence
            severity: Some("Critical"), // Critical, High, Medium, Low
            confidence: Some("High"),   // High, Medium, Low
            finding_type: Some("Vulnerability Type"),
            
            // Pattern matching (search mode)
            pattern: Some("single-pattern"),
            patterns: Some(["pattern1", "pattern2"]),
            
            // Taint analysis fields (taint mode)
            sources: Some(["source-patterns"]),
            sinks: Some(["sink-patterns"]),
            sanitizers: Some(["sanitizer-patterns"]),
            
            // File filtering
            file_types: Some((
                extensions: Some([".py", ".js"]),
                include_patterns: Some(["*test*"]),
                exclude_patterns: Some(["*safe*"])
            )),
            
            // Advanced filtering
            conditions: Some([...]),
            
            // Metadata
            tags: Some(["tag1", "tag2"]),
            message: Some("Custom message")
        )
    ]
)
```

## Search Mode Rules

Search mode rules match specific patterns in code. They're perfect for:
- Dangerous function calls
- Insecure configurations
- Known anti-patterns

### Pattern Types

The scanner supports multiple pattern matching types:

1. **Exact Match**: `"eval("`
2. **Substring**: `"system"` matches any occurrence
3. **Glob/Wildcard**: `"*.innerHTML*=*"` 
4. **Regex**: `"regex:os\\.system\\([^)]*\\)"`
5. **Escaped Patterns**: `"os\\.system\\("` (for precise matching)

### Search Mode Example

```ron
(
    id: Some("python-eval-dangerous"),
    name: Some("Dangerous eval() usage"),
    category: Some("code-injection"),
    mode: "search",
    patterns: Some([
        "eval(",
        "exec(",
        "compile("
    ]),
    finding_type: Some("Code Injection"),
    severity: Some("Critical"),
    confidence: Some("High"),
    description: Some("Direct use of eval/exec/compile can lead to code injection"),
    file_types: Some((
        extensions: Some([".py"])
    )),
    tags: Some(["code-injection", "dangerous-function"])
)
```

## Taint Mode Rules

Taint mode rules track data flow from sources (where untrusted data enters) to sinks (where it can cause harm).

### Key Components

1. **Sources**: Where untrusted data originates
   - User input: `"request.args"`, `"input("`, `"sys.argv"`
   - Environment: `"os.environ"`, `"getenv("`
   - Network: `"requests.get"`, `"urllib.request"`

2. **Sinks**: Where untrusted data becomes dangerous
   - Command execution: `"os.system"`, `"subprocess.call"`
   - Code execution: `"eval("`, `"exec("`
   - File operations: `"open("`, `"write("`

3. **Sanitizers**: Functions that clean/validate data
   - Escape functions: `"html.escape"`, `"shlex.quote"`
   - Validation: `"validate("`, `"sanitize("`

### Taint Mode Example

```ron
(
    id: Some("python-cmd-injection-taint"),
    name: Some("Command Injection via User Input"),
    category: Some("injection"),
    mode: "taint",
    sources: Some([
        "request.args",
        "request.form", 
        "input(",
        "sys.argv",
        "os.environ"
    ]),
    sinks: Some([
        "os.system",
        "subprocess.call",
        "subprocess.run",
        "os.popen"
    ]),
    sanitizers: Some([
        "shlex.quote",
        "pipes.quote",
        "validate_input"
    ]),
    finding_type: Some("Command Injection"),
    severity: Some("Critical"),
    confidence: Some("High"),
    description: Some("User input flows to command execution without sanitization"),
    file_types: Some((
        extensions: Some([".py"])
    )),
    tags: Some(["command-injection", "taint-flow"])
)
```

## Reducing False Positives

False positives occur when safe code is flagged as vulnerable. Use these techniques:

### 1. Use Conditions for Context Filtering

```ron
conditions: Some([
    (
        field: "argument",
        operator: "not_literal",
        value: "",
        condition_type: Some("not_literal"),
        argument_position: Some(0)
    )
])
```

### 2. File Type Restrictions

```ron
file_types: Some((
    extensions: Some([".py"]),
    exclude_patterns: Some(["*test*", "*safe*", "*mock*"])
))
```

### 3. Context-Aware Conditions

```ron
conditions: Some([
    (
        field: "context",
        operator: "not_in",
        value: "",
        condition_type: Some("in_context"),
        not_in: Some(["comment", "string", "test_function"])
    )
])
```

### 4. Parent/Ancestor Filtering

```ron
conditions: Some([
    (
        field: "parent",
        operator: "not_equals",
        value: "if_statement",
        condition_type: Some("has_parent"),
        parent_type: Some("try_statement")
    )
])
```

### 5. Sanitizer Detection (Taint Mode)

```ron
sanitizers: Some([
    "escape(",
    "validate(",
    "sanitize(",
    "clean(",
    "filter("
])
```

## Reducing False Negatives

False negatives occur when vulnerable code is missed. Use these techniques:

### 1. Multiple Pattern Variations

```ron
patterns: Some([
    "os.system(",
    "os.popen(",
    "subprocess.call(",
    "subprocess.run(",
    "subprocess.Popen(",
    "subprocess.check_output("
])
```

### 2. Flexible Pattern Matching

```ron
patterns: Some([
    "regex:eval\\s*\\(",      // eval with whitespace
    "regex:eval\\s*\\[",      // eval as array access
    "eval(*)",                // glob pattern
    "*eval*(*)*"              // very broad pattern
])
```

### 3. Case Variations

```ron
patterns: Some([
    "system(",
    "System(",
    "SYSTEM("
])
```

### 4. Language-Specific Patterns

```ron
// Python
patterns: Some([
    "__import__(",
    "importlib.import_module(",
    "getattr(",
    "setattr("
])

// JavaScript  
patterns: Some([
    "eval(",
    "Function(",
    "setTimeout(",
    "setInterval("
])
```

### 5. Comprehensive Source Coverage (Taint Mode)

```ron
sources: Some([
    // Direct user input
    "request.*",
    "input(",
    "raw_input(",
    
    // Environment
    "os.environ",
    "getenv(",
    
    // Command line
    "sys.argv",
    "argparse",
    
    // Network
    "requests.",
    "urllib.",
    "socket.recv",
    
    // File input
    "open(",
    "read(",
    "readlines("
])
```

## Best Practices

### 1. Rule Organization

- **Group related rules**: Put similar vulnerabilities in the same file
- **Use consistent naming**: `language-category-number` (e.g., `python-sql-001`)
- **Categories**: Use standard categories like `injection`, `xss`, `deserialization`

### 2. Metadata Quality

- **Clear descriptions**: Explain what the rule detects and why it's dangerous
- **Appropriate severity**: 
  - `Critical`: RCE, SQL injection with direct user input
  - `High`: XSS, command injection, file inclusion
  - `Medium`: Information disclosure, weak crypto
  - `Low`: Deprecated functions, minor issues
- **Confidence levels**: 
  - `High`: Clear vulnerability patterns
  - `Medium`: Likely vulnerabilities that need review
  - `Low`: Suspicious patterns worth investigating

### 3. Performance Considerations

- **Start with search mode**: More efficient for simple patterns
- **Use taint mode for complex flows**: When data flow matters
- **Limit pattern scope**: Avoid overly broad patterns that match everything
- **File filtering**: Use extensions and patterns to limit scope

### 4. Testing and Validation

- **Test with known vulnerable code**: Ensure rules catch real vulnerabilities
- **Test with safe code**: Verify no false positives
- **Use conditions**: Add filtering to reduce noise
- **Iterate**: Refine rules based on results

## Common Patterns

### Command Injection
```ron
// Search mode - direct patterns
patterns: Some([
    "os.system(",
    "subprocess.call(",
    "eval(",
    "exec("
])

// Taint mode - data flow
sources: Some(["request.*", "input(", "sys.argv"])
sinks: Some(["os.system", "subprocess.call"])
```

### SQL Injection
```ron
// Search mode
patterns: Some([
    "cursor.execute(*%*)",
    "cursor.execute(*+*)",
    "cursor.execute(*format*)"
])

// Taint mode
sources: Some(["request.*", "input("])
sinks: Some(["cursor.execute", "db.query"])
sanitizers: Some(["escape", "parameterized"])
```

### XSS (JavaScript)
```ron
patterns: Some([
    "*.innerHTML*=*",
    "document.write(",
    "*.insertAdjacentHTML("
])
```

### Deserialization
```ron
patterns: Some([
    "pickle.loads(",
    "pickle.load(",
    "json.loads(",
    "yaml.load("
])
```

## Examples

### Complete Python Command Injection Rule

```ron
(
    rules: [
        (
            id: Some("python-cmd-injection-comprehensive"),
            name: Some("Comprehensive Command Injection Detection"),
            category: Some("injection"),
            mode: "taint",
            
            sources: Some([
                "request.args",
                "request.form",
                "request.json",
                "input(",
                "sys.argv",
                "os.environ"
            ]),
            
            sinks: Some([
                "os.system",
                "os.popen",
                "subprocess.call",
                "subprocess.run", 
                "subprocess.Popen",
                "subprocess.check_output"
            ]),
            
            sanitizers: Some([
                "shlex.quote",
                "pipes.quote",
                "re.escape",
                "validate_command"
            ]),
            
            finding_type: Some("Command Injection"),
            severity: Some("Critical"),
            confidence: Some("High"),
            
            description: Some("User input flows to command execution without proper sanitization"),
            
            file_types: Some((
                extensions: Some([".py"]),
                exclude_patterns: Some(["*test*", "*mock*"])
            )),
            
            tags: Some(["command-injection", "cwe-78", "critical"])
        )
    ]
)
```

### JavaScript XSS Rule with Conditions

```ron
(
    rules: [
        (
            id: Some("js-dom-xss-innerHTML"),
            name: Some("DOM XSS via innerHTML"),
            category: Some("xss"),
            mode: "search",
            
            patterns: Some([
                "*.innerHTML*=*"
            ]),
            
            conditions: Some([
                (
                    field: "argument", 
                    operator: "not_literal",
                    value: "",
                    condition_type: Some("not_literal"),
                    argument_position: Some(0)
                )
            ]),
            
            finding_type: Some("DOM XSS"),
            severity: Some("High"),
            confidence: Some("High"),
            
            description: Some("Dynamic assignment to innerHTML can lead to XSS"),
            
            file_types: Some((
                extensions: Some([".js", ".jsx", ".ts", ".tsx"])
            )),
            
            tags: Some(["xss", "dom", "cwe-79"])
        )
    ]
)
```

This guide provides LLMs with comprehensive knowledge to write effective security rules that minimize false positives while catching real vulnerabilities through both direct pattern matching and sophisticated data flow analysis. 