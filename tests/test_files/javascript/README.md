# XSS False Negative Test Cases

This directory contains test files designed to validate that our XSS detection rules catch common false negative patterns while maintaining low false positive rates.

## Test Files

### 1. `xss_false_negative_tests.js`
Comprehensive test cases based on real-world XSS patterns that were previously missed:

#### Case 1: innerHTML manipulation with user input
- **Pattern**: Dynamic HTML content generation with user input from DOM elements
- **Vulnerability**: User input flows to `innerHTML` without sanitization
- **Source**: `option.text`, `select.id`, `select.value`
- **Sink**: `tag.innerHTML`

#### Case 2: Dataset manipulation with user input
- **Pattern**: Setting dataset properties with user-controlled data
- **Vulnerability**: User data flows to dataset properties and element attributes
- **Source**: User profile data, URL parameters
- **Sink**: `profile.dataset.*`, `profile.src`, `profile.title`

#### Case 3: Script injection via srcdoc
- **Pattern**: Creating iframe elements with user input in srcdoc
- **Vulnerability**: User input flows to srcdoc with script tags
- **Source**: URL matching, user input
- **Sink**: `iframe.srcdoc`

#### Case 4: Sensitive data exposure via localStorage
- **Pattern**: Storing sensitive error information in localStorage
- **Vulnerability**: Sensitive data flows to console output and DOM
- **Source**: `localStorage` enumeration
- **Sink**: `console.error`, `innerHTML`

#### Case 5: SVG manipulation without sanitization
- **Pattern**: Manipulating SVG elements with user data
- **Vulnerability**: Only removes specific elements, user input may contain other malicious content
- **Source**: User elements array
- **Sink**: `textElement.innerHTML`, `styleElement.textContent`

### 2. `xss_false_negative_tests.tsx`
TypeScript/React version with additional patterns:
- React components with `dangerouslySetInnerHTML`
- Error boundaries exposing localStorage
- SVG library hooks with insufficient sanitization
- PostMessage handlers
- Form submission handlers

### 3. `xss_simple_test.js`
Simplified test cases focusing on core XSS patterns:
- URL parameters → innerHTML
- localStorage → innerHTML
- Dataset manipulation
- Script injection
- PostMessage handling
- Form data handling
- Network responses
- Attribute manipulation
- Event handler injection

### 4. `xss_comprehensive_test.js`
Complete test suite with both vulnerable and safe patterns:

#### Vulnerable Patterns (Should be detected):
1. URL parameters → innerHTML
2. localStorage → innerHTML
3. Form data → innerHTML
4. PostMessage → innerHTML
5. Network response → innerHTML
6. Script src injection
7. Iframe srcdoc injection
8. SVG innerHTML injection
9. Attribute manipulation
10. Event handler injection
11. Dataset manipulation
12. Template literal injection

#### Safe Patterns (Should NOT be detected):
1. textContent usage (safe)
2. Static innerHTML (no user input)
3. Sanitized innerHTML (DOMPurify)
4. createElement with textContent
5. createTextNode usage
6. URL validation before use
7. Escaped HTML
8. Safe DOM operations
9. Reading location (not setting)
10. Safe event listeners

## Current Detection Status

Based on testing with our taint analysis rules:

### ✅ Currently Detected
- localStorage.getItem → innerHTML
- FormData → innerHTML
- Some basic XSS patterns

### ❌ Missing Detection (False Negatives)
- URLSearchParams → innerHTML
- PostMessage data → innerHTML
- Network response → innerHTML
- Script src injection
- Iframe srcdoc injection
- SVG innerHTML injection
- Attribute manipulation (href, title, etc.)
- Event handler injection (onclick, etc.)
- Dataset manipulation
- Template literal injection

### ⚠️ False Positives
- Reading window.location.href (should be safe)
- Reading window.location.pathname (should be safe)

## Recommended Improvements

1. **Enhance Source Patterns**: Add more specific patterns for URLSearchParams, PostMessage, and network responses
2. **Expand Sink Patterns**: Include more attribute sinks (href, title, src, onclick, etc.)
3. **Improve Pattern Matching**: Better handling of method calls and property access
4. **Add Dataset Sinks**: Include dataset property assignments as potential sinks
5. **Template Literal Support**: Better detection of template literals with user input
6. **Reduce False Positives**: Improve conditions to exclude safe location reading operations

## Testing Commands

```bash
# Test simple patterns
./sighthound_macos_arm64 --taint-analysis tests/test_files/javascript/xss_simple_test.js javascript rules/javascript/frontend_taint_security.ron

# Test comprehensive patterns
./sighthound_macos_arm64 --taint-analysis tests/test_files/javascript/xss_comprehensive_test.js javascript rules/javascript/frontend_taint_security.ron

# Test TypeScript patterns
./sighthound_macos_arm64 --taint-analysis tests/test_files/javascript/xss_false_negative_tests.tsx javascript rules/javascript/frontend_taint_security.ron
```

## Expected Outcomes

After implementing the recommended improvements, we should see:
- **Reduced false negatives**: All 12 vulnerable patterns should be detected
- **Maintained low false positives**: Safe patterns should not trigger alerts
- **Better accuracy**: Higher precision and recall for XSS detection
- **Real-world coverage**: Detection of actual XSS patterns found in production code 