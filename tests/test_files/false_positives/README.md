# False Positive Regression Tests

This directory contains test files designed to prevent regression of false positive issues that have been previously identified and fixed in the vulnerability scanner.

## Purpose

False positives are a critical issue in security scanners because they:
- Reduce trust in the tool
- Create noise that masks real vulnerabilities
- Waste developer time investigating non-issues
- Can lead to the scanner being disabled or ignored

These tests ensure that once a false positive issue is fixed, it doesn't reappear in future updates.

## Test Files

### `cleartext_transmission_false_positives.js`

**Issue**: Clear-text Transmission rule was generating false positives due to overly broad taint source patterns.

**Problem**: Patterns like `"password"`, `"*[type=password]*"`, `"*[name*=token]*"` were matching any variable name containing these keywords, not just actual user input sources.

**Impact**: 
- THREE.js library: 20 false positives from constants like `DDPF_ALPHAPIXELS`
- Any library with variables containing "password", "token", "key", etc.
- Function parameters with these names were incorrectly flagged

**Expected Results**:
- 3 TRUE POSITIVES (legitimate vulnerabilities)
- 0 FALSE POSITIVES (library code, constants, function parameters)

**Test Command**:
```bash
./target/debug/sighthound tests/test_files/false_positives/cleartext_transmission_false_positives.js --code-type frontend --taint-analysis
```

**Fixed Rule**: `js-cleartext-network-taint-001`

## Running Tests

To run all false positive tests:

```bash
# Run individual test
./target/debug/sighthound tests/test_files/false_positives/cleartext_transmission_false_positives.js --code-type frontend --taint-analysis

# Count results to validate
./target/debug/sighthound tests/test_files/false_positives/cleartext_transmission_false_positives.js --code-type frontend --taint-analysis --output-format json | grep -c "Clear-text Transmission"
```

## Adding New Tests

When adding new false positive regression tests:

1. Create a descriptive filename: `{rule_category}_{issue_description}_false_positives.{ext}`
2. Include comprehensive documentation in the file header:
   - Issue description
   - Problem patterns that were fixed
   - Real-world impact
   - Expected behavior
   - Test commands
3. Include both TRUE POSITIVES and FALSE POSITIVES sections
4. Add validation instructions
5. Update this README

## Validation

Each test file should:
- Produce a known number of legitimate vulnerabilities (TRUE POSITIVES)
- Produce zero false positives from the problematic patterns
- Include clear documentation of expected results
- Be runnable with a simple command

## Maintenance

- Run these tests before each release
- Update tests when rules are modified
- Add new tests when false positives are reported and fixed
- Keep expected result counts updated in documentation

## Integration

These tests should be integrated into:
- CI/CD pipelines
- Pre-release validation
- Automated testing suites
- Developer workflow checks 