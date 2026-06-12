# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability **in Sighthound itself** (the scanner
binary, library, or embedded rule engine — not findings in code you scan), please
report it privately.

**Do not** open a public GitHub issue for security vulnerabilities.

### How to report

1. Open a [GitHub private security advisory](https://github.com/Corgea/Sighthound/security/advisories/new)
   on this repository, or
2. Email the maintainers at [security@corgea.com](mailto:security@corgea.com) with
   the subject line `Sighthound Security Report`.

Include:

- A description of the vulnerability and its impact
- Steps to reproduce
- Affected version(s)
- Any proof-of-concept or suggested fix (if available)

### Response timeline

| Stage | Target |
|-------|--------|
| Initial acknowledgement | Within 3 business days |
| Triage and severity assessment | Within 7 business days |
| Fix or mitigation plan | Depends on severity; critical issues prioritized |

We will coordinate disclosure with you and credit reporters who wish to be
acknowledged (unless you prefer to remain anonymous).

## Scope

**In scope:**

- Remote code execution, sandbox escapes, or privilege escalation in Sighthound
- Crashes or undefined behavior triggered by malicious rule files or source inputs
- Incorrect taint/search results caused by engine bugs (when reproducible)

**Out of scope:**

- Findings reported by Sighthound in third-party code you scanned
- False positives or false negatives in specific rules (file a regular issue or PR
  with a rule fix instead)
- Social engineering or physical attacks

## Supported versions

Security fixes are applied to the latest release. We recommend always running the
most recent version.
