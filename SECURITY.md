# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x (latest) | Yes |
| < 1.0 | No |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities in Breach Gate itself.**

Report vulnerabilities privately via **GitHub's built-in private vulnerability reporting**:

1. Go to the repository on GitHub
2. Click **Security** → **Advisories** → **Report a vulnerability**

If you cannot use that, email the maintainer directly (see the npm package metadata for contact details).

### What to include

- A clear description of the vulnerability
- Steps to reproduce or a proof-of-concept
- The version of Breach Gate affected
- Potential impact

### Response timeline

| Milestone | Target |
|-----------|--------|
| Initial acknowledgement | Within 2 business days |
| Confirmation / triage | Within 5 business days |
| Patch or mitigation | Within 30 days for HIGH/CRITICAL |

You will be credited in the advisory unless you request otherwise.

## Scope

This policy covers vulnerabilities **in the Breach Gate tool itself**, for example:

- Command injection via a maliciously crafted `security.config.yml`
- Path traversal when loading configs, baselines, or suppression files
- Credential leakage in log output or reports
- SSRF triggered by the scanner against unintended internal targets

**Out of scope:**

- Vulnerabilities in the *target* API being scanned — that is the intended output of the tool
- Vulnerabilities in optional external tools (Trivy, ZAP, Ollama) — report those upstream
- Scanner false positives or false negatives — use the [False Positive issue template](.github/ISSUE_TEMPLATE/false_positive.yml)
