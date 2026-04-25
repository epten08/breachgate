# CI/CD Future Work

This project is already shaped like a CI/CD security gate: it has a `breach-gate scan` CLI, YAML configuration, JSON and Markdown reports, Docker Compose environment support, scanner adapters, a CI output mode, and deployment-oriented verdicts.

To make it reliable for development teams across real pipelines, the next work should focus on packaging, deterministic execution, machine-readable outputs, safe scanner behavior, and clear integration templates.

## Current State

- `package.json` exposes a `breach-gate` binary from `dist/cli/index.js` and scripts for `build`, `typecheck`, `test`, `scan`, and the vulnerable demo API.
- `src/cli/commands/run.ts` supports `--ci`, `--target`, `--config`, `--output`, `--format`, scanner skip flags, and exit codes intended for deployment gating.
- `security.config.yml` supports target URL or Docker Compose, health checks, endpoint hints, auth settings, scanner toggles, thresholds, and report formats.
- The orchestrator normalizes scanner output and can mark a run `INCONCLUSIVE` when scanners fail.
- Reports can be generated as Markdown and JSON, and the CLI summary focuses on deployment verdicts, attack feasibility, attack chains, and remediation.
- Scanner adapters currently cover Trivy filesystem scanning, Trivy image scanning, OWASP ZAP API scanning, and AI-assisted behavioral testing.
- Authenticated CI scans support pre-scan hooks, session cookies, custom headers, and role-based dynamic/AI scan passes.
- Safety controls support passive, safe-active, and full-active profiles, production-looking host blocking, host allowlists, excluded paths, request throttling, and replayable AI test artifacts.

## High Priority Tasks

### 1. Make Missing Scanners Fail Safely In CI

Problem: some scanner adapters return an empty finding list when Trivy, Docker, ZAP, or required images are unavailable. In CI this can look like a clean scan even though a scanner did not run.

Tasks:

- Add a `required` flag per scanner, defaulting to `true` in CI and `false` or warning-only in local development.
- Make scanner dependency failures return structured scanner status rather than empty results.
- Treat missing required tools, missing Docker images, unreachable ZAP, and AI provider failures as `INCONCLUSIVE` unless the scanner is explicitly skipped.
- Add CLI output that distinguishes `scanner skipped`, `scanner unavailable`, `scanner failed`, and `scanner completed`.
- Add tests proving that missing scanners do not produce a `SAFE` verdict in CI.

Acceptance criteria:

- `breach-gate scan --ci` exits non-zero when an enabled required scanner cannot run.
- The final CI output names the unavailable scanner.
- JSON reports include failed and skipped scanner names.

### 2. Generate Artifacts In CI Mode

Problem: CI mode prints deterministic status, but report generation is currently inside the non-CI output branch. Pipelines need JSON or Markdown artifacts even when using `--ci`.

Tasks:

- Generate configured reports in CI mode when `--format` or reporting config is present.
- Use stable artifact filenames such as `security-report.json`, plus optional timestamped copies.
- Emit the artifact paths in CI output.
- Ensure report generation failure can optionally fail the run.

Acceptance criteria:

- `breach-gate scan --ci -f json,markdown -o ./reports` writes both reports.
- Report artifacts are generated for `SAFE`, `UNSAFE`, and `INCONCLUSIVE` runs.

### 3. Add Verdict And Scanner Status To JSON Reports

Problem: the JSON report currently contains metadata, summary, and findings, but not the deployment verdict or scanner completion state. CI systems need stable fields for policy decisions.

Tasks:

- Add a top-level `verdict` object with `status`, `reason`, `operationalConclusion`, `exitCode`, `confirmedExploits`, and `scanIncomplete`.
- Add `scannerStatus` with completed, failed, skipped, unavailable, durations, versions, and command metadata.
- Add `policy` with thresholds and active profile.
- Version the JSON schema and document compatibility rules.
- Add fixture-based tests for the report schema.

Acceptance criteria:

- CI can decide deployment using only the JSON report.
- The JSON schema can evolve without breaking existing consumers silently.

### 4. Provide First-Party Pipeline Templates

Problem: the README includes a small GitHub Actions snippet, but teams need copyable, tested templates for common CI systems.

Tasks:

- Add `docs/ci/github-actions.md` with examples for pull request quick scans, protected branch full scans, and artifact upload.
- Add `docs/ci/gitlab-ci.md` with equivalent jobs and artifact retention.
- Add `docs/ci/azure-pipelines.md` or `docs/ci/jenkins.md` if those platforms are in scope.
- Add examples for external running APIs and Docker Compose-managed test environments.
- Include recommended scanner caching for Trivy DB and Docker images.

Acceptance criteria:

- A developer can copy a template, set `API_URL`, and get a working CI gate.
- Templates upload JSON and Markdown reports as build artifacts.

### 5. Package The Tool For Reuse

Problem: the repo can be built locally, but reusable CI/CD adoption needs installable, pinned, versioned delivery.

Tasks:

- Publish the package to npm or a private registry with the `breach-gate` binary.
- Add a Docker image containing Node, the built CLI, Trivy, and optional scanner dependencies.
- Add a composite GitHub Action wrapper for common usage.
- Add release automation that builds, tests, tags, publishes, and creates release notes.
- Document version pinning, for example `npx breach-gate@1.2.3 scan --ci`.

Acceptance criteria:

- CI jobs can run Breach Gate without cloning this repository.
- Teams can pin a known version and upgrade deliberately.

## Medium Priority Tasks

### 6. Implement Config Environment Variable Expansion

Problem: the example config uses values like `${JWT_TOKEN}`, but the config loader currently parses YAML without expanding environment variables.

Tasks:

- Add safe interpolation for `${VAR}` and `${VAR:-default}` values.
- Fail configuration validation when required environment variables are missing.
- Redact interpolated secret values in logs, reports, and error messages.
- Add tests for JWT, API key, OpenAI, Anthropic, and ZAP secret handling.

Acceptance criteria:

- Developers can store secrets in CI secret stores and reference them from `security.config.yml`.
- Secret values never appear in normal logs or reports.

### 7. Load And Use OpenAPI Specs End To End

Problem: configuration has `target.openApiSpec`, and the prompt builder can parse OpenAPI objects, but the CLI path does not currently load the spec into the execution context.

Tasks:

- Load `target.openApiSpec` from YAML or JSON.
- Resolve relative paths from the config file location.
- Pass the parsed OpenAPI document into `ExecutionContext`.
- Use the spec to scope ZAP scanning and AI test generation.
- Add validation and helpful errors for invalid specs.

Acceptance criteria:

- `target.openApiSpec` changes the scanned endpoint set.
- ZAP and AI scans are limited to documented API scope unless explicitly configured otherwise.

### 8. Add Policy-As-Code

Problem: `failOn` exists, but CI adoption usually needs more nuanced rules, exceptions, and environment-specific policies.

Tasks:

- Add policy profiles such as `pull-request`, `main`, `release`, and `nightly`.
- Support rules such as `failOnConfirmedExploit`, `maxCritical`, `maxHigh`, `failOnInconclusive`, and `failOnScannerFailure`.
- Add an ignore or baseline file with expiry dates, owners, and justifications.
- Add differential mode that fails only on new findings for legacy projects.
- Document recommended policies for PR, staging, and release gates.

Acceptance criteria:

- Teams can adopt the tool without immediately blocking on known legacy findings.
- Exceptions are explicit, reviewed, and time-limited.

### 9. Add SARIF And PR Annotation Outputs

Problem: JSON and Markdown are useful artifacts, but CI platforms can surface SARIF findings directly in code scanning and pull requests.

Tasks:

- Add `sarif` to supported report formats.
- Map findings to SARIF rules, locations, severity levels, and help text.
- Add GitHub Code Scanning upload examples.
- Add optional GitLab code quality or security report format if GitLab support is important.

Acceptance criteria:

- Findings can appear inline in GitHub Security or PR checks.
- The SARIF output validates against the SARIF schema.

### 10. Add A CI Bootstrap Command

Problem: each team currently has to hand-build config and pipeline wiring.

Tasks:

- Add `breach-gate init` to generate a starter `security.config.yml`.
- Add `breach-gate init ci --provider github|gitlab|azure` to generate pipeline snippets.
- Add `breach-gate doctor` to check Node, Docker, Trivy, ZAP, Ollama, environment variables, config validity, target health, and image availability.
- Make `doctor --ci` fail with actionable messages.

Acceptance criteria:

- A new project can be onboarded with one command and minor config edits.
- CI failures identify missing prerequisites before a full scan starts.

### 11. Improve Authenticated Scanning

Status: implemented in Phase 4. Future improvements should focus on endpoint-level auth expectations and stronger redaction coverage.

Problem: real APIs usually need short-lived tokens, login flows, cookies, tenant headers, and role-based scans.

Tasks:

- Add pre-scan auth hooks or commands that can obtain tokens.
- Support multiple identities such as anonymous, user, admin, and service account.
- Support cookies and session-based auth in executor and ZAP flows.
- Allow endpoint-level auth expectations.
- Redact auth headers and tokens from evidence.

Acceptance criteria:

- CI can scan protected APIs without hardcoding static tokens.
- Reports can show which role was used without leaking credentials.

### 12. Make AI Scans Deterministic And Replayable

Status: implemented in Phase 4 for deterministic CI defaults, saved test artifacts, and configured replay files. Future improvements should add CLI aliases and prompt/model metadata to reports.

Problem: AI generation currently defaults to non-zero temperature and may fall back to generated tests when the provider is unavailable. CI needs repeatability.

Tasks:

- Default AI CI mode to deterministic settings.
- Record generated test cases as an artifact.
- Add `--replay-ai-tests <file>` to re-run a previous AI test set.
- Add a policy for whether unavailable AI is `warn`, `skip`, or `fail`.
- Pin provider, model, temperature, max tokens, and prompt version in reports.

Acceptance criteria:

- A failed AI scan can be reproduced from the saved test artifact.
- CI runs do not change behavior unexpectedly due to model output drift.

### 13. Add Safe Scan Profiles

Status: implemented in Phase 4. Future improvements should add payload-class controls and richer per-endpoint safety policy.

Problem: active dynamic and AI tests can send state-changing requests. CI needs guardrails so scans target test environments and avoid destructive actions.

Tasks:

- Add profiles such as `passive`, `safe-active`, and `full-active`.
- Require explicit confirmation or config for destructive methods and payload classes.
- Add scope allowlists and deny production hostnames by default unless explicitly allowed.
- Add request rate limits and endpoint exclusions.
- Document that full active scans should run against disposable staging environments.

Acceptance criteria:

- Pull request scans can run safely against ephemeral environments.
- Release/nightly scans can opt into deeper active testing.

### 14. Improve Performance And Pipeline Ergonomics

Problem: full security scans can be slow. CI usage needs fast PR feedback plus deeper scheduled coverage.

Tasks:

- Expose orchestrator parallel execution through config and CLI.
- Add per-scanner timeout configuration.
- Add PR profile that runs static and container checks only.
- Add nightly profile that runs static, container, ZAP, and AI checks.
- Cache Trivy vulnerability DB and Docker scanner images in template workflows.

Acceptance criteria:

- PR scans complete within an agreed target time.
- Nightly scans provide deeper coverage without slowing every commit.

## Lower Priority Tasks

### 15. Add The Project's Own CI Pipeline

Status: implemented in Phase 5. The repository now has a CI workflow for typecheck, tests, CLI hardening tests, build, packaging, SBOM generation, and a demo API scan smoke job.

Tasks:

- Add a repository CI workflow running `npm ci`, `npm run typecheck`, `npm test`, and `npm run build`.
- Add linting and formatting scripts.
- Add dependency caching.
- Add a demo scan job against `demo/vulnerable-api.ts` or `demo/docker-compose.yml`.
- Preserve generated reports as artifacts for the demo job.

Acceptance criteria:

- Every pull request verifies the tool itself still builds, tests, and scans.

### 16. Expand Automated Test Coverage

Status: implemented in Phase 5 for CLI exit codes, scanner dependency failure handling, and JSON report schema compatibility checks. Additional verdict and output stability cases can still be added later.

Tasks:

- Add unit tests for `AttackAnalyzer.generateVerdictWithStatus`.
- Add CLI integration tests for exit codes `0`, `1`, and `2`.
- Add tests for CI mode output stability.
- Add tests for scanner dependency failure behavior.
- Add tests for report generation in CI mode.
- Add tests for config interpolation and secret redaction.

Acceptance criteria:

- Future CI/CD behavior changes are covered by regression tests.

### 17. Add Supply Chain Controls

Status: partially implemented in Phase 5 for CycloneDX SBOM generation, npm provenance, and container provenance/SBOM attestations. Dependency automation and trusted-tag policy remain future work.

Tasks:

- Generate an SBOM for npm package and Docker image releases.
- Add dependency update automation.
- Add package provenance or signing for released artifacts.
- Add `npm audit` or equivalent dependency policy to the repository pipeline.
- Document trusted image tags and scanner image pinning.

Acceptance criteria:

- Teams can use Breach Gate in regulated or security-conscious pipelines with traceable artifacts.

### 18. Add Multi-Project And Monorepo Support

Status: implemented in Phase 5 with `--configs` and `--workdir` support for multi-service scans and config-relative execution.

Tasks:

- Support multiple config files in one repository.
- Add `--workdir` and matrix-friendly output paths.
- Support per-service Docker Compose files and per-service OpenAPI specs.
- Merge multiple service reports into a single deployment verdict.

Acceptance criteria:

- Monorepos can run one scan job per service and still produce a clear release gate.

### 19. Add Notifications And Issue Creation

Tasks:

- Add PR comment summaries.
- Add Slack or Teams webhook notifications for blocked deployments.
- Add optional Jira or GitHub issue creation for confirmed exploits.
- Include links to CI artifacts and remediation guidance.

Acceptance criteria:

- Developers receive actionable feedback where they already work.

### 20. Make Terminal Output Encoding CI-Safe

Problem: some console output and docs use box drawing or emoji-style symbols that can render poorly in Windows or CI logs.

Tasks:

- Add an ASCII-only mode for reports and CLI output.
- Make `--ci` default to ASCII-safe output.
- Keep rich formatting for local interactive runs.
- Add tests or snapshots for CI text output.

Acceptance criteria:

- CI logs are readable on Windows, Linux, GitHub Actions, GitLab, and plain text log collectors.

## Recommended Adoption Path

1. First make scanner failures fail safely in CI.
2. Generate JSON and Markdown artifacts in CI mode.
3. Add verdict and scanner status fields to JSON.
4. Ship a GitHub Actions template and a Docker image or npm package.
5. Add policy-as-code with baselines and exceptions.
6. Expand to SARIF, richer auth, deterministic AI replay, and monorepo support.

## Example Target CI Experience

```bash
npm ci
npx breach-gate@1.2.3 scan \
  --ci \
  --config security.config.yml \
  --format json,markdown,sarif \
  --output ./security-reports
```

Expected CI behavior:

- Exit `0` when the configured policy passes.
- Exit `1` when confirmed exploits, policy violations, or required scanner failures occur.
- Exit `2` for configuration errors.
- Always upload machine-readable and human-readable reports.
- Never treat an incomplete scan as proof that the application is safe.

