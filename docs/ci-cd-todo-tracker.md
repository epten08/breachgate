# CI/CD Todo Tracker

This tracker turns the future-work backlog into implementation-sized tasks. Status values are:

- `[x]` done
- `[~]` in progress
- `[ ]` not started

## Phase 1: CI Gate Foundations

- [x] Create CI/CD future-work backlog.
- [x] Create implementation todo tracker.
- [x] Track scanner status as completed, failed, skipped, or unavailable.
- [x] Make unavailable required scanners produce an incomplete scan result.
- [x] Generate reports in `--ci` mode.
- [x] Add stable report filenames for CI artifacts.
- [x] Add verdict, scanner status, and policy data to JSON reports.
- [x] Support `${ENV_VAR}` and `${ENV_VAR:-default}` interpolation in YAML config values.
- [x] Load configured OpenAPI specs into the execution context.

## Phase 2: Pipeline Templates And Packaging

- [x] Add GitHub Actions examples for pull request, protected branch, and scheduled scans.
- [x] Add GitLab CI examples with report artifacts.
- [x] Add Azure Pipelines or Jenkins examples if needed.
- [x] Add a reusable Docker image for CI usage.
- [x] Add an npm publishing/release workflow.
- [x] Add a composite GitHub Action wrapper.

## Phase 3: Policy And Developer Workflow

- [x] Add policy profiles such as `pull-request`, `main`, `release`, and `nightly`.
- [x] Add baseline/ignore files with owners, expiry dates, and justifications.
- [x] Add differential mode to fail only on new findings.
- [x] Add SARIF output.
- [x] Add PR annotations or code scanning upload examples.
- [x] Add `breach-gate init` for config scaffolding.
- [x] Add `breach-gate doctor` for CI prerequisite checks.

## Phase 4: Auth, AI, And Safety

- [x] Add pre-scan auth hooks for short-lived tokens.
- [x] Support multi-role scans such as anonymous, user, admin, and service account.
- [x] Support cookies/session auth in dynamic and AI test flows.
- [x] Add deterministic AI replay artifacts.
- [x] Add active scan safety profiles.
- [x] Add production-host guardrails and scope allowlists.

## Phase 5: Hardening

- [x] Add repository CI for build, typecheck, tests, and demo scans.
- [x] Expand tests for CLI exit codes.
- [x] Expand tests for scanner dependency failures.
- [x] Expand tests for report schema compatibility.
- [x] Add SBOM generation for releases.
- [x] Add package provenance or signing.
- [x] Add monorepo and multi-config support.

