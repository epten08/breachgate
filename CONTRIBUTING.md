# Contributing to Breach Gate

Thank you for taking the time to contribute. This document covers everything you need to get started.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Ways to Contribute](#ways-to-contribute)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Running Tests](#running-tests)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Adding a New Scanner](#adding-a-new-scanner)
- [Adding New AI Attack Categories](#adding-new-ai-attack-categories)
- [Commit Message Format](#commit-message-format)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating you agree to uphold it. Report unacceptable behaviour to the maintainers listed in that file.

---

## Ways to Contribute

- **Bug reports** — use the [Bug Report](.github/ISSUE_TEMPLATE/bug_report.yml) template
- **False positive reports** — the scanner flagged something that is not a vulnerability — use the [False Positive](.github/ISSUE_TEMPLATE/false_positive.yml) template
- **Feature requests** — use the [Feature Request](.github/ISSUE_TEMPLATE/feature_request.yml) template
- **Pull requests** — fixes, new attack categories, new scanners, documentation improvements
- **Security vulnerabilities in Breach Gate itself** — see [SECURITY.md](SECURITY.md), do **not** open a public issue

---

## Development Setup

### Prerequisites

- Node.js >= 18 (Node 20 recommended — matches CI)
- npm >= 8

### 1. Fork and clone

```bash
git clone https://github.com/YOUR_USERNAME/breach-gate.git
cd breach-gate
```

### 2. Install dependencies

```bash
npm install
```

### 3. Copy environment template

```bash
cp .env.example .env
# Add ANTHROPIC_API_KEY, OPENAI_API_KEY, etc. as needed
```

### 4. Verify the setup

```bash
npm run typecheck   # TypeScript validation
npm test            # Integration tests
npm run test:cli    # CLI exit-code and schema tests
npm run build       # Compile to dist/
```

Or all in one:

```bash
npm run test:all
```

### 5. Run the demo

```bash
# Terminal 1 — start the intentionally vulnerable API
npm run demo

# Terminal 2 — scan it
npm run scan -- -t http://localhost:3000 -v
```

---

## Project Structure

```
src/
├── ai/                  # LLM integration
│   ├── adversary.ts     # AI provider abstraction (Anthropic, OpenAI, Ollama)
│   ├── executor.ts      # Test execution with baseline diffing and parallel runs
│   ├── evaluator.ts     # Rule-based and AI-assisted vulnerability classification
│   ├── test.generator.ts # Per-endpoint test case generation
│   └── prompt.builder.ts # System prompts and endpoint-focused attack prompts
├── cli/
│   └── commands/
│       ├── run.ts        # breach-gate scan
│       ├── watch.ts      # breach-gate watch
│       ├── init.ts       # breach-gate init
│       └── doctor.ts     # breach-gate doctor
├── core/                # Config loader, logger, errors
├── findings/            # Attack feasibility analysis, proofs, scoring, normaliser
├── intel/               # EPSS and CISA KEV exploit intelligence
├── orchestrator/        # Scanner orchestration, environment management
├── policy/
│   ├── policy.ts        # Baseline evaluation
│   └── suppression.ts   # .breachgateignore parser
├── reports/             # JSON, Markdown, SARIF, HTML report generators
├── safety/              # Allowlist enforcement, rate limiting
└── scanners/
    ├── ai/              # AI behavioural tester (the only source of proofs)
    ├── static/          # Trivy dependency and IaC analysis
    └── dynamic/         # OWASP ZAP
```

Breach Gate scans running REST APIs and nothing else. Frontend, GraphQL, and
container scanning were removed in v2.0.0. Please do not reintroduce breadth:
the value of a deploy gate is entirely in whether its verdict can be trusted.

---

## Running Tests

```bash
npm run test:controls # Negative controls — clean targets must stay SAFE
npm run precision     # Precision and recall against the corpus
npm test              # Integration tests
npm run test:cli      # CLI tests
npm run test:watch    # Watch mode
npm run test:coverage # Coverage report
npm run typecheck     # Type-only check, no output files
npm run lint          # ESLint
npm run format:check  # Prettier
```

All PRs must pass the full CI suite: `npm run test:all`.

The integration tests run against mock servers — no live API key or external target is required.

### The negative control rule

**Every detector needs a test proving it stays quiet on a clean target, and that
test must be written before the detector is merged.** If you cannot write it,
you do not understand your detector well enough to ship it.

This rule exists because of a specific failure. Until v2.0.0 the entire
behavioural test suite ran against `demo/vulnerable-api.ts`, where every
endpoint is deliberately broken. `UNSAFE` was therefore always the expected
answer, and `UNSAFE` is also this tool's failure mode. The suite could not tell
a working scanner from a broken one, and a scanner that reported a missing
`X-Frame-Options` header as a confirmed SQL injection passed CI and shipped to
npm.

Two suites enforce the rule now, and CI runs both **before** lint, unit tests,
and build:

| Suite | What it guarantees |
|---|---|
| `test/negative-controls.test.ts` | Clean targets stay `SAFE`. Every past false-positive defect is pinned here as a regression test. |
| `test/precision.test.ts` | Measured precision and recall against `test/corpus/targets.ts`. Precision is gated at exactly 1.0, so one false positive fails the build. |

Recall is gated lower (0.9) than precision (1.0) on purpose. A missed finding is
a bug. A false positive that blocks a good deploy gets the tool deleted from the
pipeline and never reinstated.

When you add a corpus case, make the clean half adversarial. Good clean cases
return the word "error" in a healthy body, reflect input safely escaped, return
500 without a stack trace, and set no security headers at all. Building the
corpus this way immediately exposed two detector bugs that code review had
missed.

---

## Submitting a Pull Request

1. **Open an issue first** for significant changes (new scanner, large refactor) so direction can be agreed before you invest time writing code.
2. Create a feature branch from `main`: `git checkout -b feat/my-feature`
3. Make your changes and add or update tests.
4. Run `npm run test:all` locally — CI will block merges on failures.
5. Follow the [commit message format](#commit-message-format).
6. Open the PR and fill in the pull request template.

### What reviewers look for

- Tests cover the new behaviour (or a clear explanation of why they don't apply)
- No new TypeScript `any` casts without justification
- No breaking changes to `security.config.yml` schema without a migration path
- Docs updated if a user-facing feature changed (README, relevant `docs/` page)
- No hardcoded credentials, API keys, or real target URLs

---

## Adding a New Scanner

Scanners implement the `Scanner` interface (`src/scanners/scanner.ts`):

```typescript
export interface Scanner {
  name: string;
  category: ScannerCategory;   // "static" | "dynamic" | "ai"
  run(ctx: ExecutionContext): Promise<RawFinding[]>;
}
```

Steps:

1. Create `src/scanners/<category>/<name>.scanner.ts` implementing `Scanner`.
2. Return `RawFinding[]` — the orchestrator handles normalisation and deduplication.
3. Add a corresponding config key to `ScannersConfig` in `src/core/config.loader.ts`.
4. Wire it into `createScanners()` in `src/cli/commands/run.ts`.
5. Add integration tests covering available and unavailable states.
6. Add a negative control. See the rule below; this is not optional.

See `src/scanners/static/trivy.static.ts` for a self-contained example with graceful fallback when the tool is missing.

**A scanner that cannot reach its target must throw, not return `[]`.** An empty
result set is recorded as a successful scan, so swallowing errors turns an
unreachable target into a `SAFE` verdict. `src/scanners/ai/ai.scanner.ts` shows
the pattern: count the failures and raise `ScannerError` past a threshold.

---

## Adding New AI Attack Categories

To teach the AI scanner a new attack type:

### 1. Add to the prompt (`src/ai/prompt.builder.ts`)

List the new category in `buildEndpointTestPrompt()` under "Attack categories to consider". If the category is auth-dependent (like JWT attacks), gate it on `this.ctx.auth?.type`.

### 2. Add a fallback test case (`src/ai/test.generator.ts`)

In `getFallbackTestsForEndpoint()`, add a branch with a concrete payload for when the AI call fails or is unavailable. This ensures the category is always tested even offline.

### 3. Decide what would PROVE it (`src/ai/executor.ts`)

This is the important step. A category is only useful if a response can prove it.
Add an `ExploitProof` value in `src/findings/finding.ts` and a detector in
`evaluateResponse()` that returns the matched excerpt.

Three rules your detector must follow:

- **Quote the evidence.** A proof without an excerpt is not a proof, because a
  developer cannot verify it in ten seconds.
- **Diff against the baseline.** If the signal also appears in the benign
  request, your payload did not cause it.
- **Be narrow.** An early version of the command-output pattern matched
  `/bin/bash`, which appears in every `/etc/passwd`, so reading a file was
  reported as command execution. Prefer a pattern that misses over one that
  guesses.

### 4. Map the proof to a category (`src/ai/evaluator.ts`)

Add an entry to `PROOF_CLASSIFICATION` and rank it in `PROOF_PRIORITY`.
Classification is driven by what was observed, never by `testCase.category`.
Dispatching on the test's own label is what once caused a missing response
header to be reported as a confirmed SQL injection.

### 5. Add corpus cases (`test/corpus/targets.ts`)

Add **both** a vulnerable endpoint and a clean one that a naive detector would
flag. The clean case is the one that matters.

### 6. Add to the README proof table

Update the table under *What counts as proof*.

---

## Commit Message Format

```
<type>(<scope>): <short summary>

[optional body — explain WHY, not WHAT]
```

**Types:** `feat`, `fix`, `docs`, `test`, `refactor`, `chore`

**Scope** (optional): `ai`, `scanner`, `cli`, `reports`, `policy`, `config`

**Examples:**

```
feat(ai): add SSRF cloud-metadata proof with baseline diffing
fix(ai): narrow command-output pattern so /etc/passwd is not read as RCE
docs: document .breachgateignore suppression file format
test(policy): add suppression expiry edge case
```

Single-line commits are fine for small changes. Use a body when the reason behind a change is non-obvious.
