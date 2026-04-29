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
├── findings/            # Attack feasibility analysis, risk scoring, normaliser
├── orchestrator/        # Scanner orchestration, environment management
├── policy/
│   ├── policy.ts        # Baseline evaluation
│   └── suppression.ts   # .breachgateignore parser
├── reports/             # JSON, Markdown, SARIF, HTML report generators
├── safety/              # Allowlist enforcement, rate limiting
└── scanners/
    ├── ai/              # AI behavioral tester
    ├── graphql/         # GraphQL security prober
    ├── static/          # Trivy SAST
    ├── container/       # Trivy image scanning
    └── dynamic/         # OWASP ZAP
```

---

## Running Tests

```bash
npm test              # Integration tests (src/test/integration.test.ts)
npm run test:cli      # CLI tests
npm run test:watch    # Watch mode
npm run test:coverage # Coverage report
npm run typecheck     # Type-only check, no output files
npm run lint          # ESLint
npm run format:check  # Prettier
```

All PRs must pass the full CI suite: `npm run test:all`.

The integration tests run against mock servers — no live API key or external target is required.

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
  category: ScannerCategory;   // "static" | "container" | "dynamic" | "ai"
  run(ctx: ExecutionContext): Promise<RawFinding[]>;
}
```

Steps:

1. Create `src/scanners/<category>/<name>.scanner.ts` implementing `Scanner`.
2. Return `RawFinding[]` — the orchestrator handles normalisation and deduplication.
3. Add a corresponding config key to `ScannersConfig` in `src/core/config.loader.ts`.
4. Wire it into `createScanners()` in `src/cli/commands/run.ts`.
5. Add integration tests covering available and unavailable states.

See `src/scanners/graphql/graphql.scanner.ts` for a self-contained example that does endpoint discovery, multiple probes, and graceful fallback.

---

## Adding New AI Attack Categories

To teach the AI scanner a new attack type:

### 1. Add to the prompt (`src/ai/prompt.builder.ts`)

List the new category in `buildEndpointTestPrompt()` under "Attack categories to consider". If the category is auth-dependent (like JWT attacks), gate it on `this.ctx.auth?.type`.

### 2. Add a fallback test case (`src/ai/test.generator.ts`)

In `getFallbackTestsForEndpoint()`, add a branch with a concrete payload for when the AI call fails or is unavailable. This ensures the category is always tested even offline.

### 3. Add a classifier (`src/ai/evaluator.ts`)

In `classifyVulnerability()`, add a case that matches on the new category string and returns the correct `type`, `severity`, and `recommendation`.

### 4. Update `inferSeverity` (`src/ai/executor.ts`)

Add the new category to the `severityMap` in `inferSeverity()` so the live console output shows the right severity badge.

### 5. Add to the README attack categories table

Update the table in `README.md` under *AI-Assisted Behavioral Testing → Attack Categories*.

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
feat(scanner): add GraphQL introspection and depth-limit probes
fix(ai): skip bodyContains check on 4xx responses to eliminate false positives
docs: document .breachgateignore suppression file format
test(policy): add suppression expiry edge case
```

Single-line commits are fine for small changes. Use a body when the reason behind a change is non-obvious.
