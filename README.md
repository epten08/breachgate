# Breach Gate

**Attack Feasibility Analyzer** — CLI security analysis tool for REST APIs and frontend applications. Goes beyond vulnerability detection to answer the key question: **"Is it safe to deploy?"**

Combines static analysis, container scanning, dynamic API testing, AI-assisted behavioral testing, and **frontend-specific scanning** (Semgrep, Gitleaks, OSV, project health) to produce deployment verdicts with contextual remediation.

## What Makes This Different

Most security scanners answer: *"What vulnerabilities exist?"*

Breach Gate answers: **"Can an attacker actually compromise the system?"**

| Traditional Scanner | Breach Gate |
|---------------------|--------------|
| Lists vulnerabilities | Analyzes attack feasibility |
| Severity-based sorting | Risk = Impact × Exploitability × Reachability × Confidence |
| Generic recommendations | Contextual remediation with code examples |
| Pass/fail on severity | **Deployment verdict: SAFE / UNSAFE / REVIEW_REQUIRED** |
| Backend APIs only | **Frontend apps too — React, Vue, Angular, Next.js** |

## Features

### API & Backend
- **Attack Feasibility Analysis** — Multiplicative risk scoring: reachability × exploitability × impact × confidence
- **Deployment Verdicts** — Clear SAFE/UNSAFE/REVIEW_REQUIRED decisions with reasons
- **Attack Chain Detection** — Identifies multi-step attack paths (e.g., Auth Bypass → Data Exfiltration)
- **Confirmed Exploit Tracking** — AI/dynamic testing success = auto-critical priority
- **Multi-Scanner Integration** — Trivy (SAST), ZAP (DAST), Container scanning, AI behavioral testing, GraphQL probing
- **AI-Assisted Testing** — Context-aware attack payloads, baseline response diffing, blind injection detection
- **Watch Mode** — Continuous scanning with new/resolved finding diffs
- **Finding Suppression** — `.breachgateignore` for suppressing known-acceptable findings

### Frontend
- **Static Security Scanning** — Semgrep with 12+ custom React/TS rules: `dangerouslySetInnerHTML`, insecure storage, HTTP endpoints, eval, postMessage wildcards
- **Secrets Detection** — Gitleaks scans for exposed API keys, `.env` values, hardcoded credentials
- **Dependency Vulnerabilities** — OSV Scanner (primary) or `npm audit` (fallback) for vulnerable packages
- **Project Health Checks** — Runs `lint`, `typecheck`, and `build`; records failures as findings
- **Frontend-only Mode** — No network target required; scans the local filesystem directly

## Quick Start

```bash
# Install
npm install
npm run build

# ── API scanning ──
npm run demo                                    # start the vulnerable demo API
npm run scan -- -t http://localhost:3000 -v    # run attack feasibility analysis

# ── Frontend scanning ──
npm run scan:frontend                          # scan the built-in vulnerable React demo
# or point at your own project:
breach-gate scan --frontend --frontend-path ./my-app
```

## Sample Output

### API Scan

```
═══════════════════════════════════════════════════════════
                    SCAN RESULTS
═══════════════════════════════════════════════════════════

  SECURITY VERDICT:

  ╔════════════════════════════════════════════════════════╗
  ║            ⛔  UNSAFE TO DEPLOY  ⛔                    ║
  ╚════════════════════════════════════════════════════════╝

  Reason: Confirmed exploitation: SQL Injection, Command Injection.

  ⚡ 2 CONFIRMED EXPLOITS:
     • SQL Injection on POST /api/data
     • Command Injection on POST /api/execute

  POST /api/execute    Risk: ████████████████████ 95%
  POST /api/data       Risk: ██████████████████░░ 90%

═══════════════════════════════════════════════════════════
  DEPLOYMENT BLOCKED — 2 confirmed exploit(s) to fix
═══════════════════════════════════════════════════════════
```

### Frontend Scan

```
═══════════════════════════════════════════════
      Frontend Security Scanner — Results
═══════════════════════════════════════════════

Security: HIGH
  [CRITICAL] Hardcoded API key in src/services/auth.ts:12
  [HIGH]     Token stored in localStorage (src/services/auth.ts:44)
  [HIGH]     dangerouslySetInnerHTML usage (src/components/SearchResults.tsx:18)
  [MEDIUM]   Insecure HTTP endpoint — use HTTPS (src/services/api.ts:21)
  [MEDIUM]   postMessage with wildcard origin (src/services/api.ts:38)
  [MEDIUM]   Client-side role check (src/components/AdminPanel.tsx:14)

Dependencies: MEDIUM
  [HIGH]     3 vulnerable packages (npm audit)

Code Health: LOW
  [LOW]      Type errors detected (tsc --noEmit)

Overall Risk: HIGH

Top Fixes:
  1. Move auth tokens from localStorage to httpOnly cookies
  2. Sanitize HTML with DOMPurify before dangerouslySetInnerHTML
  3. Rotate and remove hardcoded API key — store in env vars
  4. Upgrade vulnerable packages: npm audit fix
  5. Specify exact target origin in postMessage calls
═══════════════════════════════════════════════
```

## Prerequisites

### Required

- **Node.js** >= 18.0.0
- **npm** >= 8.0.0

### Optional (API scanning)

| Tool | Purpose | Installation |
|------|---------|--------------|
| **Docker** | Container scanning, ZAP/Trivy via containers | [docker.com](https://www.docker.com/get-started) |
| **Trivy** | Static analysis & container vulnerability scanning | [trivy docs](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) |
| **OWASP ZAP** | Dynamic API security testing | [zaproxy.org](https://www.zaproxy.org/download/) |
| **AI Provider** | LLM for AI-assisted behavioral testing | See [AI Provider Setup](#ai-provider-setup) |

### Optional (frontend scanning)

| Tool | Purpose | Installation |
|------|---------|--------------|
| **Semgrep** | Static React/TS security rules | `pip install semgrep` or `brew install semgrep` |
| **Gitleaks** | Secrets and credential detection | `brew install gitleaks` or [GitHub releases](https://github.com/gitleaks/gitleaks/releases) |
| **osv-scanner** | Dependency vulnerability scanning | `go install github.com/google/osv-scanner/cmd/osv-scanner@latest` |

> **Note:** Frontend scanning works even if some tools are missing — each runner is independent and degrades gracefully with a warning. `npm audit` is used automatically if `osv-scanner` is not installed.

### Installing Prerequisites

**Windows (with winget):**
```bash
winget install Docker.DockerDesktop
winget install AquaSecurity.Trivy
winget install Gitleaks.Gitleaks
# Semgrep via pip:
pip install semgrep
```

**macOS (with Homebrew):**
```bash
brew install --cask docker
brew install trivy
brew install gitleaks
brew install semgrep
```

**Linux (Ubuntu/Debian):**
```bash
# Trivy
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy

# Gitleaks
wget https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz
tar -xzf gitleaks_linux_x64.tar.gz && sudo mv gitleaks /usr/local/bin/

# Semgrep
pip install semgrep
```

## Developer Setup

### 1. Install dependencies

```bash
npm install
```

### 2. Add local environment values

Create `.env` from `.env.example` and add the values you need:

```
OPENAI_API_KEY=...
ANTHROPIC_API_KEY=...
JWT_TOKEN=...
```

### 3. Verify the repository

```bash
npm run typecheck
npm test
npm run test:cli
npm run build
```

Or in one command: `npm run test:all`

### 4. Bootstrap a starter config

```bash
npm run dev -- init --baseline --ci-provider github
```

### 5. Validate local prerequisites

```bash
npm run dev -- doctor --config security.config.yml
```

### Common Developer Commands

| Command | Purpose |
|--------|---------|
| `npm run dev -- scan ...` | Run the CLI from source |
| `npm run scan -- ...` | Shortcut for `scan` during development |
| `npm run demo` | Start the vulnerable demo API |
| `npm run demo:frontend` | Install and start the vulnerable React demo |
| `npm run scan:frontend` | Run a frontend scan on the built-in demo |
| `npm run typecheck` | TypeScript validation |
| `npm test` | Integration tests |
| `npm run test:cli` | CLI exit-code, schema, and multi-config tests |
| `npm run build` | Compile the CLI into `dist/` |

## Usage

```bash
# Run with tsx (development)
npm run dev -- scan [options]

# Or use the scan shortcut
npm run scan -- [options]

# Or directly after build
breach-gate scan [options]
```

### Commands

#### `scan`

Run attack feasibility analysis against an API target, a frontend project, or both.

```bash
breach-gate scan [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `-c, --config <path>` | Path to config file (default: `security.config.yml`) |
| `--configs <paths>` | Comma-separated config files for monorepo/multi-service scans |
| `--workdir <path>` | Working directory for resolving config, compose, reports, and scanner paths |
| `-t, --target <url>` | Target URL (overrides config) |
| `-o, --output <dir>` | Output directory for reports |
| `-f, --format <formats>` | Output formats: `markdown`, `json`, `sarif` |
| `--fail-on <severity>` | Fail if findings at this severity or above |
| `--profile <name>` | Policy profile: `pull-request`, `main`, `release`, `nightly` |
| `--baseline <path>` | Path to baseline/ignore file |
| `--differential` | Fail only on findings not covered by the baseline |
| `-v, --verbose` | Enable verbose output |
| `-q, --quiet` | Suppress non-essential output |
| `--ci` | CI mode — minimal, deterministic output for pipelines |
| `--skip-static` | Skip static analysis (Trivy) |
| `--skip-container` | Skip container scanning |
| `--skip-dynamic` | Skip dynamic API scanning (ZAP) |
| `--skip-ai` | Skip AI-assisted behavioral testing |
| `--frontend` | **Enable frontend scanning** (Semgrep + Gitleaks + OSV + project checks) |
| `--skip-frontend` | Skip frontend scanning |
| `--framework <type>` | Framework hint: `react`, `vue`, `angular`, `next`, `auto` |
| `--frontend-path <path>` | Path to frontend project root (default: current directory) |
| `--explain-verdict` | Show how each finding's feasibility score was calculated |

#### `init`

Create starter configuration and optional baseline/CI files.

```bash
breach-gate init --baseline --ci-provider github
```

#### `watch`

Continuously scan the target on a fixed interval and report new or resolved findings as a diff.

```bash
# Rescan every 2 minutes
breach-gate watch --interval 120
```

#### `doctor`

Check local or CI prerequisites.

```bash
breach-gate doctor --ci --config security.config.yml
```

### Examples

```bash
# Full API attack feasibility analysis
breach-gate scan -t http://localhost:3000 -v

# Frontend-only scan (no API target needed)
breach-gate scan --frontend --frontend-path ./my-react-app

# Frontend scan with framework hint
breach-gate scan --frontend --framework next --frontend-path ./apps/web

# Scan both API and frontend in one run
breach-gate scan -t http://localhost:3000 --frontend --frontend-path ./frontend

# CI mode
breach-gate scan -t http://localhost:3000 --ci
# Output:
# SECURITY STATUS: PASSED|FAILED|INCONCLUSIVE
# Reason: <one-line reason>

# Monorepo — multiple service configs
breach-gate scan --ci --configs services/api/security.config.yml,services/admin/security.config.yml

# Skip specific frontend sub-scanners
breach-gate scan --frontend --frontend-path . --skip-static   # still runs Gitleaks + OSV + project checks
```

## Frontend Security Scanning

Breach Gate's frontend scanner runs four independent sub-scanners. Each one degrades gracefully if its tool is not installed.

### 1. Static Analysis (Semgrep)

Runs custom React/TypeScript rules against the source tree. Detects:

| Rule | Finding | Severity |
|------|---------|----------|
| `react-dangerous-html` | `dangerouslySetInnerHTML` usage | HIGH |
| `localstorage-auth-token` | Auth token in localStorage | HIGH |
| `sessionstorage-auth-token` | Auth token in sessionStorage | MEDIUM |
| `insecure-http-fetch` | `fetch("http://...")` to a non-localhost URL | MEDIUM |
| `insecure-http-axios` | `axios.get("http://...")` to a non-localhost URL | MEDIUM |
| `eval-usage` | `eval()` call | HIGH |
| `innerhtml-assignment` | `el.innerHTML = ...` | MEDIUM |
| `document-write` | `document.write(...)` | MEDIUM |
| `client-side-role-check` | `if (obj.role === ...)` | MEDIUM |
| `hardcoded-secret-var` | Hardcoded API key/secret in a variable | HIGH |
| `postmessage-wildcard-origin` | `postMessage(data, "*")` | MEDIUM |
| `missing-message-origin-check` | `addEventListener("message", ...)` without origin check | MEDIUM |

### 2. Secrets Detection (Gitleaks)

Scans the project directory for exposed credentials without reading git history. Detects:

- Exposed `.env` values (`VITE_*`, `NEXT_PUBLIC_*`)
- API keys (Stripe, Firebase, AWS, Anthropic, etc.)
- Accidentally committed tokens and private keys

### 3. Dependency Vulnerabilities

Uses **OSV Scanner** (primary) or **npm audit** (fallback). Detects:

- Known CVEs in npm dependencies
- Transitive dependency vulnerabilities
- Maps CVSS scores to severity (CRITICAL/HIGH/MEDIUM/LOW)

### 4. Project Health Checks

Runs the scripts defined in `package.json`:

| Script | Severity on failure | What it catches |
|--------|---------------------|----------------|
| `lint` | LOW | Code quality, unused variables |
| `typecheck` | MEDIUM | Type safety errors |
| `build` | HIGH | Broken builds, missing imports |

Scripts that don't exist in `package.json` are silently skipped.

### Configuration via YAML

```yaml
# security.config.yml — frontend-only (no target: required)
version: "1.0"

scanners:
  static: { enabled: false }
  container: { enabled: false }
  dynamic: { enabled: false }
  ai: { enabled: false }
  frontend:
    enabled: true
    framework: react            # react | vue | angular | next | auto
    targetDir: ./src            # optional, defaults to cwd
    skipSemgrep: false
    skipSecrets: false
    skipDeps: false
    skipProjectChecks: false

thresholds:
  failOn: HIGH
  warnOn: MEDIUM

reporting:
  outputDir: ./security-reports
  formats: [markdown, json]
```

## Demo

Two intentionally vulnerable targets are included:

### API Demo

```bash
npm run demo                              # start vulnerable Node.js API on :3000
npm run scan -- -t http://localhost:3000 -v
```

Vulnerabilities: SQL Injection, Command Injection, Path Traversal, IDOR, Information Disclosure, Missing Security Headers.

### Frontend Demo

```bash
npm run demo:frontend      # install deps and start Vite dev server
npm run scan:frontend      # run BreachGate against the demo source
```

The React demo (`demo-frontend/`) contains deliberate instances of every pattern the frontend scanner detects:

| File | Vulnerabilities |
|------|----------------|
| `src/services/auth.ts` | Hardcoded `sk_live_*` key, `localStorage` token storage, insecure `http://` login endpoint |
| `src/services/api.ts` | Insecure HTTP calls, `postMessage("*")`, `innerHTML` assignment, `eval()` |
| `src/components/SearchResults.tsx` | `dangerouslySetInnerHTML` with API response |
| `src/components/AdminPanel.tsx` | Client-side role check bypassed via DevTools |

Scan with the built-in config:

```bash
cd demo-frontend
breach-gate scan -c security.config.yml
```

Or point the root CLI at it:

```bash
breach-gate scan --frontend --frontend-path demo-frontend --framework react
```

## Local Development Workflow

### API target

```bash
npm run demo
npm run scan -- -t http://127.0.0.1:3000 -v
```

### Frontend target

```bash
breach-gate scan --frontend --frontend-path ./my-react-app
breach-gate scan --frontend --framework next --frontend-path ./apps/web
```

### Both in one run

```bash
breach-gate scan \
  -t http://localhost:3000 \
  --frontend --frontend-path ./frontend \
  -v
```

### Exit Codes

| Code | Verdict | Description |
|------|---------|-------------|
| `0` | SAFE | No exploitable vulnerabilities detected |
| `0` | REVIEW_REQUIRED | Findings need review, no confirmed exploits |
| `1` | UNSAFE | Confirmed exploits detected — deployment blocked |
| `1` | INCONCLUSIVE | Scan failed — cannot verify security, failing safely |
| `2` | — | Configuration error |

## How Attack Feasibility Works

```
risk = impact × exploitability × reachability × confidence
```

| Factor | Description |
|--------|-------------|
| **Reachability** | Can attacker access this endpoint? |
| **Exploitability** | Is exploit demonstrated (AI, ZAP)? |
| **Impact** | Damage potential (RCE=1.0, XSS=0.75, info=0.4) |
| **Confidence** | Source quality (confirmed AI > dynamic > static) |

## Configuration

```yaml
version: "1.0"

target:
  baseUrl: http://localhost:3000
  healthEndpoint: /health
  endpoints:
    - path: /api/login
      method: POST
      body: { username: test, password: test }

auth:
  type: none   # jwt | apikey | session | none

scanners:
  static:
    enabled: true
  container:
    enabled: true
    images: [my-app:latest]
  dynamic:
    enabled: true
  ai:
    enabled: true
    provider: anthropic
    model: claude-haiku-4-5-20251001
    maxTests: 15
  graphql:
    enabled: false
  frontend:
    enabled: true
    framework: react
    targetDir: ./frontend

thresholds:
  failOn: HIGH
  warnOn: MEDIUM

reporting:
  outputDir: ./security-reports
  formats: [markdown, json, sarif]
  includeEvidence: true
```

## Finding Suppression

Two mechanisms for suppressing findings:

| Mechanism | Best for |
|-----------|---------|
| `.breachgateignore` | Permanently acceptable findings |
| `.breach-gate-baseline.yml` | Temporary waivers with expiry dates |

```yaml
# .breachgateignore
suppressions:
  - id: "7ba985bc-6885-4c1d-8666-92f317402bd4"
    reason: "Rate limiting handled by load balancer"

  - pattern: "Missing security header"
    reason: "Security headers added at CDN layer"

  - pattern: "Broken Access Control"
    endpoint: "/api/legacy"
    reason: "Tracked in SEC-456, scheduled for Q3"
    expires: "2026-09-01"
```

## AI-Assisted Behavioral Testing

The AI scanner understands endpoint semantics and generates context-aware attack payloads per endpoint. It captures a benign baseline response before attacking to avoid false positives.

| Category | Detection |
|----------|-----------|
| SQL Injection | Error text or payload reflected |
| Command Injection | Output in response or time-based blind |
| Path Traversal | File content in response |
| XSS | Script tag reflected verbatim |
| IDOR | 2xx when 4xx expected |
| SSRF | Cloud metadata in response |
| Mass Assignment | Privileged field echoed back |
| JWT attacks | Algorithm confusion, claim tampering |

## AI Provider Setup

### Anthropic (recommended)

```bash
# .env
ANTHROPIC_API_KEY=sk-ant-...
```

```yaml
scanners:
  ai:
    enabled: true
    provider: anthropic
    model: claude-haiku-4-5-20251001
    maxTests: 15
```

| Model | Speed | Best for |
|-------|-------|----------|
| `claude-haiku-4-5-20251001` | Fastest | CI pipelines |
| `claude-sonnet-4-6` | Balanced | Complex vulnerabilities |
| `claude-opus-4-7` | Thorough | Nightly / release scans |

### OpenAI

```yaml
scanners:
  ai:
    enabled: true
    provider: openai
    model: gpt-4o-mini
```

### Ollama (local)

```yaml
scanners:
  ai:
    enabled: true
    provider: ollama
    model: llama3:8b
    baseUrl: http://localhost:11434
```

## GraphQL Scanning

```yaml
scanners:
  graphql:
    enabled: true
```

Auto-discovers `/graphql`, `/api/graphql`, `/query`, `/gql`. Checks: introspection, query depth, field suggestions, SQL injection via variables, IDOR.

## Project Structure

```
breach-gate/
├── src/
│   ├── cli/
│   │   └── commands/
│   │       ├── run.ts       # breach-gate scan
│   │       ├── watch.ts     # breach-gate watch
│   │       ├── init.ts      # breach-gate init
│   │       └── doctor.ts    # breach-gate doctor
│   ├── core/                # Config loader, logger, process runner
│   ├── orchestrator/        # Scan orchestration, environment management
│   ├── scanners/
│   │   ├── ai/              # AI behavioral tester
│   │   ├── graphql/         # GraphQL security prober
│   │   ├── static/          # Trivy SAST
│   │   ├── container/       # Trivy image scanning
│   │   ├── dynamic/         # OWASP ZAP
│   │   └── frontend/        # Frontend scanner
│   │       ├── semgrep.runner.ts     # React/TS static rules
│   │       ├── gitleaks.runner.ts    # Secrets detection
│   │       ├── osv.runner.ts         # Dependency vulnerabilities
│   │       ├── project.checks.ts     # lint / typecheck / build
│   │       └── frontend.scanner.ts   # Orchestrator
│   ├── findings/            # Attack analysis, risk scoring, remediation
│   ├── policy/              # Baseline and suppression
│   └── reports/             # JSON, Markdown, SARIF, HTML generators
├── demo/                    # Vulnerable Node.js API demo
├── demo-frontend/           # Vulnerable React app demo
│   ├── src/
│   │   ├── services/
│   │   │   ├── auth.ts      # localStorage tokens, hardcoded keys, http://
│   │   │   └── api.ts       # postMessage *, innerHTML, eval()
│   │   └── components/
│   │       ├── SearchResults.tsx   # dangerouslySetInnerHTML
│   │       └── AdminPanel.tsx      # client-side role check
│   └── security.config.yml  # frontend-only config
├── .breachgateignore.example
└── security.config.yml
```

## CI/CD Integration

```yaml
# GitHub Actions example — API + frontend
- name: Run Breach Gate
  uses: epten08/breach-gate@v1
  with:
    config: security.config.yml
    target: ${{ vars.STAGING_API_URL }}
    output: security-reports
    format: json,markdown,sarif
    scan-args: --profile main --frontend --frontend-path ./frontend

- name: Upload security reports
  uses: actions/upload-artifact@v4
  if: always()
  with:
    name: security-reports
    path: security-reports/
```

Full CI/CD docs: [GitHub Actions](docs/ci/github-actions.md) · [GitLab CI](docs/ci/gitlab-ci.md) · [Azure Pipelines](docs/ci/azure-pipelines.md) · [Policy profiles](docs/ci/policy.md)

## Troubleshooting

### "Semgrep not found"
Frontend static analysis skipped. Install with:
```bash
pip install semgrep       # or: brew install semgrep
```
Or skip it: `breach-gate scan --frontend --skip-static`

### "Gitleaks not found"
Secrets detection skipped. Install with:
```bash
brew install gitleaks
# or download from: https://github.com/gitleaks/gitleaks/releases
```

### "osv-scanner not found"
Falls back to `npm audit` automatically — no action needed.
To install osv-scanner:
```bash
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
```

### "No lockfile found — run npm install first"
The dependency scanner needs a lockfile. Run `npm install` in the frontend project directory first.

### "Trivy not found"
Breach Gate can use Trivy via Docker. Ensure Docker is running, or:
```bash
breach-gate scan --skip-static --skip-container
```

### "ZAP not found"
Breach Gate can use ZAP via Docker. Or:
```bash
breach-gate scan --skip-dynamic
```

### "Ollama connection refused"
```bash
ollama serve
```
Or switch to a cloud provider, or skip AI testing:
```bash
breach-gate scan --skip-ai
```

### "Anthropic / OpenAI API key not configured"
```bash
export ANTHROPIC_API_KEY=sk-ant-...
# or
export OPENAI_API_KEY=sk-...
```

## Deploying Breach Gate

### npm package

```bash
npx breach-gate@latest scan --ci --config security.config.yml --profile main
```

### Docker image

```bash
docker run --rm \
  -v "$PWD:/workspace" -w /workspace \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/epten08/breach-gate:latest \
  scan --ci --config security.config.yml --profile main
```

### GitHub Action

```yaml
- uses: epten08/breach-gate@v1
  with:
    config: security.config.yml
    target: ${{ vars.STAGING_API_URL }}
    scan-args: --profile main --frontend --frontend-path ./frontend
```

## License

MIT
