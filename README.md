# Breach Gate

**Attack Feasibility Analyzer** - CLI-based automated security analysis tool for REST APIs. Goes beyond vulnerability detection to answer the key question: **"Is it safe to deploy?"**

Combines static analysis, container scanning, dynamic API testing, and AI-assisted behavioral testing to provide deployment verdicts with contextual remediation.

## What Makes This Different

Most security scanners answer: *"What vulnerabilities exist?"*

Breach Gate answers: **"Can an attacker actually compromise the system?"**

| Traditional Scanner | Breach Gate |
|---------------------|--------------|
| Lists vulnerabilities | Analyzes attack feasibility |
| Severity-based sorting | Risk = Impact × Exploitability × Reachability × Confidence |
| Generic recommendations | Contextual remediation with code examples |
| Pass/fail on severity | **Deployment verdict: SAFE / UNSAFE / REVIEW_REQUIRED** |

## Features

- **Attack Feasibility Analysis** - Multiplicative risk scoring: reachability × exploitability × impact × confidence
- **Deployment Verdicts** - Clear SAFE/UNSAFE/REVIEW_REQUIRED decisions with reasons
- **Attack Chain Detection** - Identifies multi-step attack paths (e.g., Auth Bypass → Data Exfiltration)
- **Confirmed Exploit Tracking** - AI/dynamic testing success = auto-critical priority
- **Endpoint Correlation** - Groups findings by attack surface area
- **Contextual Remediation** - Specific fixes with code examples, not generic advice
- **Multi-Scanner Integration** - Trivy (SAST), ZAP (DAST), Container scanning, AI behavioral testing
- **CI Auth And Safety** - Short-lived auth hooks, multi-role scans, session cookies, AI replay artifacts, and active-scan guardrails

## Quick Start

```bash
# Install
npm install
npm run build

# Start demo vulnerable API
npm run demo

# Run attack feasibility analysis
npm run scan -- -t http://localhost:3000 -v
```

## Sample Output

```
═══════════════════════════════════════════════════════════
                    SCAN RESULTS
═══════════════════════════════════════════════════════════

  SECURITY VERDICT:

  ╔════════════════════════════════════════════════════════╗
  ║            ⛔  UNSAFE TO DEPLOY  ⛔                    ║
  ╚════════════════════════════════════════════════════════╝

  Reason: Confirmed exploitation: SQL Injection, Command Injection. Active attacks succeeded during testing.

  ⚡ 2 CONFIRMED EXPLOITS:
     • SQL Injection on POST /api/data
     • Command Injection on POST /api/execute

  Attack Surface (by endpoint):

  POST /api/execute
     Risk: ████████████████████ 95%
     ├── Command Injection
     └── Attack chain: Command Injection → Full System Compromise

  POST /api/data
     Risk: ██████████████████░░ 90%
     ├── SQL Injection
     └── Attack chain: Injection → System Compromise

═══════════════════════════════════════════════════════════
  DEPLOYMENT BLOCKED
  2 confirmed exploit(s) must be fixed before deployment.
═══════════════════════════════════════════════════════════
```

## Prerequisites

### Required

- **Node.js** >= 18.0.0
- **npm** >= 8.0.0

### Optional (for full scanning capabilities)

| Tool | Purpose | Installation |
|------|---------|--------------|
| **Docker** | Container scanning, ZAP/Trivy via containers | [docker.com](https://www.docker.com/get-started) |
| **Trivy** | Static analysis & container vulnerability scanning | [trivy docs](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) |
| **OWASP ZAP** | Dynamic API security testing | [zaproxy.org](https://www.zaproxy.org/download/) |
| **AI Provider** | LLM for AI-assisted behavioral testing — pick one: Anthropic, OpenAI, or Ollama (local) | See [AI Provider Setup](#ai-provider-setup) |

### Installing Prerequisites

**Windows (with winget):**
```bash
winget install Docker.DockerDesktop
winget install AquaSecurity.Trivy
# Optional: only needed for local Ollama
winget install Ollama.Ollama
```

**macOS (with Homebrew):**
```bash
brew install --cask docker
brew install trivy
# Optional: only needed for local Ollama
brew install ollama
```

**Linux (Ubuntu/Debian):**
```bash
# Docker
curl -fsSL https://get.docker.com | sh

# Trivy
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy

# Optional: only needed for local Ollama
curl -fsSL https://ollama.ai/install.sh | sh
```

## Developer Setup

Use this path if you are cloning the repository to develop Breach Gate itself.

### 1. Install dependencies

```bash
npm install
```

Node.js 20 is the easiest target because it matches the repository CI and release workflows.

### 2. Add local environment values

If you need cloud AI providers or protected API credentials locally, create a `.env` from `.env.example` and add only the values you need.

Common variables:

- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`
- `JWT_TOKEN`
- `API_KEY`
- `ZAP_API_KEY`

### 3. Verify the repository

```bash
npm run typecheck
npm test
npm run test:cli
npm run build
```

Or run the main local verification path in one command:

```bash
npm run test:all
```

### 4. Bootstrap a starter config

```bash
npm run dev -- init --baseline --ci-provider github
```

That creates:

- `security.config.yml`
- `.breach-gate-baseline.yml`
- `.github/workflows/breach-gate.yml`

### 5. Validate local prerequisites

```bash
npm run dev -- doctor --config security.config.yml
```

Use `--ci` when you want to confirm that the enabled scanners and target are suitable for pipeline execution.

### Common Developer Commands

| Command | Purpose |
|--------|---------|
| `npm run dev -- scan ...` | Run the CLI from source with `tsx` |
| `npm run scan -- ...` | Shortcut for `scan` during local development |
| `npm run demo` | Start the intentionally vulnerable demo API |
| `npm run typecheck` | TypeScript validation |
| `npm test` | Integration tests |
| `npm run test:cli` | CLI exit-code, schema, and multi-config tests |
| `npm run build` | Compile the CLI into `dist/` |
| `npm run sbom -- sbom.cdx.json` | Generate a CycloneDX SBOM for the package |

## Usage

```bash
# Run with tsx (development)
npm run dev -- scan [options]

# Or use the scan shortcut
npm run scan -- [options]

# Or directly
npx tsx src/cli/index.ts scan [options]
```

### Commands

#### `scan`

Run attack feasibility analysis against a target API.

```bash
breach-gate scan [options]
```

**Options:**

| Option | Description |
|--------|-------------|
| `-c, --config <path>` | Path to config file (default: `security.config.yml`) |
| `--configs <paths>` | Comma-separated config files for monorepo or multi-service scans |
| `--workdir <path>` | Working directory used to resolve config, compose, report, and scanner paths |
| `-t, --target <url>` | Target URL (overrides config) |
| `-o, --output <dir>` | Output directory for reports |
| `-f, --format <formats>` | Output formats, comma-separated: `markdown`, `json`, `sarif` |
| `--fail-on <severity>` | Legacy: fail on severity (now uses attack feasibility) |
| `--profile <name>` | Policy profile: `pull-request`, `main`, `release`, `nightly` |
| `--baseline <path>` | Path to baseline/ignore file |
| `--differential` | Fail only on findings not covered by the baseline |
| `-v, --verbose` | Enable verbose output with attack chains and remediations |
| `-q, --quiet` | Suppress non-essential output |
| `--ci` | **CI mode** - minimal, deterministic output for pipelines |
| `--skip-static` | Skip static analysis |
| `--skip-container` | Skip container scanning |
| `--skip-dynamic` | Skip dynamic API scanning |
| `--skip-ai` | Skip AI-assisted behavioral testing |
| `-h, --help` | Display help |

#### `init`

Create starter configuration and optional baseline/CI files.

```bash
breach-gate init --baseline --ci-provider github
```

#### `doctor`

Check local or CI prerequisites.

```bash
breach-gate doctor --ci --config security.config.yml
```

### Examples

```bash
# Full attack feasibility analysis
breach-gate scan -t http://localhost:3000 -v

# Quick scan (static + container only)
breach-gate scan -t http://localhost:3000 --skip-dynamic --skip-ai

# AI-focused testing
breach-gate scan -t http://localhost:3000 --skip-static --skip-container -v

# Output reports for CI/CD integration
breach-gate scan -t http://localhost:3000 -f json,markdown -o ./reports

# CI mode - minimal, deterministic output
breach-gate scan -t http://localhost:3000 --ci
# Output:
# SECURITY STATUS: PASSED|FAILED|INCONCLUSIVE
# Reason: <one-line reason>

# Monorepo scan across multiple service configs
breach-gate scan --ci --configs services/api/security.config.yml,services/admin/security.config.yml --output ./security-reports

# Run from a service directory without cd-ing into it
breach-gate scan --ci --workdir services/api --config security.config.yml
```

## Local Development Workflow

### Run the demo target

Start the vulnerable API in one terminal:

```bash
npm run demo
```

Run Breach Gate against it from another terminal:

```bash
npm run scan -- -t http://127.0.0.1:3000 -v
```

If you want to use the demo-specific config file instead of the repository root config:

```bash
npm run dev -- scan --workdir demo --config security.config.yml
```

### Work on one service in a monorepo

```bash
npm run dev -- scan --workdir services/payments --config security.config.yml --ci
```

### Scan multiple service configs in one run

```bash
npm run dev -- scan --ci --configs services/api/security.config.yml,services/admin/security.config.yml --output ./security-reports
```

### Exit Codes

| Code | Verdict | Description |
|------|---------|-------------|
| `0` | SAFE | No exploitable vulnerabilities detected |
| `0` | REVIEW_REQUIRED | Findings need review, but no confirmed exploits |
| `1` | UNSAFE | Confirmed exploits detected - deployment blocked |
| `1` | INCONCLUSIVE | Scan failed - cannot verify security, failing safely |
| `2` | - | Configuration error |

**Key principle:** `SCAN FAILED ≠ NO VULNERABILITIES`. If scanners fail, the verdict is `INCONCLUSIVE` and exits non-zero.

## How Attack Feasibility Works

Traditional scanners use simple severity (LOW/MEDIUM/HIGH/CRITICAL). Breach Gate uses **multiplicative risk scoring**:

```
risk = impact × exploitability × reachability × confidence
```

### Risk Factors

| Factor | Description | Sources |
|--------|-------------|---------|
| **Reachability** | Can attacker access this? | Endpoint analysis, auth requirements |
| **Exploitability** | Is exploit demonstrated? | AI success, ZAP active scan, CVE data |
| **Impact** | What damage is possible? | Category mapping (RCE=1.0, XSS=0.75, etc.) |
| **Confidence** | How strong is evidence? | Source type, evidence quality, deduplication |

### Confirmed Exploits

When AI or dynamic testing **successfully exploits** a vulnerability:
- Automatically marked as confirmed
- Minimum feasibility score of 0.8
- Verdict becomes UNSAFE
- Prioritized for immediate remediation

## Reports

### Security Verdict

Every report leads with the deployment decision:

```markdown
## Security Verdict

╔══════════════════════════════════════════════════════════╗
║              ⛔  UNSAFE TO DEPLOY  ⛔                     ║
╚══════════════════════════════════════════════════════════╝

**Reason:** Confirmed exploitation: SQL Injection, Command Injection.

### ⚡ Confirmed Exploits

These vulnerabilities were **actively exploited** during testing:

- **SQL Injection** on `POST /api/data`
- **Command Injection** on `POST /api/execute`
```

### Attack Surface Analysis

```markdown
| Endpoint | Risk | Vulnerabilities | Attack Feasibility |
|----------|------|-----------------|-------------------|
| `POST /api/execute` | 🔴 95% | Command Injection | High |
| `POST /api/data` | 🔴 90% | SQL Injection | High |
| `GET /api/users/:id` | 🟠 65% | Broken Access Control | Medium |
```

### Contextual Remediation

Instead of generic advice, you get specific fixes:

```markdown
### 🚨 SQL Injection

**Endpoint:** `POST /api/data`
**Priority:** IMMEDIATE

**Fix:** Parameterize query on POST /api/data for parameter 'id'

**Example:**
```javascript
// Instead of:
db.query(`SELECT * FROM users WHERE id = ${id}`);

// Use:
db.query('SELECT * FROM users WHERE id = ?', [id]);
```

## Configuration

Create a `security.config.yml` file in your project root:

```yaml
version: "1.0"

target:
  baseUrl: http://localhost:3000
  healthEndpoint: /health

  # Endpoints for AI testing (if no OpenAPI spec)
  endpoints:
    - path: /api/login
      method: POST
      body:
        username: test
        password: test
    - path: /api/users
      method: GET
      params:
        id: "1"

auth:
  type: none
  # type: jwt
  # token: ${JWT_TOKEN}

scanners:
  static:
    enabled: true
    trivy:
      severityThreshold: MEDIUM

  container:
    enabled: true
    images:
      - my-app:latest

  dynamic:
    enabled: true
    zap:
      apiScanType: api
      maxDuration: 300

  ai:
    enabled: true
    provider: anthropic        # ollama | openai | anthropic
    model: claude-haiku-4-5-20251001
    maxTests: 15

thresholds:
  failOn: HIGH
  warnOn: MEDIUM

policy:
  profile: main
  # baselinePath: ./.breach-gate-baseline.yml
  # differentialOnly: true

reporting:
  outputDir: ./security-reports
  formats:
    - markdown
    - json
    - sarif
  includeEvidence: true
```

## AI-Assisted Behavioral Testing

The AI scanner is the **key differentiator**. It:
- Understands endpoint semantics and business logic
- Generates context-aware attack payloads
- Confirms exploitation with actual requests
- Provides high-confidence findings

### Why AI Findings Matter More

| Source | Confidence | Why |
|--------|------------|-----|
| Static (Trivy) | Medium | Theoretical - pattern matching |
| Dynamic (ZAP) | High | Active testing, but generic |
| **AI Tester** | Very High | Context-aware behavioral testing |

When AI successfully exploits a vulnerability, it's a **confirmed attack path**.

## AI Provider Setup

Breach Gate supports three AI providers. Pick one and configure it in `security.config.yml`.

### Anthropic (recommended for CI/CD)

No local server required. Get an API key from [console.anthropic.com](https://console.anthropic.com/settings/keys).

```bash
# .env
ANTHROPIC_API_KEY=sk-ant-...
```

```yaml
# security.config.yml
scanners:
  ai:
    enabled: true
    provider: anthropic
    model: claude-haiku-4-5-20251001   # fast and cost-effective
    maxTests: 15
```

| Model | Speed | Best for |
|-------|-------|----------|
| `claude-haiku-4-5-20251001` | Fastest | CI pipelines, high test volume |
| `claude-sonnet-4-6` | Balanced | Better reasoning on complex vulnerabilities |
| `claude-opus-4-7` | Thorough | Highest quality, nightly or release scans |

### OpenAI

```bash
# .env
OPENAI_API_KEY=sk-...
```

```yaml
scanners:
  ai:
    enabled: true
    provider: openai
    model: gpt-4o-mini    # or gpt-4o
    maxTests: 15
```

### Ollama (local, no API key needed)

Requires a running Ollama server. Good for air-gapped environments.

```bash
# Install and start
ollama serve
ollama pull llama3

# Verify
curl http://localhost:11434/api/tags
```

```yaml
scanners:
  ai:
    enabled: true
    provider: ollama
    model: llama3:8b
    baseUrl: http://localhost:11434    # optional, this is the default
    maxTests: 15
```

| RAM | Recommended model |
|-----|------------------|
| 16 GB+ | `llama3:8b` |
| 8 GB | `llama3:8b-q4_0` |
| GPU | `codellama:13b` |

## Demo

A vulnerable demo API is included:

```bash
# Start demo API (intentionally vulnerable)
npm run demo

# Run full analysis
npm run scan -- -t http://localhost:3000 -v
```

Demo vulnerabilities:
- SQL Injection
- Command Injection
- Path Traversal
- IDOR (Broken Access Control)
- Information Disclosure
- Missing Security Headers

## Project Structure

```
breach-gate/
├── src/
│   ├── cli/           # CLI commands and options
│   ├── core/          # Config loader, logger, process runner
│   ├── orchestrator/  # Scan orchestration, environment management
│   ├── scanners/      # Scanner implementations (Trivy, ZAP, AI)
│   ├── findings/      # Attack analysis, risk scoring, remediation
│   │   ├── attack.analyzer.ts  # Attack feasibility analysis
│   │   ├── risk.engine.ts      # Risk scoring
│   │   └── normalizer.ts       # Finding normalization
│   ├── reports/       # Report generators with verdict
│   └── ai/            # LLM integration, behavioral testing
├── demo/              # Vulnerable demo API
└── security.config.yml
```

## Deploying Breach Gate

There are two common deployment stories:

1. deploy Breach Gate into another repository or CI/CD pipeline
2. publish a new Breach Gate release for other teams to consume

### Use Breach Gate in another project

You can deploy it into a target pipeline in three main ways.

#### Option 1: npm package

```bash
npx breach-gate@1.0.0 scan --ci --config security.config.yml --profile main --format json,markdown,sarif --output security-reports
```

Use this when the pipeline already has Node available.

#### Option 2: Docker image

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  -w /workspace \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/OWNER/breach-gate:1.0.0 \
  scan --ci --config security.config.yml --profile main --format json,markdown,sarif --output security-reports
```

Use this when you want a pinned runtime with the CLI and Trivy already present.

#### Option 3: GitHub Action

```yaml
- name: Run Breach Gate
  uses: OWNER/breach-gate@v1
  with:
    config: security.config.yml
    target: ${{ vars.STAGING_API_URL }}
    output: security-reports
    format: json,markdown,sarif
    scan-args: --profile main
```

Use this when you want the shortest GitHub Actions setup path.

### Release a new Breach Gate version

For maintainers, the release flow is:

```bash
npm install
npm run test:all
npm audit --omit=dev
npm run sbom -- sbom.cdx.json
git tag v1.2.3
git push origin v1.2.3
```

Pushing a semantic version tag triggers `.github/workflows/release.yml`, which verifies the package and publishes:

- the npm package
- the GHCR container image
- the CycloneDX SBOM artifact
- npm provenance
- container provenance and SBOM attestations

Manual dry runs are also available through the `workflow_dispatch` input on the release workflow.

### Repository CI

The repository CI workflow lives at `.github/workflows/ci.yml` and runs:

- `npm run typecheck`
- `npm test`
- `npm run test:cli`
- `npm run build`
- `npm audit --omit=dev`
- `npm run sbom -- security-reports/sbom.cdx.json`
- `npm pack --dry-run`
- a demo API scan smoke test

## CI/CD Integration

First-party CI/CD examples are available in:

- [Repository release publishing](docs/ci/releasing.md)
- [GitHub Actions](docs/ci/github-actions.md)
- [GitLab CI](docs/ci/gitlab-ci.md)
- [Azure Pipelines](docs/ci/azure-pipelines.md)
- [Policy profiles and baselines](docs/ci/policy.md)
- [Auth, AI replay, and safety profiles](docs/ci/auth-and-safety.md)
- [Code scanning and PR feedback](docs/ci/code-scanning.md)

```yaml
# GitHub Actions example
- name: Run Breach Gate
  uses: OWNER/breach-gate@v1
  with:
    config: security.config.yml
    target: ${{ vars.STAGING_API_URL }}
    output: security-reports
    format: json,markdown,sarif
    scan-args: --profile main

- name: Upload security reports
  uses: actions/upload-artifact@v4
  if: always()
  with:
    name: security-reports
    path: security-reports/
```

## Troubleshooting

### "Trivy not found"
Breach Gate can use Trivy via Docker. Ensure Docker is running, or:
```bash
breach-gate scan --skip-static --skip-container
```

### "ZAP not found"
Breach Gate can use ZAP via Docker (`ghcr.io/zaproxy/zaproxy`). Or:
```bash
breach-gate scan --skip-dynamic
```

### "Ollama connection refused"
```bash
ollama serve  # Start the server first
```
Or switch to a cloud provider (no local server needed) — see [AI Provider Setup](#ai-provider-setup).
Or skip AI testing entirely:
```bash
breach-gate scan --skip-ai
```

### "Anthropic API key not configured" / "OpenAI API key not configured"
Set the key in your `.env` file or export it in your shell:
```bash
export ANTHROPIC_API_KEY=sk-ant-...
# or
export OPENAI_API_KEY=sk-...
```

### Low-confidence findings
Run with AI enabled - it provides the highest confidence through behavioral testing:
```bash
breach-gate scan -t http://localhost:3000 -v
```

## License

MIT

