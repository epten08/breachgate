# Breach Gate: Brutal Audit

Reviewed 30 July 2026 against commit `2e9086d`, npm `breach-gate@1.2.3`.
Scope: 11,637 lines of TypeScript in `src`, 1,108 lines of tests, 796 line README.

> **Status: remediated in v2.0.0.** Every defect below has been fixed and each
> one now has a regression test. See [Remediation](#remediation) at the end of
> this document for what changed and how it was verified. The findings are kept
> here unedited, because the reasoning that produced them is the thing worth
> keeping.

## Verdict first

The engineering discipline here is real. The core product logic is broken in a way that inverts the product's entire promise, and I proved it by running the code, not by reading it.

Breach Gate exists to answer "is it safe to deploy?" I pointed it at an API with no vulnerabilities whatsoever, a five line HTTP server that returns static JSON with no database, no reflection, no shell, and no error leakage. Breach Gate reported a **confirmed SQL injection exploit** and blocked the deploy.

That is not a tuning problem. It is the product failing at the only thing it claims to do better than everyone else.

## What is genuinely good

Do not let the rest of this document erase these. They are not common in solo projects.

The repository hygiene is above the median for funded startups. Typecheck passes clean with strict TypeScript. There is a real CI workflow, npm provenance, container provenance, SBOM generation, a CycloneDX pipeline, CODEOWNERS, issue templates including a dedicated false positive template, a security policy, and a contributing guide. The package publishes with signed attestations. Someone who does this understands shipping.

The layering is correct in shape. Scanners implement a common interface, findings flow through a normalizer into a deduplicator into an analyzer into pluggable reporters, and the orchestrator owns lifecycle. Adding a scanner touches one directory. That is the right architecture for this problem.

Two design decisions are better than what several commercial tools do. First, `INCONCLUSIVE` as a distinct verdict with a non-zero exit code, so a crashed scan cannot masquerade as a clean bill of health. Most tools silently pass. Second, the safety layer: `enforceTargetSafety` refuses production-looking hostnames in CI unless explicitly overridden, destructive HTTP methods are gated behind a profile, and there is host allowlisting and path exclusion. Someone thought about the liability of shipping an active attack tool. That is mature.

The multi-format reporting including SARIF is the correct integration surface for GitHub code scanning, and the suppression plus baseline split (permanent acceptance versus tracked temporary waiver) is a genuinely thoughtful distinction that many tools conflate.

## The fatal defect

### Reproduction

Target: a server with zero vulnerabilities. Its only deviation from best practice is that it does not set three response headers.

```js
http.createServer((_req, res) => {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ items: [{ id: 1, name: "widget" }] }));
}).listen(4399);
```

One AI test case, category `SQL Injection`, expecting `syntax error` in the body. Running the real `TestExecutor`, `TestEvaluator`, `normalizeFindings`, and `AttackAnalyzer`:

```
[CRITICAL] SQL injection in items query

matchedCriteria: ["Missing security header: x-content-type-options",
                  "Missing security header: x-frame-options",
                  "Missing security header: strict-transport-security"]
isVulnerable: true

RAW FINDING: SQL Injection / CRITICAL
evidence: "Response Status: 200
           Matched: Missing security header: x-content-type-options, ...
           Response: {"items":[{"id":1,"name":"widget"}]}"

>>> VERDICT: UNSAFE
>>> REASON: database access via SQL injection on GET /api/items
>>> confirmedExploits: [ 'SQL Injection' ]
```

Read the evidence field. It states plainly that the only thing matched was three missing headers, and it prints a clean JSON body with no SQL error. The tool then reports database access via SQL injection as a confirmed exploit and blocks the deploy.

### Root cause

Four independent defects compound. Any one alone would be survivable.

In `src/ai/executor.ts`, `evaluateResponse` appends a criterion for every missing header on every 2xx response, regardless of what the test was actually probing:

```ts
const securityHeaders = ["x-content-type-options", "x-frame-options", "strict-transport-security"];
for (const header of securityHeaders) {
  if (!headers[header] && !expected.headerMissing?.includes(header)) {
    matchedCriteria.push(`Missing security header: ${header}`);
  }
}
```

Then `isVulnerable` is defined as `matchedCriteria.length > 0`, so a header miss becomes evidence of exploitation.

Then `src/ai/evaluator.ts` classifies the finding by dispatching on `testCase.category` through roughly ten branches before it ever asks whether any criterion was substantive. The guard that filters out pure header misses does exist, and the comment above it shows the author was aware of the problem, but it sits after the category branches so it almost never executes. The header misses get relabeled as whatever attack the test case happened to be named.

Then `src/findings/attack.analyzer.ts` accepts `Response Status:` plus `Matched:` in the evidence string as proof of exploitation, so the mislabeled finding becomes a confirmed exploit, which short circuits directly to `UNSAFE`.

### Why this is not a niche edge case

HSTS is absent from every plain HTTP target, which means every local run and most staging environments. `X-Frame-Options` and `X-Content-Type-Options` are commonly set at the CDN or ingress rather than the origin, which is exactly the topology of most deployed APIs. So the trigger condition is not rare. It is the default.

The failure mode is also the worst possible shape. It is not a noisy extra finding you learn to ignore. It fabricates a CRITICAL confirmed breach, names a specific attack class that did not happen, writes a specific operational claim ("database access via SQL injection"), and exits non-zero. In CI that blocks every deploy. The first engineer who investigates and finds nothing wrong will delete the job, and they will be right to.

The author noticed the symptom and shipped a workaround instead of a fix. The README recommends suppressing `Missing security header` with the reason "Security headers are added at the CDN layer." That workaround does not help. Suppression in `src/policy/suppression.ts` matches against title or category, and the mislabeled finding's category is `SQL Injection`. To silence it you would have to suppress SQL injection globally, which defeats the tool.

### A second false positive path

The same trust in ZAP's source label produces a second one. `isExploitConfirmed` returns `true` for every finding sourced from `OWASP ZAP API`, unconditionally, with no check on risk code. ZAP's passive scanner emits informational alerts by design. `parseAlerts` tags all of them with the same source, and nothing filters `riskcode: 0`. Verified:

```
Input:  ZAP passive INFO alert, "Timestamp Disclosure"
Output: VERDICT UNSAFE, "Sensitive data leak from GET /api/health", 1 confirmed exploit

Input:  ZAP LOW alert, "X-Content-Type-Options Header Missing"
Output: VERDICT UNSAFE, "Confirmed exploitation: Missing Security Header.
        Active attacks succeeded during testing."
```

A missing header is reported as an active attack that succeeded. Enabling ZAP on any real target guarantees dozens of passive alerts, so this path alone makes `UNSAFE` the permanent verdict.

### A false negative path

`TestExecutor.execute` catches per test failures into `logger.debug` and continues. If every request fails with a network error, the scanner returns an empty array and is recorded as having completed successfully, not as failed. The `INCONCLUSIVE` protection operates at scanner granularity, so it does not fire. A misconfigured target URL therefore yields `SAFE`, which is the exact failure the README says the design prevents.

## Architectural problems

There are two competing risk engines with contradictory mathematics. `RiskEngine.calculateCompositeScore` is additive:

```ts
const composite = severityWeight * 0.3 + exploitability * 0.4 + confidence * 0.3;
```

`AttackAnalyzer.analyzeAttackVector` is multiplicative across four factors. Both write a number called risk onto the same finding, both appear in reports, and they disagree. The verdict uses one, the sorting and the report tables use the other. `calculateExploitability` and `calculateConfidence` exist in both classes with different logic, and because `AttackAnalyzer` consumes `finding.confidence` that `RiskEngine` already computed and then boosts it again, confidence is inflated twice.

The multiplicative formula, the headline differentiator, is then defeated by patches. A confirmed exploit is floored at 0.8, frontend findings get a severity floor, and combined risk gets a vector count bonus and a confirmed bonus. Every one of those overrides exists because the multiplication kept collapsing scores the author knew were important. That is the formula telling you it is wrong and the code arguing with it.

The README's central claim is `risk = impact × exploitability × reachability × confidence`. The word "reachability" appears zero times in `risk.engine.ts`. In `attack.analyzer.ts` it is a string inspection of the URL path: `+0.1` if the path contains `/api/`, `-0.2` if it contains `/admin`. That is not reachability analysis. Reachability in 2026 means function level call graph analysis proving the vulnerable code path is invoked. Marketing a substring check as reachability in a security tool is the kind of claim that costs credibility permanently once someone checks.

There is no exploit intelligence at all. No EPSS, no CISA KEV, no CVSS vector parsing. Exploitability is a hardcoded lookup table of author intuitions, and `hasKnownExploit` is literally `raw.cve && raw.severityHint === "CRITICAL"`. `RiskFactors.cvssScore` is declared and never populated. The OSV runner parses a CVSS score, converts it to a coarse severity bucket, and discards the number.

Seven files ship empty in the published package: `src/findings/severity.ts`, `src/orchestrator/pipeline.ts`, `src/utils/time.ts`, and all four files in `src/types`. Scaffolding that was never filled in and never removed.

Finally, the tool contributes no detection capability of its own. Every finding originates from Trivy, ZAP, Semgrep, Gitleaks, OSV Scanner, or npm audit. Breach Gate is a scoring and reporting layer over other people's scanners. That is a legitimate product category, and it is also the category where the scoring layer is the entire value, which is why the scoring being wrong is fatal rather than inconvenient.

## Testing

Forty five tests across two files for 11,637 lines. That ratio is not the problem by itself. The distribution is.

`attack.analyzer.ts` is 1,019 lines and holds the verdict logic, the breach classifier, the attack chain detector, and the feasibility formula. It is the product. It has roughly four assertions against it, all routed through `generateVerdictWithStatus` and mostly checking the scan failure path. `isExploitConfirmed`, `calculateReachability`, `classifyBreach`, and `identifyAttackChains` have no direct tests. `risk.engine.ts` is 540 lines with no dedicated test file.

This is precisely why the defect above shipped. A single test asserting that a clean 200 response with no headers does not produce a confirmed SQL injection would have caught it. The CI smoke test scans the deliberately vulnerable demo API, where everything is genuinely broken and `UNSAFE` is correct for the wrong reasons. There is no negative control anywhere in the suite. For a tool whose output is a boolean gate, the absence of a "clean target stays clean" test is the single most important gap.

The operator surface is also unusually heavy for a project with one maintainer: Docker, Trivy, ZAP, Semgrep, Gitleaks, OSV Scanner, and an LLM key, plus a 19KB config schema with 108 keys. Each is a support burden and a failure mode.

## Position in the 2026 market

The honest competitive picture is unkind.

The "ZAP engine plus CI automation plus developer friendly reporting" position is already occupied by StackHawk as a funded commercial product. The free tier of that space is ZAP baseline scans plus Nuclei with 11,000 community templates, which is what teams actually wire into pipelines today.

Risk prioritisation has consolidated around a layered standard that Breach Gate does not touch: CVSS for severity, EPSS for exploitation probability in the next thirty days, and CISA KEV for confirmed in the wild exploitation, now with over 1,200 entries and codified in CISA BOD 26-04 as a four factor risk model. Endor Labs claims roughly 95% false positive reduction from function level reachability across 40 plus languages, and after the Autonomous Plane acquisition in February 2026, full stack reachability combining source with dynamic container analysis. Semgrep Supply Chain surfaces the roughly 2% of dependency findings that are actually reachable.

A hand tuned category to coefficient table cannot compete with that, and it does not need to, because the differentiator was never supposed to be the coefficients. It was supposed to be the deploy verdict. That framing is genuinely good and remains underserved. But a verdict is only worth something if it is trustworthy, and a security tool gets exactly one chance. False negatives are dangerous; false positives are fatal to adoption, because a gate that blocks good deploys gets deleted in a week and never reinstalled.

The activity signal is also honest data. Six npm releases between 27 and 30 April, then nothing. Last commit 4 May. Three months dormant as of today.

## What adoption would actually require

In order, because the order matters.

Delete the unconditional header check from `evaluateResponse`. It should only fire when the test case explicitly asked about headers via `expected.headerMissing`, and it should never contribute to `isVulnerable` for a test whose category is an injection class.

Move the substantive criteria filter in `evaluator.ts` to the top of the classifier, before any category branch. If every matched criterion is a header miss, the finding is a `Security Misconfiguration` at MEDIUM, full stop, regardless of what the test was named.

Redefine confirmed exploitation as a whitelist of positive proof rather than a source label. Require an actual signal: a SQL error string, reflected payload, command output, cloud metadata, a timing delta, a 2xx where the baseline was 4xx. Never trust `sources.includes("OWASP ZAP API")` as proof. Filter ZAP `riskcode: 0` entirely and stop mapping ZAP INFO to LOW.

Delete one of the two risk engines. Keep the multiplicative one, remove every floor and bonus, and if removing the floors collapses scores you care about, the factor weights are wrong and need fixing rather than patching.

Then write the negative control suite. A clean target with no headers must return `SAFE`. A ZAP INFO alert alone must return `SAFE`. A single missing header must never be a confirmed exploit. Then a corpus: run against several deliberately vulnerable applications and, more importantly, against several known good ones, and publish measured precision and recall. No security tool gets adopted in 2026 on a claim of accuracy without numbers.

Replace the exploitability table with EPSS and KEV lookups. Both are free HTTP APIs, this is a few hundred lines, and it moves the tool from author intuition to industry standard overnight. It is the single highest leverage credibility change available.

Then fix the README. Either implement reachability or stop calling the path substring check reachability, and correct the model identifiers in the AI provider section, which reference strings that do not exist.

## Final call

Does this have potential to be used by developers in 2026 and beyond?

Not in its current state, and not as currently positioned. Anyone who installs it today against a real API gets `UNSAFE TO DEPLOY` with a fabricated confirmed exploit, and they will uninstall it that afternoon. Shipping it wider right now is worse than not shipping, because a security tool that cries wolf teaches teams to ignore security tools. The three month dormancy also means a prospective adopter sees an unmaintained scanner, which is the least appealing category of dependency there is.

The potential is real but it is not where the README says it is. The reusable assets are the release and provenance engineering, the scanner plugin architecture, the safety guardrails, the `INCONCLUSIVE` verdict, and above all the framing: developers genuinely do not want a list of 400 findings, they want a decision. That framing is correct and still underserved at the open source tier. The category coefficient table is not defensible and never was.

The realistic path is to stop competing on breadth and win narrowly. Drop the frontend scanner, drop GraphQL, drop container scanning. Be one thing: the OpenAPI aware API deploy gate that produces trustworthy verdicts with published precision numbers, EPSS and KEV grounded prioritisation, and evidence a developer can verify in ten seconds. Six scanners at 40% precision is worth nothing. One scanner at 95% precision is worth a company.

The gap between here and there is perhaps two to three months of focused work, and most of it is deletion and testing rather than new features. That is a good position to be in. It is not a good position to publish from.

One process note that matters more than any individual bug. The header defect, the ZAP defect, and the silent network failure share one root cause, which is that verdict logic was written without adversarial tests against known good inputs. The demo target is deliberately vulnerable, so every test confirms the tool says `UNSAFE`, and `UNSAFE` is the tool's failure mode. The suite was structured so that the bug could not be observed. Fix that habit and the rest follows; leave it and the next three defects will ship the same way.

---

# Remediation

Implemented in v2.0.0. Every reproduction in this document was re-run against the fixed code.

## The four proven defects

| # | Before | After |
|---|---|---|
| 1 | Clean API missing headers, test labelled "SQL Injection" → `UNSAFE`, "database access via SQL injection" | `SAFE`, one `LOW` header finding |
| 2 | ZAP passive INFO alert (timestamp disclosure) → `UNSAFE`, "Sensitive data leak" | `SAFE`, alert dropped at the source |
| 3 | ZAP missing-header alert → `UNSAFE`, "Active attacks succeeded during testing" | `SAFE` |
| 4 | Unreachable target → 0 results, scanner marked complete → `SAFE` | Scanner throws → `INCONCLUSIVE`, exit 1 |

Positive control: a genuine SQL injection carrying a `sql-error` proof still returns `UNSAFE` with the quoted excerpt `You have an error in your SQL syntax near "1' OR '1'='1"`.

## What changed

**Confirmation now requires proof.** `Finding.proofs` holds one of nine `ExploitProof` values, and `isExploitConfirmed` is exactly `finding.proofs.length > 0`. Scanner identity, evidence string shape, and severity label no longer participate. Every proof must also be absent from a benign baseline request and must carry a quotable excerpt, so a claim that cannot be verified is not made.

**The header sweep is gone.** `evaluateResponse` collects missing headers into a separate `missingHeaders` field that never touches `matchedCriteria` and never influences `isVulnerable`. Headers are summarised once per scan as a single `LOW` finding with no proof.

**Classification follows the evidence.** The evaluator dispatches on the worst observed proof through `PROOF_CLASSIFICATION`, not on `testCase.category`. A test named "SQL Injection" that only observed a header miss produces nothing.

**ZAP is no longer trusted as an oracle.** Informational (`riskcode` 0) and low-confidence alerts are discarded in `parseAlerts`. Remaining alerts arrive with `proofs: []` and are scored like any unconfirmed finding.

**Failures surface.** `TestExecutor.execute` returns `{ results, erroredTests, skippedTests, attemptedTests }`. Zero results from a non-zero attempt count, or an error rate above 50%, raises `ScannerError`, which the orchestrator turns into `INCONCLUSIVE`.

**One scoring model.** `RiskEngine.calculateCompositeScore` and the deduplicator's third formula are both deleted. `Finding` stores only `confidence`; feasibility is computed on demand through `src/findings/score.ts`, which every reporter and the CLI summary share. All floors and bonuses are removed from the multiplicative formula.

**Exploitability comes from data.** `src/intel/exploit.intel.ts` enriches CVE-bearing findings from CISA KEV and EPSS, cached to disk with a 24h TTL and failing open on network problems. `AttackVector.exploitabilityBasis` records whether a number came from `kev`, `proof`, `epss`, or a `category` guess, and `--explain-verdict` prints it.

**Scope narrowed.** Frontend, GraphQL, and container scanners removed, along with their config, CLI flags, schema entries, and seven empty placeholder files. 11,637 lines down to 10,460, with more capability in the part that matters.

## Verification

| Check | Result |
|---|---|
| `tsc --noEmit` | Clean |
| Negative controls (new) | 14 passed |
| Precision harness (new) | 5 passed, precision 100%, recall 100% |
| Integration | 32 passed |
| CLI | 7 passed |
| ESLint on all changed files | Clean |
| Build | Clean, no stale modules in `dist` |

`test/negative-controls.test.ts` encodes every defect above as a regression test. `test/precision.test.ts` measures precision and recall against a 14-endpoint corpus (`test/corpus/targets.ts`) with declared ground truth, writes `security-reports/precision.json`, and fails the build on a single false positive.

Building the corpus immediately paid for itself by exposing two detector bugs that no amount of code reading had surfaced: the command-output pattern matched `/bin/bash` inside `/etc/passwd`, so reading a file was reported as command execution, and the stack-trace pattern did not allow a space before the opening parenthesis, so V8 traces were missed entirely.

CI now runs the negative controls and the precision gate before lint, tests, or build. If the tool cannot stay quiet on a clean target, nothing else about the build matters.

## Still outstanding

Honest list of what this work did not address.

The corpus is 14 synthetic endpoints. That is enough to catch the failure class found here and to gate CI, but the published precision number means considerably more once it is measured against real applications. Adding third-party vulnerable apps such as VAmPI or crAPI, plus a handful of known-good open source APIs, is the natural next step.

`timing-oracle` is defined and classified but never emitted, because a single slow response is not an oracle and the repeat-request confirmation is not implemented. Timing is currently recorded as an observation only.

Reachability remains a path and auth heuristic. It is now labelled as one in the code and the README rather than being marketed as reachability analysis, but it is not the real thing.

`REVIEW_THRESHOLD` is set at 0.35 by judgement, not by measurement. Once the corpus covers unproven-but-real findings it should be tuned against data.

EPSS and KEV enrichment has no dedicated test that exercises the network path; only the scoring functions that consume the data are covered.
