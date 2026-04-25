# How the Verdict Is Calculated

Breach Gate does not grade you on the number of vulnerabilities found. It asks one question: **can an attacker actually compromise this system right now?**

## The Four-Factor Score

Every finding is evaluated as a potential attack vector using four multiplicative factors:

```
Feasibility Score = Reachability × Exploitability × Impact × Confidence
```

| Factor | What it measures | Example values |
|--------|-----------------|----------------|
| **Reachability** | Can an attacker reach this endpoint? | `/api/login` (public) = 0.9 · `/admin/metrics` = 0.5 |
| **Exploitability** | Is exploitation proven or theoretical? | AI/ZAP confirmed = 0.85–0.95 · Static only = 0.5 |
| **Impact** | What damage is possible if exploited? | RCE = 1.0 · SQL Injection = 0.95 · Missing header = 0.25 |
| **Confidence** | How strong is the evidence? | Multiple sources = 0.9 · Single static scanner = 0.6 |

Because the score is **multiplicative**, a finding must score highly across *all* factors to be considered high-risk. A CRITICAL CVE in a vendored dependency that is locked behind multi-factor authentication and has no known public exploit may score 0.3 — not 1.0.

## Confirmed Exploits Override the Score

If a scanner (AI Security Tester or OWASP ZAP Active Scan) **actively demonstrated exploitation**, the finding is classified as a **Confirmed Breach** — not just a high-scoring finding. Confirmed breaches immediately trigger `UNSAFE`, regardless of score:

```
AI Security Tester → SQL payload returned 200 with data → Confirmed breach
```

This distinction matters: a CRITICAL CVSS score from a static scanner is a vulnerability. A successful UNION SELECT returned from your login endpoint is a breach.

## Verdict Thresholds

| Verdict | Condition |
|---------|-----------|
| `UNSAFE` | Any confirmed breach OR unconfirmed finding with impact ≥ 0.9 (RCE-class) |
| `REVIEW_REQUIRED` | Feasibility score ≥ 0.6 on at least one unconfirmed finding |
| `SAFE` | All findings score < 0.6 and none are confirmed |
| `INCONCLUSIVE` | One or more required scanners failed — scan is incomplete |

## Example: Same CVE, Different Verdicts

Consider `CVE-2021-23337` (lodash prototype pollution, HIGH severity):

**Scenario A — internal tooling, no user input:**
- Reachability: 0.4 (internal only)
- Exploitability: 0.5 (static scanner, no exploit demonstrated)
- Impact: 0.5 (dependency vulnerability)
- Confidence: 0.7
- **Score: 0.07 → SAFE** (update lodash, but it won't block your deploy)

**Scenario B — user-controlled input reaches the vulnerable code path:**
- Reachability: 0.9 (public API)
- Exploitability: 0.85 (ZAP confirmed manipulated prototype)
- Impact: 0.8 (data corruption possible)
- Confidence: 0.85
- **Score: 0.52 → REVIEW_REQUIRED**

## How to See the Score Breakdown

Run a scan with `--explain-verdict`:

```bash
breach-gate scan --explain-verdict
```

Output:
```
Score  Finding                                    Factors
-----  ----------------------------------------   -------
 85%   SQL Injection in login endpoint            reach=90% exploit=95% impact=95% conf=80%  [CONFIRMED]
 52%   lodash prototype pollution                 reach=90% exploit=50% impact=50% conf=70%
  7%   Missing X-Content-Type-Options             reach=80% exploit=50% impact=25% conf=70%
```
