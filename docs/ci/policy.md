# Policy Profiles And Baselines

Breach Gate can apply a policy profile after scanning. The scanner still records all findings, but deployment decisions can be made from the effective findings after baseline suppression.

## Built-In Profiles

| Profile | Intended Use | Behavior |
|---------|--------------|----------|
| `pull-request` | PR checks | Fails on confirmed exploits, incomplete scans, scanner failures, any critical finding, or any high finding. Defaults to differential mode. |
| `main` | Protected branch gate | Fails on confirmed exploits, incomplete scans, scanner failures, any critical finding, or any high finding. |
| `release` | Release gate | Same as `main`, intended for final deployment checks. |
| `nightly` | Scheduled deeper scans | Fails on confirmed exploits, incomplete scans, scanner failures, any critical finding, or more than five high findings. |

Use a profile from the CLI:

```bash
breach-gate scan --ci --profile pull-request --format json,markdown,sarif
```

Or configure it:

```yaml
policy:
  profile: main
```

## Custom Profile Overrides

```yaml
policy:
  profile: release
  profiles:
    release:
      failOnConfirmedExploit: true
      failOnInconclusive: true
      failOnScannerFailure: true
      maxCritical: 0
      maxHigh: 0
      differentialOnly: false
```

## Baseline File

Baselines are for findings that have been reviewed and accepted temporarily. Each entry needs an owner, reason, and expiry date.

```yaml
version: "1.0"
findings:
  - fingerprint: "0123456789abcdef"
    owner: "payments-team"
    reason: "Legacy endpoint will be replaced by 2026 Q3."
    expires: "2026-09-30"
```

Reference a baseline from config:

```yaml
policy:
  profile: pull-request
  baselinePath: ./.breach-gate-baseline.yml
  differentialOnly: true
```

Or from the CLI:

```bash
breach-gate scan --ci --profile pull-request --baseline ./.breach-gate-baseline.yml --differential
```

## Finding Fingerprints

Fingerprints are emitted in the JSON report under:

- `policyEvaluation.effectiveFindingFingerprints`
- `policyEvaluation.suppressedFindingFingerprints`

Add only reviewed findings to the baseline. Expired baseline entries stop suppressing findings.

## Differential Mode

Differential mode is designed for legacy projects. It lets teams start using Breach Gate without immediately blocking on every known historical issue. The gate fails on new findings that are not covered by the baseline.

Recommended adoption:

1. Run a full scan and review the JSON report.
2. Add accepted legacy findings to `.breach-gate-baseline.yml`.
3. Use `--profile pull-request --baseline ./.breach-gate-baseline.yml --differential` in PR checks.
4. Burn down baseline entries over time by fixing findings before their expiry dates.

