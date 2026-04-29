# Baselines — Suppressing Known Findings

Breach Gate has two suppression mechanisms. Use the right one for the job:

| Mechanism | When to use |
|-----------|-------------|
| `.breach-gate-baseline.yml` | **Temporary waivers** — tracked tickets, no upstream fix yet, sprint backlog items. Findings reappear when the entry expires. |
| `.breachgateignore` | **Permanent acceptable findings** — intentional behaviour, headers handled at the CDN, internal-only endpoints. Findings never appear in reports. |

This document covers `.breach-gate-baseline.yml`. For `.breachgateignore`, see the [Finding Suppression section in the README](../README.md#finding-suppression).

---

A baseline lets you acknowledge known findings so they don't block CI while your team works on a fix, without hiding new findings that appear later.

## The Problem

You run Breach Gate on a legacy service. It finds 12 dependency vulnerabilities that are on the roadmap but not blocking this sprint's deploy. Without baselines, CI blocks every PR until all 12 are fixed.

With a baseline, you acknowledge those 12 findings. They're suppressed in future scans. New findings that weren't in the baseline still fail CI.

## Creating a Baseline

Run the init command:

```bash
breach-gate init --baseline
```

This generates `.breach-gate-baseline.yml` from the current scan's findings. Review it — each entry has a fingerprint (a content hash of the finding), an owner, and a reason:

```yaml
version: "1.0"
findings:
  - fingerprint: a1b2c3d4e5f6...
    owner: security-team
    reason: "Tracked in JIRA SEC-123, scheduled for next sprint"
    expires: "2025-06-30"

  - fingerprint: f6e5d4c3b2a1...
    owner: deps-bot
    reason: "No fix available upstream yet"
    # No expires = never expires (use sparingly)
```

## Referencing the Baseline in Config

```yaml
policy:
  baselinePath: .breach-gate-baseline.yml
```

Or pass it at the command line:

```bash
breach-gate scan --baseline .breach-gate-baseline.yml
```

## Differential Mode — Only Fail on New Findings

With `--differential`, the scan passes as long as all failing findings were already in the baseline. New findings not in the baseline will fail CI.

```bash
breach-gate scan --baseline .breach-gate-baseline.yml --differential
```

In config:

```yaml
policy:
  baselinePath: .breach-gate-baseline.yml
  differentialOnly: true
```

## Expiring Baseline Entries

Set an `expires` date on each entry. After that date, the finding is no longer suppressed — it resurfaces in scan results. This prevents acknowledged findings from being forgotten indefinitely:

```yaml
findings:
  - fingerprint: a1b2c3d4...
    owner: alice
    reason: "Temporary waiver while upstream patch is tested"
    expires: "2025-03-31"   # Will resurface on April 1
```

Expired entries appear in scan output as `expired (owner: alice)` and count toward the verdict.

## How Fingerprinting Works

Fingerprints are content hashes computed from:
- Finding category
- Endpoint (if present)
- CVE ID (if present)
- Package name (if present)

The fingerprint is **not** based on the finding's title or description, which can change between scanner versions. This means updates to scanner output won't invalidate existing baselines.

## Policy Profile Interaction

The `release` policy profile requires a clean baseline — all findings must either be fixed or have a non-expired baseline entry with an assigned owner. This ensures release candidates have no unacknowledged security debt:

```yaml
policy:
  profile: release
  baselinePath: .breach-gate-baseline.yml
```

## Team Workflow

1. Security team runs `breach-gate scan` on `main` after each sprint.
2. New findings are reviewed and either fixed or added to the baseline with an owner and expiry.
3. The baseline file is committed to the repository.
4. PRs run with `--differential` — they only fail on regressions not in the baseline.
5. Release builds run with `profile: release` — all findings must be acknowledged.
