# Safety Profiles — Choosing the Right Scan Mode

Safety profiles control how aggressively Breach Gate interacts with your target. The default (`safe-active`) is appropriate for most CI and local development scenarios.

## Quick Decision Guide

| Scenario | Profile |
|----------|---------|
| Analyzing static code / container images only — no HTTP requests | `passive` |
| Typical CI scan of a staging API | `safe-active` (default) |
| Full penetration-test-style assessment on an isolated environment | `full-active` |
| Scanning a production URL (requires explicit opt-in) | `safe-active` + `allowProductionTargets: true` |

## Profile Reference

### `passive`

No active HTTP requests are made to the target. Only static analysis (Trivy filesystem) and container image scanning run.

Use when:
- You're scanning a repository or image in CI without a running server
- You want to check dependencies and secrets without any network activity

```yaml
safety:
  profile: passive
```

Note: Dynamic (ZAP) and AI scanners are automatically disabled in passive mode.

### `safe-active` (default)

Runs all scanners but constrains active testing:
- ZAP runs in **passive spider mode** — it follows links and observes responses but does not fuzz or attack
- AI scanner generates tests but skips destructive methods (DELETE, PUT with arbitrary payloads)
- Respects `excludedPaths` and `maxRequestsPerSecond` rate limits
- Blocks scans targeting production-like hostnames (e.g., `.prod.`, `.production.`) unless explicitly allowed

Use when:
- Running in CI against a staging or development environment
- You want real dynamic coverage without the risk of corrupting test data

```yaml
safety:
  profile: safe-active
  maxRequestsPerSecond: 2
  excludedPaths:
    - /admin/reset
    - /api/purge
```

### `full-active`

Enables destructive scan methods:
- ZAP active scan — fuzzes every parameter with attack payloads
- AI scanner can issue DELETE, PUT, and PATCH requests with attack payloads
- `allowDestructiveMethods` is implicitly enabled

Use **only** when:
- Scanning a fully isolated environment (containers with fresh state, ephemeral database)
- Running a dedicated penetration test assessment — not routine CI
- Your team has explicitly signed off on the scan scope

```yaml
safety:
  profile: full-active
  allowedHosts:
    - localhost
    - "*.test.internal"
```

## Additional Safety Controls

These apply regardless of profile:

### `allowedHosts`

Restrict the scanner to only contact specific hosts. Any request to a host not on the list fails immediately:

```yaml
safety:
  allowedHosts:
    - localhost
    - "127.0.0.1"
    - "*.staging.example.com"
```

Supports `*` as a prefix wildcard. If the list is empty, all hosts are allowed (subject to production guard).

### `excludedPaths`

Paths matching these patterns are never scanned, even if discovered via OpenAPI spec or spider:

```yaml
safety:
  excludedPaths:
    - /admin/shutdown
    - /api/test/seed
    - /debug
```

### `allowProductionTargets`

By default, Breach Gate blocks scans against hostnames that look like production (containing `.prod.`, `.production.`, or similar patterns). Set this to `true` only if you have a dedicated security assessment agreement in place:

```yaml
safety:
  allowProductionTargets: true  # Only with explicit security team sign-off
```

### `maxRequestsPerSecond`

Limits the outbound request rate to avoid overwhelming the target or triggering WAF rate limits:

```yaml
safety:
  maxRequestsPerSecond: 1   # Very conservative
  # maxRequestsPerSecond: 5 # Faster for isolated environments
```

Set to `0` to disable rate limiting (not recommended outside fully isolated environments).

## Profile Interaction with Scanners

| Scanner | passive | safe-active | full-active |
|---------|---------|-------------|-------------|
| Trivy Static | ✅ | ✅ | ✅ |
| Trivy Image | ✅ | ✅ | ✅ |
| ZAP (passive spider) | ❌ | ✅ | ✅ |
| ZAP (active attack) | ❌ | ❌ | ✅ |
| AI (read-only tests) | ❌ | ✅ | ✅ |
| AI (destructive tests) | ❌ | ❌ | ✅ |
