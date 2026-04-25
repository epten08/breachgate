# Auth, AI Replay, And Safety

Use these options when Breach Gate runs in CI against protected APIs or shared staging environments.

## Pre-Scan Auth Hooks

Auth hooks run before scanning and can mint short-lived credentials from your CI secret store or identity provider. The hook can return raw text or JSON.

```yaml
auth:
  type: jwt
  preScan:
    command: node
    args: ["scripts/get-ci-token.js"]
    output: json
    tokenField: accessToken
    headersField: headers
```

Example JSON hook output:

```json
{
  "accessToken": "eyJ...",
  "headers": {
    "X-Tenant": "ci"
  }
}
```

For API keys, use `apiKeyField`. For session auth, use `cookieField` plus `cookieName`.

## Multi-Role Scans

When `auth.roles` is configured, Breach Gate runs static and container scanners once, then runs dynamic and AI scanners once per role. Findings and scanner statuses include the role name.

```yaml
auth:
  type: none
  roles:
    - name: anonymous
      type: none
    - name: user
      type: jwt
      preScan:
        command: node
        args: ["scripts/login-user.js"]
        output: json
        tokenField: token
    - name: admin
      type: session
      cookieName: sid
      preScan:
        command: node
        args: ["scripts/login-admin.js"]
        output: json
        cookieField: sessionCookie
      headers:
        X-Tenant: ci
```

Supported auth types are `none`, `jwt`, `apikey`, and `session`. Custom headers are sent by the AI executor and ZAP request seeding flow.

## AI Replay Artifacts

CI mode defaults AI generation to deterministic settings when AI scanning is enabled. If no replay path is configured, Breach Gate writes generated tests into the report directory:

- single-role scan: `security-reports/ai-tests.json`
- multi-role scan: `security-reports/ai-tests-{role}.json`

You can configure the paths explicitly:

```yaml
scanners:
  ai:
    enabled: true
    provider: ollama
    model: llama3:8b
    deterministic: true
    temperature: 0
    maxTokens: 2048
    saveTests: ./security-reports/ai-tests-{role}.json
```

Replay a previous artifact to reproduce a CI failure without regenerating tests:

```yaml
scanners:
  ai:
    enabled: true
    provider: ollama
    model: llama3:8b
    replayTests: ./security-reports/ai-tests-user.json
```

Replay mode uses the saved test cases and does not require the AI provider for test generation.

## Safety Profiles

Safety profiles control how active the runtime scanners are.

| Profile | Behavior |
|---------|----------|
| `passive` | Disables AI active tests and skips ZAP active scan. |
| `safe-active` | Seeds ZAP with scoped authenticated requests, collects passive alerts, and runs AI tests with scope and method guardrails. |
| `full-active` | Enables ZAP active scan and allows destructive methods. Use only on disposable staging or preview environments. |

Recommended CI guardrails:

```yaml
safety:
  profile: safe-active
  allowProductionTargets: false
  allowedHosts:
    - staging.example.com
    - "*.preview.example.com"
  excludedPaths:
    - /admin/delete*
    - /billing/live*
  maxRequestsPerSecond: 2
  allowDestructiveMethods: false
```

In CI, hosts containing `prod`, `production`, or `live` are blocked unless `allowProductionTargets: true` is set. If `allowedHosts` is non-empty, the target host must match one of the exact hostnames or wildcard entries such as `*.preview.example.com`.

Use `full-active` only when the target is isolated, resettable, and approved for destructive security testing:

```yaml
safety:
  profile: full-active
  allowDestructiveMethods: true
  allowedHosts:
    - disposable-nightly.example.com
```

