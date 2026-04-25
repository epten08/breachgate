# Writing a Custom Scanner Plugin

Breach Gate's scanner architecture is built around the `Scanner` interface. Any module that implements it can be plugged into the orchestrator. This guide shows how to write, test, and load a custom scanner.

## The Scanner Interface

```typescript
import type { ExecutionContext } from "breach-gate";
import type { RawFinding } from "breach-gate";

export interface Scanner {
  /** Display name shown in scan output and reports */
  name: string;

  /** Scanner category — controls which policy rules apply */
  category: "static" | "container" | "dynamic" | "ai";

  /** Entry point: run the scan and return raw findings */
  run(ctx: ExecutionContext): Promise<RawFinding[]>;
}
```

Both `Scanner` and `RawFinding` are exported from the `breach-gate` npm package.

## Minimal Example

```typescript
// my-scanner/index.ts
import type { Scanner } from "breach-gate";
import type { ExecutionContext, RawFinding } from "breach-gate";
import { ScannerUnavailableError } from "breach-gate";

export class MyCustomScanner implements Scanner {
  name = "My Custom Scanner";
  category = "dynamic" as const;

  async run(ctx: ExecutionContext): Promise<RawFinding[]> {
    // ctx.targetUrl  — the API base URL
    // ctx.auth       — resolved auth credentials
    // ctx.openApi    — parsed OpenAPI spec (if provided)
    // ctx.endpoints  — manual endpoint list (if no spec)

    const findings: RawFinding[] = [];

    for (const endpoint of ctx.endpoints ?? []) {
      const url = `${ctx.targetUrl}${endpoint.path}`;
      const resp = await fetch(url);

      // Check for a specific header
      if (!resp.headers.get("X-Frame-Options")) {
        findings.push({
          source: this.name,
          category: "Security Misconfiguration",
          description: `Missing X-Frame-Options header on ${endpoint.path}`,
          endpoint: `${endpoint.method ?? "GET"} ${endpoint.path}`,
          severityHint: "MEDIUM",
          evidence: `Response from ${url} had no X-Frame-Options header`,
        });
      }
    }

    return findings;
  }
}
```

## `RawFinding` Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source` | `string` | ✅ | Your scanner's name (used for deduplication) |
| `category` | `string` | ✅ | Finding type (maps to impact scoring) |
| `description` | `string` | ✅ | Human-readable finding description |
| `endpoint` | `string` | — | `"METHOD /path"` format, e.g. `"GET /api/users"` |
| `severityHint` | `string` | — | `"LOW"` / `"MEDIUM"` / `"HIGH"` / `"CRITICAL"` |
| `evidence` | `string` | — | Raw request/response snippet or other proof |
| `cve` | `string` | — | CVE ID if applicable (`"CVE-2023-1234"`) |
| `cwe` | `string` | — | CWE ID (`"CWE-79"`) |
| `package` | `string` | — | Affected package name |
| `version` | `string` | — | Installed version |
| `fixedVersion` | `string` | — | First safe version |
| `reference` | `string` | — | URL to vulnerability details |

## Throwing vs. Returning

- **Return empty array** if your scanner ran successfully but found nothing.
- **Throw `ScannerUnavailableError`** if a prerequisite is missing (tool not installed, API key not set). The orchestrator will mark this scanner as `skipped` and continue.
- **Throw `ScannerError`** for unexpected runtime failures. The orchestrator marks the scanner as `failed` — in CI mode this makes the overall scan `INCONCLUSIVE`.

```typescript
import { ScannerUnavailableError, ScannerError } from "breach-gate";

// Prerequisite not met — optional skip
if (!process.env.MY_API_KEY) {
  throw new ScannerUnavailableError(
    "MY_API_KEY not set",
    this.name,
    undefined,
    "Set the MY_API_KEY environment variable"
  );
}

// Unexpected failure — log and fail
try {
  // ... scan
} catch (err) {
  throw new ScannerError(`Scan failed: ${(err as Error).message}`, this.name, err as Error);
}
```

## Loading Your Plugin

Build your scanner to CommonJS or ESM and reference the compiled file in `security.config.yml`:

```yaml
scanners:
  plugins:
    - ./dist/my-scanner/index.js
```

Your plugin file must export a class named `default` that implements `Scanner`:

```typescript
// my-scanner/index.ts
export default class MyCustomScanner implements Scanner {
  // ...
}
```

The orchestrator dynamically imports the plugin and instantiates it with no arguments. If your scanner requires configuration, read it from environment variables or a separate config file.

## Testing Your Scanner

Use the `createTestExecutionContext` pattern from the test suite:

```typescript
import { describe, it, expect } from "vitest";
import { MyCustomScanner } from "./index.js";

const ctx = {
  targetUrl: "http://localhost:3000",
  environment: { baseUrl: "http://localhost:3000", images: [], services: [], managedByUs: false },
  auth: { type: "none" as const, role: "anonymous" },
  config: { failOnSeverity: "HIGH" as const, safety: { profile: "safe-active" as const } },
  endpoints: [{ path: "/health", method: "GET" }],
};

describe("MyCustomScanner", () => {
  it("finds missing X-Frame-Options", async () => {
    // Mock fetch to return a response without the header
    globalThis.fetch = async () => new Response("ok", { status: 200 });
    const scanner = new MyCustomScanner();
    const findings = await scanner.run(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].category).toBe("Security Misconfiguration");
  });
});
```

## Category Impact Scores

The `category` field drives the impact multiplier in attack feasibility scoring:

| Category | Impact |
|----------|--------|
| `Remote Code Execution` / `Command Injection` | 1.0 |
| `SQL Injection` | 0.95 |
| `Path Traversal` / `Broken Access Control` / `Broken Authentication` | 0.85 |
| `Sensitive Data Exposure` | 0.8 |
| `Cross-Site Scripting (XSS)` | 0.75 |
| `Hardcoded Secret` | 0.7 |
| `CSRF` | 0.6 |
| `Information Disclosure` | 0.5 |
| `Security Misconfiguration` | 0.45 |
| `Missing Security Header` | 0.25 |

Use standard category names to get accurate feasibility scoring. Custom category names default to 0.5 (moderate impact).
