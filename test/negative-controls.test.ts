import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "http";
import type { AddressInfo } from "net";
import { normalizeFindings } from "../src/findings/normalizer.js";
import { AttackAnalyzer } from "../src/findings/attack.analyzer.js";
import { TestExecutor } from "../src/ai/executor.js";
import { TestEvaluator } from "../src/ai/evaluator.js";
import type { RawFinding } from "../src/findings/raw.finding.js";
import type { ExecutionContext } from "../src/orchestrator/context.js";

/**
 * NEGATIVE CONTROLS
 *
 * Every test in this file asserts that Breach Gate stays quiet when nothing is
 * wrong. This is the suite that did not exist before, and its absence is the
 * direct cause of every fabricated-breach defect found in the audit.
 *
 * The old suite only ever scanned a deliberately vulnerable demo API, where
 * UNSAFE is the correct answer. UNSAFE is also the tool's failure mode, so the
 * tests could not distinguish working from broken.
 *
 * Rule for anyone adding a detector: if you cannot write the negative control,
 * you do not understand your detector well enough to ship it.
 */

const analyzer = new AttackAnalyzer();

function verdictFor(raw: RawFinding[]) {
  return analyzer.generateVerdict(normalizeFindings(raw));
}

function ctxFor(baseUrl: string): ExecutionContext {
  return {
    targetUrl: baseUrl,
    environment: { baseUrl, images: [], services: [], managedByUs: false },
    auth: { type: "none", role: "anonymous" },
    config: { failOnSeverity: "HIGH", safety: {} },
  } as unknown as ExecutionContext;
}

// ===========================================================================
// Regression: a clean API must not be reported as breached
// ===========================================================================

describe("Negative control: clean API end to end", () => {
  let server: http.Server;
  let baseUrl: string;

  beforeAll(async () => {
    // A genuinely safe API. Static JSON, no database, no shell, no reflection,
    // no error leakage. Its only deviation from best practice is that it does
    // not set X-Frame-Options, X-Content-Type-Options, or HSTS, which is the
    // normal situation when those are handled at a CDN or ingress.
    server = http.createServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ items: [{ id: 1, name: "widget" }] }));
    });
    await new Promise<void>((resolve) => server.listen(0, resolve));
    baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("does not report a confirmed exploit for a clean response missing headers", async () => {
    const testCase = {
      name: "SQL injection in items query",
      endpoint: "GET /api/items",
      category: "SQL Injection",
      description: "Attempt SQLi via query parameter",
      request: { method: "GET", path: "/api/items?q=1%27+OR+%271%27%3D%271" },
      expectedVulnerable: { bodyContains: ["syntax error"] },
    };

    const ctx = ctxFor(baseUrl);
    const outcome = await new TestExecutor(ctx).execute([testCase]);

    expect(outcome.results).toHaveLength(1);
    const result = outcome.results[0];

    // The three missing headers are recorded as observations, never as proof.
    expect(result.missingHeaders.length).toBeGreaterThan(0);
    expect(result.proofs).toEqual([]);
    expect(result.isVulnerable).toBe(false);
    expect(result.matchedCriteria.join(" ")).not.toMatch(/security header/i);

    const raws = await new TestEvaluator(ctx).evaluate(outcome.results);

    // Only the LOW header summary should be produced. No SQL Injection finding.
    expect(raws.filter((r) => r.category === "SQL Injection")).toHaveLength(0);
    const headerFinding = raws.find((r) => r.category === "Missing Security Header");
    expect(headerFinding).toBeDefined();
    expect(headerFinding?.severityHint).toBe("LOW");
    expect(headerFinding?.proofs).toEqual([]);

    const verdict = analyzer.generateVerdict(normalizeFindings(raws));
    expect(verdict.verdict).toBe("SAFE");
    expect(verdict.confirmedExploits).toHaveLength(0);
    expect(verdict.breaches).toHaveLength(0);
  });

  it("does not confirm exploitation when the target rejects the payload with 401", async () => {
    const authServer = http.createServer((_req, res) => {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "unauthorized" }));
    });
    await new Promise<void>((resolve) => authServer.listen(0, resolve));
    const url = `http://127.0.0.1:${(authServer.address() as AddressInfo).port}`;

    try {
      const outcome = await new TestExecutor(ctxFor(url)).execute([
        {
          name: "Auth bypass attempt",
          endpoint: "GET /api/admin",
          category: "Broken Access Control",
          description: "Access admin without credentials",
          request: { method: "GET", path: "/api/admin" },
          expectedVulnerable: { statusCodes: [200] },
        },
      ]);

      expect(outcome.results[0].proofs).toEqual([]);
      expect(outcome.results[0].isVulnerable).toBe(false);
    } finally {
      await new Promise<void>((resolve) => authServer.close(() => resolve()));
    }
  });

  it("reports an unreachable target as an error rather than as clean results", async () => {
    // Port 1 is reserved and will refuse the connection.
    const outcome = await new TestExecutor(ctxFor("http://127.0.0.1:1")).execute([
      {
        name: "Any test",
        endpoint: "GET /api/items",
        category: "SQL Injection",
        description: "x",
        request: { method: "GET", path: "/api/items" },
        expectedVulnerable: {},
      },
    ]);

    expect(outcome.attemptedTests).toBe(1);
    expect(outcome.results).toHaveLength(0);
    expect(outcome.erroredTests).toBe(1);
  });
});

// ===========================================================================
// Regression: source labels are not proof
// ===========================================================================

describe("Negative control: scanner identity is never proof", () => {
  it("does not treat a ZAP finding as a confirmed exploit", () => {
    const verdict = verdictFor([
      {
        source: "OWASP ZAP API",
        category: "Missing Security Header",
        description: "X-Content-Type-Options Header Missing",
        endpoint: "GET http://localhost:3000/",
        severityHint: "LOW",
        evidence: "",
        proofs: [],
      },
    ]);

    expect(verdict.verdict).toBe("SAFE");
    expect(verdict.confirmedExploits).toHaveLength(0);
    expect(verdict.reason).not.toMatch(/active attacks succeeded/i);
  });

  it("drops ZAP informational alerts before they reach the verdict", () => {
    const findings = normalizeFindings([
      {
        source: "OWASP ZAP API",
        category: "Information Disclosure",
        description: "Timestamp Disclosure - Unix",
        endpoint: "GET http://localhost:3000/api/health",
        severityHint: "INFO",
        evidence: "1700000000",
        proofs: [],
      },
    ]);

    expect(findings).toHaveLength(0);
    expect(analyzer.generateVerdict(findings).verdict).toBe("SAFE");
  });

  it("does not confirm an AI finding that carries no proof", () => {
    const verdict = verdictFor([
      {
        source: "AI Security Tester",
        category: "SQL Injection",
        description: "SQLi probe",
        endpoint: "GET /api/items",
        severityHint: "CRITICAL",
        evidence: "Response Status: 200\nMatched: something",
        proofs: [],
      },
    ]);

    expect(verdict.confirmedExploits).toHaveLength(0);
    expect(verdict.breaches).toHaveLength(0);
    // Plausible but unproven: surface it, do not block on it.
    expect(verdict.verdict).not.toBe("UNSAFE");
  });

  it("never returns UNSAFE without at least one proof", () => {
    const categories = [
      "SQL Injection",
      "Command Injection",
      "Remote Code Execution",
      "Broken Access Control",
      "Server-Side Request Forgery (SSRF)",
      "Path Traversal",
    ];

    for (const category of categories) {
      const verdict = verdictFor([
        {
          source: "OWASP ZAP API",
          category,
          description: `${category} suspected`,
          endpoint: "POST /api/data",
          severityHint: "CRITICAL",
          evidence: "pattern matched",
          proofs: [],
        },
      ]);

      expect(verdict.verdict, `${category} without proof must not block deploy`).not.toBe("UNSAFE");
    }
  });
});

// ===========================================================================
// Positive controls: real proof must still fail the build
// ===========================================================================

describe("Positive control: proven exploitation blocks deployment", () => {
  it("returns UNSAFE when a SQL error proof is attached", () => {
    const verdict = verdictFor([
      {
        source: "AI Security Tester",
        category: "SQL Injection",
        description: "SQLi in items query",
        endpoint: "GET /api/items",
        severityHint: "CRITICAL",
        evidence: "Proof: sql-error",
        proofs: ["sql-error"],
        proofExcerpt: 'You have an error in your SQL syntax near "OR 1=1"',
      },
    ]);

    expect(verdict.verdict).toBe("UNSAFE");
    expect(verdict.confirmedExploits).toHaveLength(1);
    expect(verdict.breaches[0].type).toBe("data_exfiltration");
    expect(verdict.breaches[0].proofExcerpt).toContain("SQL syntax");
  });

  it("returns UNSAFE for proven command execution and names it correctly", () => {
    const verdict = verdictFor([
      {
        source: "AI Security Tester",
        category: "Command Injection",
        description: "Command injection in exec endpoint",
        endpoint: "POST /api/execute",
        severityHint: "CRITICAL",
        evidence: "Proof: command-output",
        proofs: ["command-output"],
        proofExcerpt: "uid=0(root) gid=0(root) groups=0(root)",
      },
    ]);

    expect(verdict.verdict).toBe("UNSAFE");
    expect(verdict.breaches[0].type).toBe("remote_code_execution");
    expect(verdict.operationalConclusion).toMatch(/remote command execution/i);
  });

  it("still fails the scan when scanners did not complete", () => {
    const verdict = analyzer.generateVerdictWithStatus([], {
      isComplete: false,
      failedScanners: ["OWASP ZAP API"],
    });

    expect(verdict.verdict).toBe("INCONCLUSIVE");
    expect(verdict.scanIncomplete).toBe(true);
  });
});

// ===========================================================================
// Scoring model invariants
// ===========================================================================

describe("Scoring model has no floors or bonuses", () => {
  it("scores a missing header far below a proven injection", () => {
    const [header] = normalizeFindings([
      {
        source: "OWASP ZAP API",
        category: "Missing Security Header",
        description: "X-Frame-Options missing",
        endpoint: "GET /",
        severityHint: "LOW",
        proofs: [],
      },
    ]);

    const [injection] = normalizeFindings([
      {
        source: "AI Security Tester",
        category: "SQL Injection",
        description: "SQLi",
        endpoint: "POST /api/data",
        severityHint: "CRITICAL",
        proofs: ["sql-error"],
        proofExcerpt: "SQL syntax error",
      },
    ]);

    const headerScore = analyzer.analyzeAttackVector(header).feasibilityScore;
    const injectionScore = analyzer.analyzeAttackVector(injection).feasibilityScore;

    expect(headerScore).toBeLessThan(0.1);
    expect(injectionScore).toBeGreaterThan(0.5);
  });

  it("labels a CRITICAL severity finding with no proof as unconfirmed", () => {
    const [finding] = normalizeFindings([
      {
        source: "Trivy Static",
        category: "Dependency Vulnerability",
        description: "CVE-2024-0001 in left-pad",
        severityHint: "CRITICAL",
        cve: "CVE-2024-0001",
        proofs: [],
      },
    ]);

    const vector = analyzer.analyzeAttackVector(finding);
    expect(vector.isConfirmed).toBe(false);
    // No EPSS or KEV data in a unit test, so the basis must be the category
    // baseline and must be honest about that.
    expect(vector.exploitabilityBasis).toBe("category");
  });

  it("raises exploitability when a CVE is listed in CISA KEV", () => {
    const [plain] = normalizeFindings([
      {
        source: "Trivy Static",
        category: "Dependency Vulnerability",
        description: "CVE-2024-0002",
        severityHint: "MEDIUM",
        cve: "CVE-2024-0002",
        proofs: [],
      },
    ]);

    const exploited = { ...plain, knownExploited: true };

    const plainVector = analyzer.analyzeAttackVector(plain);
    const kevVector = analyzer.analyzeAttackVector(exploited);

    expect(kevVector.exploitability).toBeGreaterThan(plainVector.exploitability);
    expect(kevVector.exploitabilityBasis).toBe("kev");
  });

  it("does not build attack chains out of unproven findings", () => {
    const verdict = verdictFor([
      {
        source: "OWASP ZAP API",
        category: "Broken Access Control",
        description: "Possible IDOR",
        endpoint: "GET /api/users/1",
        severityHint: "HIGH",
        proofs: [],
      },
      {
        source: "OWASP ZAP API",
        category: "Sensitive Data Exposure",
        description: "Possible data exposure",
        endpoint: "GET /api/users/1",
        severityHint: "HIGH",
        proofs: [],
      },
    ]);

    expect(verdict.attackChains).toHaveLength(0);
  });
});
