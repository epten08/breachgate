/**
 * Integration tests for Breach Gate.
 * Validates the end-to-end pipeline without requiring external tools
 * (Trivy, ZAP, Ollama) to be installed.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { existsSync, rmSync, mkdirSync, writeFileSync } from "fs";
import { join } from "path";

import { loadConfig, validateConfig } from "../src/core/config.loader.js";
import { logger } from "../src/core/logger.js";
import { normalizeFindings, sortByRisk } from "../src/findings/normalizer.js";
import { RawFinding } from "../src/findings/raw.finding.js";
import { ReportGenerator } from "../src/reports/report.generator.js";
import { JsonReporter } from "../src/reports/json.reporter.js";
import { MarkdownReporter } from "../src/reports/markdown.reporter.js";
import { SarifReporter } from "../src/reports/sarif.reporter.js";
import { HtmlReporter } from "../src/reports/html.reporter.js";
import { CliSummary } from "../src/reports/cli.summary.js";
import { AttackAnalyzer } from "../src/findings/attack.analyzer.js";
import { Orchestrator, ScanResult } from "../src/orchestrator/orchestrator.js";
import { resolveAuthContexts, buildAuthHeaders } from "../src/auth/auth.js";
import { TestExecutor } from "../src/ai/executor.js";
import { SecurityTestCase } from "../src/ai/test.generator.js";
import { AIScanner } from "../src/scanners/ai/ai.scanner.js";
import { ExecutionContext } from "../src/orchestrator/context.js";
import { Scanner } from "../src/scanners/scanner.js";
import { ScannerError, ScannerUnavailableError } from "../src/core/errors.js";
import {
  allowsDestructiveMethod,
  enforceTargetSafety,
  shouldRunZapActiveScan,
} from "../src/safety/safety.js";
import {
  applyBaseline,
  evaluatePolicy,
  fingerprintFinding,
  resolvePolicyRules,
} from "../src/policy/policy.js";

beforeAll(() => {
  logger.setLevel("error"); // Suppress internal logs during tests
});

// ---------------------------------------------------------------------------
// Test Fixtures
// ---------------------------------------------------------------------------

function createMockRawFindings(): RawFinding[] {
  return [
    {
      description:
        "SQL Injection in login endpoint - The login endpoint is vulnerable to SQL injection",
      severityHint: "CRITICAL",
      category: "Injection",
      source: "zap",
      endpoint: "/api/login",
      evidence: "Parameter 'username' appears to be vulnerable to SQL injection",
      cve: "CVE-2023-1234",
      cwe: "CWE-89",
    },
    {
      description: "Cross-Site Scripting (XSS) - Reflected XSS in search endpoint",
      severityHint: "HIGH",
      category: "XSS",
      source: "zap",
      endpoint: "/api/search",
      evidence: "<script>alert(1)</script> reflected in response",
    },
    {
      description: "Vulnerable dependency: lodash < 4.17.21 has prototype pollution",
      severityHint: "HIGH",
      category: "Dependency Vulnerability",
      source: "trivy",
      package: "lodash",
      version: "4.17.20",
      fixedVersion: "4.17.21",
      cve: "CVE-2021-23337",
    },
    {
      description: "Missing security headers - Response missing X-Content-Type-Options header",
      severityHint: "LOW",
      category: "Misconfiguration",
      source: "zap",
      endpoint: "/api/users",
    },
    {
      description: "SQL Injection in login endpoint - SQL injection detected via AI testing",
      severityHint: "CRITICAL",
      category: "Injection",
      source: "ai",
      endpoint: "/api/login",
      evidence: "UNION SELECT attack successful",
      cve: "CVE-2023-1234",
    },
  ];
}

function createHeaderTestCase(): SecurityTestCase {
  return {
    name: "Missing Header - GET /health",
    endpoint: "GET /health",
    category: "Security Misconfiguration",
    description: "Detect a missing response header",
    request: { method: "GET", path: "/health" },
    expectedVulnerable: { headerMissing: ["X-Test-Security"] },
  };
}

function createMockScanner(
  name: string,
  category: Scanner["category"],
  run: Scanner["run"]
): Scanner {
  return { name, category, run };
}

function createTestExecutionContext(auth?: ExecutionContext["auth"]): ExecutionContext {
  return {
    targetUrl: "http://localhost:3000",
    environment: {
      baseUrl: "http://localhost:3000",
      images: [],
      services: [],
      managedByUs: false,
    },
    auth: auth ?? { type: "none", role: "anonymous" },
    config: {
      failOnSeverity: "HIGH",
      safety: {
        profile: "safe-active",
        allowProductionTargets: false,
        allowedHosts: [],
        excludedPaths: [],
        maxRequestsPerSecond: 0,
        allowDestructiveMethods: false,
      },
    },
  };
}

const reportConfig = {
  formats: ["json", "markdown"] as ("json" | "markdown")[],
  outputDir: "./test-reports",
  includeEvidence: true,
};

// ---------------------------------------------------------------------------
// Config Loader
// ---------------------------------------------------------------------------

const FIXTURE_CONFIG_DIR = "./test-output-config-loader";
const FIXTURE_CONFIG_PATH = join(FIXTURE_CONFIG_DIR, "security.config.yml");
const FIXTURE_CONFIG_YAML = `version: "1.0"
target:
  baseUrl: http://localhost:3000
scanners:
  static:
    enabled: false
  container:
    enabled: false
  dynamic:
    enabled: false
  ai:
    enabled: false
`;

describe("Config Loader", () => {
  it("loads default config when no file specified", () => {
    // DEFAULT_CONFIG has target:{} with no baseUrl — check shape only, not validity
    const config = loadConfig();
    expect(config).toBeTruthy();
    expect(config.target).toBeDefined();
  });

  it("validates config structure", () => {
    mkdirSync(FIXTURE_CONFIG_DIR, { recursive: true });
    writeFileSync(FIXTURE_CONFIG_PATH, FIXTURE_CONFIG_YAML);
    const config = loadConfig(FIXTURE_CONFIG_PATH);
    expect(() => validateConfig(config)).not.toThrow();
    expect(config.scanners).toBeDefined();
  });

  it("throws on missing explicit config file", () => {
    expect(() => loadConfig("nonexistent.yml")).toThrow("Config file not found");
  });

  it("expands environment variables in config values", () => {
    const testDir = "./test-output-config";
    const configPath = join(testDir, "env-security.config.yml");
    mkdirSync(testDir, { recursive: true });
    process.env.SEC_BOT_TEST_JWT = "test-token";

    writeFileSync(
      configPath,
      `
version: "1.0"
target:
  baseUrl: http://localhost:3000
auth:
  type: jwt
  token: \${SEC_BOT_TEST_JWT}
scanners:
  static:
    enabled: false
  container:
    enabled: false
  dynamic:
    enabled: false
  ai:
    enabled: false
thresholds:
  failOn: HIGH
  warnOn: MEDIUM
reporting:
  outputDir: ./security-reports
  formats:
    - json
  includeEvidence: true
`.trimStart(),
      "utf-8"
    );

    const config = loadConfig(configPath);
    expect(config.auth?.token).toBe("test-token");

    rmSync(testDir, { recursive: true });
    delete process.env.SEC_BOT_TEST_JWT;
  });

  it("throws on missing environment variables in config values", () => {
    const testDir = "./test-output-config-missing";
    const configPath = join(testDir, "missing-env.config.yml");
    mkdirSync(testDir, { recursive: true });

    writeFileSync(
      configPath,
      `
version: "1.0"
target:
  baseUrl: http://localhost:3000
auth:
  type: jwt
  token: \${SEC_BOT_MISSING_JWT}
`.trimStart(),
      "utf-8"
    );

    expect(() => loadConfig(configPath)).toThrow("SEC_BOT_MISSING_JWT");

    rmSync(testDir, { recursive: true });
  });
});

// ---------------------------------------------------------------------------
// Findings Normalizer
// ---------------------------------------------------------------------------

describe("Findings Normalizer", () => {
  const rawFindings = createMockRawFindings();

  it("normalizes raw findings to Finding objects", () => {
    const normalized = normalizeFindings(rawFindings);
    expect(Array.isArray(normalized)).toBe(true);
    expect(normalized.length).toBeGreaterThan(0);
    expect(normalized[0].riskScore).toBeDefined();
  });

  it("calculates risk scores in range 0-1", () => {
    const normalized = normalizeFindings(rawFindings);
    for (const finding of normalized) {
      expect(finding.riskScore).toBeGreaterThanOrEqual(0);
      expect(finding.riskScore).toBeLessThanOrEqual(1);
      expect(finding.exploitability).toBeGreaterThanOrEqual(0);
      expect(finding.confidence).toBeGreaterThanOrEqual(0);
    }
  });

  it("deduplicates similar findings", () => {
    const normalized = normalizeFindings(rawFindings);
    const sqlFindings = normalized.filter((f) => f.title.includes("SQL Injection"));
    expect(sqlFindings.length).toBe(1);
    expect(sqlFindings[0].duplicateCount).toBeGreaterThanOrEqual(1);
  });

  it("sorts by risk in descending order", () => {
    const normalized = normalizeFindings(rawFindings);
    const sorted = sortByRisk(normalized);
    for (let i = 1; i < sorted.length; i++) {
      expect(sorted[i - 1].riskScore).toBeGreaterThanOrEqual(sorted[i].riskScore);
    }
  });
});

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

describe("Reporting", () => {
  const rawFindings = createMockRawFindings();
  const findings = normalizeFindings(rawFindings);

  it("generates valid JSON report", () => {
    const reporter = new JsonReporter(reportConfig);
    const json = reporter.generate(findings, { targetUrl: "http://localhost:3000" });
    const parsed = JSON.parse(json);
    expect(parsed.metadata).toBeDefined();
    expect(parsed.summary).toBeDefined();
    expect(parsed.findings).toBeDefined();
    expect(parsed.summary.total).toBe(findings.length);
  });

  it("JSON report includes verdict, scanner status, and policy", () => {
    const analyzer = new AttackAnalyzer();
    const verdict = analyzer.generateVerdictWithStatus(findings, {
      isComplete: false,
      failedScanners: ["Trivy Static"],
    });
    const scanResult: ScanResult = {
      findings,
      failedScanners: ["Trivy Static"],
      completedScanners: ["OWASP ZAP API"],
      skippedScanners: [],
      unavailableScanners: ["Trivy Static"],
      scannerStatuses: [
        {
          name: "Trivy Static",
          category: "static",
          status: "unavailable",
          required: true,
          durationMs: 10,
          message: "Trivy unavailable",
        },
        {
          name: "OWASP ZAP API",
          category: "dynamic",
          status: "completed",
          required: true,
          durationMs: 20,
        },
      ],
      isComplete: false,
      allScannersFailed: false,
    };

    const reporter = new JsonReporter(reportConfig);
    const json = reporter.generate(findings, {
      targetUrl: "http://localhost:3000",
      verdict,
      scanResult,
      policy: { failOn: "HIGH", warnOn: "MEDIUM" },
    });
    const parsed = JSON.parse(json);

    expect(parsed.verdict.status).toBe("INCONCLUSIVE");
    expect(parsed.scannerStatus.unavailable[0]).toBe("Trivy Static");
    expect(parsed.policy.failOn).toBe("HIGH");
  });

  it("generates Markdown report with expected sections", () => {
    const reporter = new MarkdownReporter(reportConfig);
    const md = reporter.generate(findings, { targetUrl: "http://localhost:3000" });
    expect(md).toContain("# Security Scan Report");
    expect(md).toContain("## Executive Summary");
    expect(md).toContain("## Findings Summary");
  });

  it("generates valid SARIF 2.1.0 report", () => {
    const reporter = new SarifReporter();
    const sarif = reporter.generate(findings, { targetUrl: "http://localhost:3000" });
    const parsed = JSON.parse(sarif);
    expect(parsed.version).toBe("2.1.0");
    expect(parsed.runs[0].results.length).toBe(findings.length);
  });

  it("generates self-contained HTML report", () => {
    const reporter = new HtmlReporter(reportConfig);
    const html = reporter.generate(findings, { targetUrl: "http://localhost:3000" });
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("Breach Gate Security Report");
    expect(html).toContain('class="logo"');
    expect(html.includes("<script src") || html.includes('<link rel="stylesheet"')).toBe(false);
  });

  it("CLI summary renders without error", () => {
    const summary = new CliSummary({ maxFindings: 5, verbose: false });
    expect(() => summary.render(findings)).not.toThrow();
  });

  it("ReportGenerator creates files on disk", async () => {
    const testDir = "./test-output-reports";
    if (existsSync(testDir)) rmSync(testDir, { recursive: true });
    mkdirSync(testDir, { recursive: true });

    const generator = new ReportGenerator({ ...reportConfig, outputDir: testDir });
    const reports = await generator.generate(findings, {
      targetUrl: "http://localhost:3000",
      scanDuration: 5000,
    });

    expect(reports.length).toBe(2);
    for (const report of reports) {
      expect(existsSync(report.path)).toBe(true);
    }

    rmSync(testDir, { recursive: true });
  });
});

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

describe("Policy", () => {
  const findings = normalizeFindings(createMockRawFindings());

  it("fingerprints findings deterministically", () => {
    expect(fingerprintFinding(findings[0])).toBe(fingerprintFinding(findings[0]));
  });

  it("suppresses baseline findings", () => {
    const fingerprint = fingerprintFinding(findings[0]);
    const result = applyBaseline(findings, {
      version: "1.0",
      findings: [
        { fingerprint, owner: "security", reason: "Accepted test finding", expires: "2999-12-31" },
      ],
    });
    expect(result.suppressed.length).toBe(1);
    expect(result.effectiveFindings.length).toBe(findings.length - 1);
  });

  it("evaluates pull-request policy — fails on high/critical findings", () => {
    const { profile, rules } = resolvePolicyRules(undefined, "pull-request");
    const analyzer = new AttackAnalyzer();
    const verdict = analyzer.generateVerdictWithStatus(findings, {
      isComplete: true,
      failedScanners: [],
    });
    const evaluation = evaluatePolicy({
      allFindings: findings,
      effectiveFindings: findings,
      suppressed: [],
      expired: [],
      verdict,
      scanResult: {
        findings,
        failedScanners: [],
        completedScanners: ["mock"],
        skippedScanners: [],
        unavailableScanners: [],
        scannerStatuses: [],
        isComplete: true,
        allScannersFailed: false,
      },
      profile,
      rules,
    });
    expect(evaluation.status).toBe("failed");
  });
});

// ---------------------------------------------------------------------------
// Auth, Replay, and Safety
// ---------------------------------------------------------------------------

describe("Auth, Replay, and Safety", () => {
  it("resolves multi-role auth contexts and builds session headers", async () => {
    const contexts = await resolveAuthContexts({
      type: "none",
      roles: [
        { name: "anonymous", type: "none" },
        {
          name: "admin",
          type: "session",
          cookieName: "sid",
          cookieValue: "abc123",
          headers: { "X-Role": "admin" },
        },
      ],
    });
    expect(contexts.length).toBe(2);
    const headers = buildAuthHeaders(contexts[1]);
    expect(headers.Cookie).toBe("sid=abc123");
    expect(headers["X-Role"]).toBe("admin");
  });

  it("runs pre-scan auth hooks and reads token from JSON output", async () => {
    const contexts = await resolveAuthContexts({
      type: "jwt",
      preScan: {
        command: process.execPath,
        args: [
          "-e",
          "console.log(JSON.stringify({ token: 'hook-token', headers: { 'X-Trace': 'ci' } }))",
        ],
        output: "json",
      },
    });
    expect(contexts[0].token).toBe("hook-token");
    expect(contexts[0].headers?.["X-Trace"]).toBe("ci");
  });

  it("enforces host allowlists and rejects out-of-allowlist hosts", () => {
    expect(() =>
      enforceTargetSafety(
        { profile: "safe-active", allowedHosts: ["*.example.com"] },
        "https://api.example.com",
        true
      )
    ).not.toThrow();

    expect(() =>
      enforceTargetSafety(
        { profile: "safe-active", allowedHosts: ["api.example.com"] },
        "https://evil.example.com",
        true
      )
    ).toThrow();

    expect(allowsDestructiveMethod("DELETE", { profile: "safe-active" })).toBe(false);
    expect(allowsDestructiveMethod("DELETE", { profile: "full-active" })).toBe(true);
    expect(shouldRunZapActiveScan({ profile: "safe-active" })).toBe(false);
    expect(shouldRunZapActiveScan({ profile: "full-active" })).toBe(true);
  });

  it("AI executor sends cookie and custom auth headers", async () => {
    const originalFetch = globalThis.fetch;
    let capturedHeaders: Record<string, string> = {};

    globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      capturedHeaders = init?.headers as Record<string, string>;
      return new Response("ok", { status: 200 });
    }) as typeof fetch;

    try {
      const executor = new TestExecutor(
        createTestExecutionContext({
          type: "session",
          role: "admin",
          cookieName: "sid",
          cookieValue: "cookie-value",
          headers: { "X-Test-Role": "admin" },
        })
      );
      const results = await executor.execute([createHeaderTestCase()]);
      expect(results.length).toBe(1);
      expect(capturedHeaders.Cookie).toBe("sid=cookie-value");
      expect(capturedHeaders["X-Test-Role"]).toBe("admin");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("AI scanner replays saved tests without a live model", async () => {
    const testDir = "./test-output-replay";
    const replayPath = join(testDir, "ai-replay.json");
    mkdirSync(testDir, { recursive: true });
    writeFileSync(replayPath, JSON.stringify({ tests: [createHeaderTestCase()] }), "utf-8");

    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () => new Response("ok", { status: 200 })) as typeof fetch;

    try {
      const scanner = new AIScanner({
        provider: "ollama",
        model: "missing-model",
        replayTests: replayPath,
      });
      const findings = await scanner.run(createTestExecutionContext());
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].role).toBe("anonymous");
    } finally {
      globalThis.fetch = originalFetch;
      rmSync(testDir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// Scanner Failure Handling
// ---------------------------------------------------------------------------

describe("Scanner Failure Handling", () => {
  it("marks required unavailable scanners as incomplete", async () => {
    const orchestrator = new Orchestrator(
      [
        createMockScanner("Missing Tool", "static", () => {
          throw new ScannerUnavailableError("tool missing", "Missing Tool");
        }),
      ],
      { enabledCategories: ["static"], requiredCategories: ["static"], continueOnError: true }
    );
    const result = await orchestrator.runWithStatus(createTestExecutionContext());
    expect(result.isComplete).toBe(false);
    expect(result.failedScanners).toContain("Missing Tool");
    expect(result.unavailableScanners).toContain("Missing Tool");
  });

  it("marks optional unavailable scanners as skipped (scan still complete)", async () => {
    const orchestrator = new Orchestrator(
      [
        createMockScanner("Optional Tool", "static", () => {
          throw new ScannerUnavailableError("tool missing", "Optional Tool");
        }),
      ],
      { enabledCategories: ["static"], requiredCategories: [], continueOnError: true }
    );
    const result = await orchestrator.runWithStatus(createTestExecutionContext());
    expect(result.isComplete).toBe(true);
    expect(result.failedScanners.length).toBe(0);
    expect(result.skippedScanners).toContain("Optional Tool");
  });

  it("marks scanner runtime errors as failed", async () => {
    const orchestrator = new Orchestrator(
      [
        createMockScanner("Broken Scanner", "dynamic", () => {
          throw new ScannerError("boom", "Broken Scanner");
        }),
      ],
      { enabledCategories: ["dynamic"], requiredCategories: ["dynamic"], continueOnError: true }
    );
    const result = await orchestrator.runWithStatus(createTestExecutionContext());
    expect(result.isComplete).toBe(false);
    expect(result.failedScanners).toContain("Broken Scanner");
    expect(result.scannerStatuses[0].status).toBe("failed");
  });

  it("returns INCONCLUSIVE when all optional scanners are unavailable", async () => {
    const orchestrator = new Orchestrator(
      [
        createMockScanner("Tool A", "static", () => {
          throw new ScannerUnavailableError("not found", "Tool A");
        }),
        createMockScanner("Tool B", "dynamic", () => {
          throw new ScannerUnavailableError("not found", "Tool B");
        }),
      ],
      { enabledCategories: ["static", "dynamic"], requiredCategories: [], continueOnError: true }
    );
    const result = await orchestrator.runWithStatus(createTestExecutionContext());
    expect(result.allScannersFailed).toBe(true);

    const analyzer = new AttackAnalyzer();
    const verdict = analyzer.generateVerdictWithStatus([], {
      isComplete: result.isComplete,
      failedScanners: result.failedScanners,
      allScannersFailed: result.allScannersFailed,
    });
    expect(verdict.verdict).toBe("INCONCLUSIVE");
  });
});

// ---------------------------------------------------------------------------
// Severity Weights
// ---------------------------------------------------------------------------

describe("Severity Weights", () => {
  const findings = normalizeFindings(createMockRawFindings());

  it("CRITICAL findings have higher avg risk than others", () => {
    const critical = findings.filter((f) => f.severity === "CRITICAL");
    const others = findings.filter((f) => f.severity !== "CRITICAL");
    if (critical.length > 0 && others.length > 0) {
      const avgCritical = critical.reduce((s, f) => s + f.riskScore, 0) / critical.length;
      const avgOthers = others.reduce((s, f) => s + f.riskScore, 0) / others.length;
      expect(avgCritical).toBeGreaterThan(avgOthers);
    }
  });

  it("injection findings have exploitability above 0.5", () => {
    const injections = findings.filter((f) => f.category.toLowerCase().includes("injection"));
    for (const finding of injections) {
      expect(finding.exploitability).toBeGreaterThan(0.5);
    }
  });
});
