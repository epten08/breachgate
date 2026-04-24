/**
 * Integration tests for Breach Gate
 *
 * These tests validate the end-to-end pipeline without requiring
 * external tools (Trivy, ZAP, Ollama) to be installed.
 */

import { loadConfig, validateConfig } from "../src/core/config.loader.js";
import { logger } from "../src/core/logger.js";
import { Finding, Severity } from "../src/findings/finding.js";
import { normalizeFindings, sortByRisk } from "../src/findings/normalizer.js";
import { RawFinding } from "../src/findings/raw.finding.js";
import { ReportGenerator } from "../src/reports/report.generator.js";
import { JsonReporter } from "../src/reports/json.reporter.js";
import { MarkdownReporter } from "../src/reports/markdown.reporter.js";
import { SarifReporter } from "../src/reports/sarif.reporter.js";
import { CliSummary } from "../src/reports/cli.summary.js";
import { existsSync, rmSync, mkdirSync, writeFileSync } from "fs";
import { join } from "path";
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

// Test utilities
function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

function assertEqual<T>(actual: T, expected: T, message: string): void {
  if (actual !== expected) {
    throw new Error(`${message}: expected ${expected}, got ${actual}`);
  }
}

async function runTest(name: string, fn: () => Promise<void> | void): Promise<boolean> {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    return true;
  } catch (err) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${(err as Error).message}`);
    return false;
  }
}

// Test Data
function createMockRawFindings(): RawFinding[] {
  return [
    {
      description: "SQL Injection in login endpoint - The login endpoint is vulnerable to SQL injection",
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

// Tests
async function testConfigLoader(): Promise<boolean> {
  console.log("\n📋 Config Loader Tests:");
  let passed = 0;
  let total = 0;

  total++;
  if (await runTest("loads default config when no file specified", () => {
    const config = loadConfig();
    assert(config !== null, "Config should not be null");
    assert(config.target !== undefined, "Target should be defined");
  })) passed++;

  total++;
  if (await runTest("validates config structure", () => {
    const config = loadConfig();
    validateConfig(config);
    assert(config.scanners !== undefined, "Scanners should be defined");
  })) passed++;

  total++;
  if (await runTest("throws on missing explicit config file", () => {
    let threw = false;
    try {
      loadConfig("nonexistent.yml");
    } catch (err) {
      threw = true;
      assert((err as Error).message.includes("Config file not found"), "Should throw ConfigError");
    }
    assert(threw, "Should throw when explicit config file is missing");
  })) passed++;

  total++;
  if (await runTest("expands environment variables in config values", () => {
    const testDir = "./test-output";
    const configPath = join(testDir, "env-security.config.yml");
    mkdirSync(testDir, { recursive: true });
    process.env.SEC_BOT_TEST_JWT = "test-token";

    writeFileSync(configPath, `
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
`, "utf-8");

    const config = loadConfig(configPath);
    assertEqual(config.auth?.token, "test-token", "Should expand JWT token");

    rmSync(testDir, { recursive: true });
    delete process.env.SEC_BOT_TEST_JWT;
  })) passed++;

  total++;
  if (await runTest("throws on missing environment variables in config values", () => {
    const testDir = "./test-output";
    const configPath = join(testDir, "missing-env-security.config.yml");
    mkdirSync(testDir, { recursive: true });

    writeFileSync(configPath, `
version: "1.0"
target:
  baseUrl: http://localhost:3000
auth:
  type: jwt
  token: \${SEC_BOT_MISSING_JWT}
`, "utf-8");

    let threw = false;
    try {
      loadConfig(configPath);
    } catch (err) {
      threw = true;
      assert((err as Error).message.includes("SEC_BOT_MISSING_JWT"), "Should name missing variable");
    }

    assert(threw, "Should throw when env var is missing");
    rmSync(testDir, { recursive: true });
  })) passed++;

  console.log(`  ${passed}/${total} tests passed`);
  return passed === total;
}

async function testFindingsNormalizer(): Promise<boolean> {
  console.log("\n🔍 Findings Normalizer Tests:");
  let passed = 0;
  let total = 0;

  const rawFindings = createMockRawFindings();

  total++;
  if (await runTest("normalizes raw findings to Finding objects", () => {
    const normalized = normalizeFindings(rawFindings);
    assert(Array.isArray(normalized), "Should return array");
    assert(normalized.length > 0, "Should have findings");
    assert(normalized[0].riskScore !== undefined, "Should have risk score");
  })) passed++;

  total++;
  if (await runTest("calculates risk scores", () => {
    const normalized = normalizeFindings(rawFindings);
    for (const finding of normalized) {
      assert(finding.riskScore >= 0 && finding.riskScore <= 1, "Risk score should be 0-1");
      assert(finding.exploitability >= 0, "Exploitability should be >= 0");
      assert(finding.confidence >= 0, "Confidence should be >= 0");
    }
  })) passed++;

  total++;
  if (await runTest("deduplicates similar findings", () => {
    const normalized = normalizeFindings(rawFindings);
    // Should deduplicate the two SQL injection findings
    const sqlFindings = normalized.filter(f => f.title.includes("SQL Injection"));
    assert(sqlFindings.length === 1, "Should deduplicate SQL injection findings");
    assert(sqlFindings[0].duplicateCount >= 1, "Should track duplicate count");
  })) passed++;

  total++;
  if (await runTest("sorts by risk correctly", () => {
    const normalized = normalizeFindings(rawFindings);
    const sorted = sortByRisk(normalized);
    for (let i = 1; i < sorted.length; i++) {
      assert(sorted[i - 1].riskScore >= sorted[i].riskScore, "Should be sorted by risk desc");
    }
  })) passed++;

  console.log(`  ${passed}/${total} tests passed`);
  return passed === total;
}

async function testReporting(): Promise<boolean> {
  console.log("\n📊 Reporting Tests:");
  let passed = 0;
  let total = 0;

  const rawFindings = createMockRawFindings();
  const findings = normalizeFindings(rawFindings);

  const reportConfig = {
    formats: ["json", "markdown"] as ("json" | "markdown")[],
    outputDir: "./test-reports",
    includeEvidence: true,
  };

  total++;
  if (await runTest("generates JSON report", () => {
    const reporter = new JsonReporter(reportConfig);
    const json = reporter.generate(findings, { targetUrl: "http://localhost:3000" });
    const parsed = JSON.parse(json);
    assert(parsed.metadata !== undefined, "Should have metadata");
    assert(parsed.summary !== undefined, "Should have summary");
    assert(parsed.findings !== undefined, "Should have findings");
    assert(parsed.summary.total === findings.length, "Should have correct count");
  })) passed++;

  total++;
  if (await runTest("JSON report includes verdict, scanner status, and policy", () => {
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
    };

    const reporter = new JsonReporter(reportConfig);
    const json = reporter.generate(findings, {
      targetUrl: "http://localhost:3000",
      verdict,
      scanResult,
      policy: {
        failOn: "HIGH",
        warnOn: "MEDIUM",
      },
    });
    const parsed = JSON.parse(json);

    assertEqual(parsed.verdict.status, "INCONCLUSIVE", "Should include verdict");
    assertEqual(parsed.scannerStatus.unavailable[0], "Trivy Static", "Should include unavailable scanner");
    assertEqual(parsed.policy.failOn, "HIGH", "Should include policy");
  })) passed++;

  total++;
  if (await runTest("generates Markdown report", () => {
    const reporter = new MarkdownReporter(reportConfig);
    const md = reporter.generate(findings, { targetUrl: "http://localhost:3000" });
    assert(md.includes("# Security Scan Report"), "Should have title");
    assert(md.includes("## Executive Summary"), "Should have summary");
    assert(md.includes("## Findings Summary"), "Should have findings table");
  })) passed++;

  total++;
  if (await runTest("generates SARIF report", () => {
    const reporter = new SarifReporter();
    const sarif = reporter.generate(findings, { targetUrl: "http://localhost:3000" });
    const parsed = JSON.parse(sarif);
    assertEqual(parsed.version, "2.1.0", "Should generate SARIF 2.1.0");
    assert(parsed.runs[0].results.length === findings.length, "Should include findings");
  })) passed++;

  total++;
  if (await runTest("CLI summary renders without error", () => {
    const summary = new CliSummary({ maxFindings: 5, verbose: false });
    // Just ensure it doesn't throw
    summary.render(findings);
  })) passed++;

  total++;
  if (await runTest("ReportGenerator creates files", async () => {
    const testDir = "./test-output";
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true });
    }
    mkdirSync(testDir, { recursive: true });

    const generator = new ReportGenerator({
      ...reportConfig,
      outputDir: testDir,
    });

    const reports = await generator.generate(findings, {
      targetUrl: "http://localhost:3000",
      scanDuration: 5000,
    });

    assert(reports.length === 2, "Should generate 2 reports");
    for (const report of reports) {
      assert(existsSync(report.path), `Report should exist: ${report.path}`);
    }

    // Cleanup
    rmSync(testDir, { recursive: true });
  })) passed++;

  console.log(`  ${passed}/${total} tests passed`);
  return passed === total;
}

async function testPolicy(): Promise<boolean> {
  console.log("\n🧭 Policy Tests:");
  let passed = 0;
  let total = 0;

  const findings = normalizeFindings(createMockRawFindings());

  total++;
  if (await runTest("fingerprints findings deterministically", () => {
    const first = fingerprintFinding(findings[0]);
    const second = fingerprintFinding(findings[0]);
    assertEqual(first, second, "Fingerprint should be deterministic");
  })) passed++;

  total++;
  if (await runTest("suppresses baseline findings", () => {
    const fingerprint = fingerprintFinding(findings[0]);
    const result = applyBaseline(findings, {
      version: "1.0",
      findings: [
        {
          fingerprint,
          owner: "security",
          reason: "Accepted test finding",
          expires: "2999-12-31",
        },
      ],
    });

    assertEqual(result.suppressed.length, 1, "Should suppress baseline finding");
    assertEqual(result.effectiveFindings.length, findings.length - 1, "Should leave non-baselined findings");
  })) passed++;

  total++;
  if (await runTest("evaluates pull request policy", () => {
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
      },
      profile,
      rules,
    });

    assertEqual(evaluation.status, "failed", "Pull request policy should fail on high/critical findings");
  })) passed++;

  console.log(`  ${passed}/${total} tests passed`);
  return passed === total;
}

async function testAuthAndSafety(): Promise<boolean> {
  console.log("\n🔐 Auth, Replay, And Safety Tests:");
  let passed = 0;
  let total = 0;

  total++;
  if (await runTest("resolves multi-role auth contexts and session headers", async () => {
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

    assertEqual(contexts.length, 2, "Should resolve two auth roles");
    const headers = buildAuthHeaders(contexts[1]);
    assertEqual(headers.Cookie, "sid=abc123", "Should build session cookie header");
    assertEqual(headers["X-Role"], "admin", "Should include custom role headers");
  })) passed++;

  total++;
  if (await runTest("runs pre-scan auth hooks", async () => {
    const contexts = await resolveAuthContexts({
      type: "jwt",
      preScan: {
        command: process.execPath,
        args: ["-e", "console.log(JSON.stringify({ token: 'hook-token', headers: { 'X-Trace': 'ci' } }))"],
        output: "json",
      },
    });

    assertEqual(contexts[0].token, "hook-token", "Should read token from hook output");
    assertEqual(contexts[0].headers?.["X-Trace"], "ci", "Should read headers from hook output");
  })) passed++;

  total++;
  if (await runTest("enforces host allowlists and active scan profiles", () => {
    enforceTargetSafety(
      { profile: "safe-active", allowedHosts: ["*.example.com"] },
      "https://api.example.com",
      true
    );

    let threw = false;
    try {
      enforceTargetSafety(
        { profile: "safe-active", allowedHosts: ["api.example.com"] },
        "https://evil.example.com",
        true
      );
    } catch {
      threw = true;
    }

    assert(threw, "Should reject hosts outside the allowlist");
    assert(!allowsDestructiveMethod("DELETE", { profile: "safe-active" }), "safe-active should block DELETE");
    assert(allowsDestructiveMethod("DELETE", { profile: "full-active" }), "full-active should allow DELETE");
    assert(!shouldRunZapActiveScan({ profile: "safe-active" }), "safe-active should skip ZAP active scan");
    assert(shouldRunZapActiveScan({ profile: "full-active" }), "full-active should run ZAP active scan");
  })) passed++;

  total++;
  if (await runTest("AI executor sends cookie and custom auth headers", async () => {
    const originalFetch = globalThis.fetch;
    let capturedHeaders: Record<string, string> = {};

    globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      capturedHeaders = init?.headers as Record<string, string>;
      return new Response("ok", { status: 200 });
    }) as typeof fetch;

    try {
      const executor = new TestExecutor(createTestExecutionContext({
        type: "session",
        role: "admin",
        cookieName: "sid",
        cookieValue: "cookie-value",
        headers: { "X-Test-Role": "admin" },
      }));
      const results = await executor.execute([createHeaderTestCase()]);

      assertEqual(results.length, 1, "Should execute one test");
      assertEqual(capturedHeaders.Cookie, "sid=cookie-value", "Should send session cookie");
      assertEqual(capturedHeaders["X-Test-Role"], "admin", "Should send custom auth header");
    } finally {
      globalThis.fetch = originalFetch;
    }
  })) passed++;

  total++;
  if (await runTest("AI scanner replays saved tests without an available model", async () => {
    const testDir = "./test-output";
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

      assert(findings.length > 0, "Replay should produce rule-based findings");
      assertEqual(findings[0].role, "anonymous", "Replay findings should include role");
    } finally {
      globalThis.fetch = originalFetch;
      rmSync(testDir, { recursive: true, force: true });
    }
  })) passed++;

  console.log(`  ${passed}/${total} tests passed`);
  return passed === total;
}

async function testScannerFailureHandling(): Promise<boolean> {
  console.log("\n🧱 Scanner Failure Handling Tests:");
  let passed = 0;
  let total = 0;

  total++;
  if (await runTest("marks required unavailable scanners as incomplete", async () => {
    const orchestrator = new Orchestrator([
      createMockScanner("Missing Tool", "static", () => {
        throw new ScannerUnavailableError("tool missing", "Missing Tool");
      }),
    ], {
      enabledCategories: ["static"],
      requiredCategories: ["static"],
      continueOnError: true,
    });

    const result = await orchestrator.runWithStatus(createTestExecutionContext());
    assertEqual(result.isComplete, false, "Required unavailable scanner should make scan incomplete");
    assert(result.failedScanners.includes("Missing Tool"), "Should list unavailable scanner as failed");
    assert(result.unavailableScanners.includes("Missing Tool"), "Should list unavailable scanner separately");
  })) passed++;

  total++;
  if (await runTest("marks optional unavailable scanners as skipped", async () => {
    const orchestrator = new Orchestrator([
      createMockScanner("Optional Tool", "static", () => {
        throw new ScannerUnavailableError("tool missing", "Optional Tool");
      }),
    ], {
      enabledCategories: ["static"],
      requiredCategories: [],
      continueOnError: true,
    });

    const result = await orchestrator.runWithStatus(createTestExecutionContext());
    assertEqual(result.isComplete, true, "Optional unavailable scanner should not fail the run");
    assertEqual(result.failedScanners.length, 0, "Optional unavailable scanner should not be failed");
    assert(result.skippedScanners.includes("Optional Tool"), "Optional unavailable scanner should be skipped");
  })) passed++;

  total++;
  if (await runTest("marks scanner errors as failed", async () => {
    const orchestrator = new Orchestrator([
      createMockScanner("Broken Scanner", "dynamic", () => {
        throw new ScannerError("boom", "Broken Scanner");
      }),
    ], {
      enabledCategories: ["dynamic"],
      requiredCategories: ["dynamic"],
      continueOnError: true,
    });

    const result = await orchestrator.runWithStatus(createTestExecutionContext());
    assertEqual(result.isComplete, false, "Scanner errors should fail the run");
    assert(result.failedScanners.includes("Broken Scanner"), "Should track failed scanner");
    assertEqual(result.scannerStatuses[0].status, "failed", "Status should be failed");
  })) passed++;

  console.log(`  ${passed}/${total} tests passed`);
  return passed === total;
}

async function testSeverityWeights(): Promise<boolean> {
  console.log("\n⚖️ Severity Weight Tests:");
  let passed = 0;
  let total = 0;

  const rawFindings = createMockRawFindings();
  const findings = normalizeFindings(rawFindings);

  total++;
  if (await runTest("CRITICAL findings have highest risk", () => {
    const critical = findings.filter(f => f.severity === "CRITICAL");
    const others = findings.filter(f => f.severity !== "CRITICAL");

    if (critical.length > 0 && others.length > 0) {
      const avgCritical = critical.reduce((sum, f) => sum + f.riskScore, 0) / critical.length;
      const avgOthers = others.reduce((sum, f) => sum + f.riskScore, 0) / others.length;
      assert(avgCritical > avgOthers, "Critical should have higher avg risk");
    }
  })) passed++;

  total++;
  if (await runTest("exploitability affects risk score", () => {
    // Injection vulnerabilities should have higher exploitability
    const injections = findings.filter(f => f.category.toLowerCase().includes("injection"));
    for (const finding of injections) {
      assert(finding.exploitability > 0.5, "Injection should have high exploitability");
    }
  })) passed++;

  console.log(`  ${passed}/${total} tests passed`);
  return passed === total;
}

function createHeaderTestCase(): SecurityTestCase {
  return {
    name: "Missing Header - GET /health",
    endpoint: "GET /health",
    category: "Security Misconfiguration",
    description: "Detect a missing response header",
    request: {
      method: "GET",
      path: "/health",
    },
    expectedVulnerable: {
      headerMissing: ["X-Test-Security"],
    },
  };
}

function createMockScanner(
  name: string,
  category: Scanner["category"],
  run: Scanner["run"]
): Scanner {
  return {
    name,
    category,
    run,
  };
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
    auth: auth || { type: "none", role: "anonymous" },
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

// Main test runner
async function main(): Promise<void> {
  console.log("═".repeat(60));
  console.log("          Breach Gate Integration Tests");
  console.log("═".repeat(60));

  logger.setLevel("error"); // Suppress logs during tests

  const results: boolean[] = [];

  results.push(await testConfigLoader());
  results.push(await testFindingsNormalizer());
  results.push(await testReporting());
  results.push(await testPolicy());
  results.push(await testAuthAndSafety());
  results.push(await testScannerFailureHandling());
  results.push(await testSeverityWeights());

  console.log("\n" + "═".repeat(60));

  const allPassed = results.every(r => r);
  const passedCount = results.filter(r => r).length;

  if (allPassed) {
    console.log(`✓ All test suites passed (${passedCount}/${results.length})`);
    process.exit(0);
  } else {
    console.log(`✗ Some test suites failed (${passedCount}/${results.length} passed)`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Test runner failed:", err);
  process.exit(1);
});

