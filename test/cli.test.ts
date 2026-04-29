/**
 * CLI hardening tests.
 * These tests spawn the CLI as a subprocess to validate exit codes,
 * multi-config support, and report schema stability.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
  Dirent,
} from "fs";
import { dirname, join, resolve } from "path";
import { runProcess } from "../src/core/process.runner.js";

const ROOT = resolve("test-cli-output");

beforeAll(() => {
  rmSync(ROOT, { recursive: true, force: true });
  mkdirSync(ROOT, { recursive: true });
});

afterAll(() => {
  rmSync(ROOT, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function runCli(args: string[], env?: Record<string, string>) {
  const tsxBin = resolve("node_modules/tsx/dist/cli.mjs");
  return runProcess(process.execPath, [tsxBin, "src/cli/index.ts", ...args], {
    env,
    timeout: 120000,
  });
}

function writeConfig(path: string, body: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, body.trimStart(), "utf-8");
}

function readJson(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(path, "utf-8")) as Record<string, unknown>;
}

function findFiles(root: string, filename: string): string[] {
  if (!existsSync(root)) return [];
  const results: string[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true }) as Dirent[]) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      results.push(...findFiles(path, filename));
    } else if (entry.isFile() && entry.name === filename) {
      results.push(path);
    }
  }
  return results;
}

function disabledScannerConfig(outputDir: string): string {
  return `
version: "1.0"
target:
  baseUrl: http://127.0.0.1:9
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
  outputDir: ${outputDir}
  formats:
    - json
  includeEvidence: true
`;
}

function staticScannerConfig(outputDir: string): string {
  return `
version: "1.0"
target:
  baseUrl: http://127.0.0.1:9
scanners:
  static:
    enabled: true
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
  outputDir: ${outputDir}
  formats:
    - json
  includeEvidence: true
`;
}

// ---------------------------------------------------------------------------
// Exit Codes
// ---------------------------------------------------------------------------

describe("CLI Exit Codes", () => {
  it("returns 0 for a clean CI scan with all scanners disabled", async () => {
    const configPath = join(ROOT, "clean-security.config.yml");
    const outputDir = join(ROOT, "clean-reports").replace(/\\/g, "/");
    writeConfig(configPath, disabledScannerConfig(outputDir));

    const result = await runCli(["scan", "--ci", "--config", configPath, "--format", "json"]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("SECURITY STATUS: PASSED");
    expect(existsSync(join(outputDir, "security-report.json"))).toBe(true);
  });

  it("returns 2 for configuration errors (missing config file)", async () => {
    const result = await runCli(["scan", "--ci", "--config", join(ROOT, "missing.yml")]);
    expect(result.exitCode).toBe(2);
    expect(result.stdout).toContain("Configuration error");
  });

  it("returns 1 when a required scanner is unavailable and lists it in the report", async () => {
    const configPath = join(ROOT, "static-security.config.yml");
    const outputDir = join(ROOT, "static-reports").replace(/\\/g, "/");
    writeConfig(configPath, staticScannerConfig(outputDir));

    const result = await runCli(["scan", "--ci", "--config", configPath], { PATH: "", Path: "" });

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toContain("SECURITY STATUS: FAILED");

    const report = readJson(join(outputDir, "security-report.json"));
    const scannerStatus = report.scannerStatus as { unavailable: string[]; failed: string[] };
    expect(scannerStatus.unavailable).toContain("Trivy Static");
    expect(scannerStatus.failed).toContain("Trivy Static");
  });
});

// ---------------------------------------------------------------------------
// Monorepo / Multi-Config
// ---------------------------------------------------------------------------

describe("Monorepo and Multi-Config", () => {
  it("resolves config paths relative to --workdir", async () => {
    const serviceDir = join(ROOT, "service-a");
    writeConfig(join(serviceDir, "security.config.yml"), disabledScannerConfig("./reports"));

    const result = await runCli([
      "scan",
      "--ci",
      "--workdir",
      serviceDir,
      "--config",
      "security.config.yml",
      "--format",
      "json",
    ]);

    expect(result.exitCode).toBe(0);
    expect(existsSync(join(serviceDir, "reports", "security-report.json"))).toBe(true);
  });

  it("runs multiple configs with isolated report directories", async () => {
    const svcA = join(ROOT, "svc-a", "security.config.yml");
    const svcB = join(ROOT, "svc-b", "security.config.yml");
    const outputDir = join(ROOT, "multi-reports");
    writeConfig(svcA, disabledScannerConfig("./reports"));
    writeConfig(svcB, disabledScannerConfig("./reports"));

    const result = await runCli([
      "scan",
      "--ci",
      "--configs",
      `${svcA},${svcB}`,
      "--output",
      outputDir,
      "--format",
      "json",
    ]);

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("SECURITY CONFIG:");
    const reportFiles = findFiles(outputDir, "security-report.json");
    expect(reportFiles.length).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Report Schema Compatibility
// ---------------------------------------------------------------------------

describe("Report Schema Compatibility", () => {
  it("emits all required JSON report fields", async () => {
    const configPath = join(ROOT, "schema-security.config.yml");
    const outputDir = join(ROOT, "schema-reports").replace(/\\/g, "/");
    writeConfig(configPath, disabledScannerConfig(outputDir));

    const result = await runCli(["scan", "--ci", "--config", configPath, "--format", "json"]);
    expect(result.exitCode).toBe(0);

    const report = readJson(join(outputDir, "security-report.json"));
    expect((report.metadata as Record<string, unknown>).schemaVersion).toBe("1.3.0");
    expect(report.verdict).toBeDefined();
    expect(report.scannerStatus).toBeDefined();
    expect(report.policy).toBeDefined();
    expect(report.policyEvaluation).toBeDefined();
    expect(Array.isArray(report.findings)).toBe(true);
  });

  it("generates self-contained HTML report via --format html", async () => {
    const configPath = join(ROOT, "html-security.config.yml");
    const outputDir = join(ROOT, "html-reports").replace(/\\/g, "/");
    writeConfig(configPath, disabledScannerConfig(outputDir));

    const result = await runCli(["scan", "--ci", "--config", configPath, "--format", "html"]);
    expect(result.exitCode).toBe(0);

    const htmlPath = join(outputDir, "security-report.html");
    expect(existsSync(htmlPath)).toBe(true);
    const html = readFileSync(htmlPath, "utf-8");
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("Breach Gate Security Report");
  });
});
