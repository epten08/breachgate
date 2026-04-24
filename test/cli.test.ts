import { Dirent, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "fs";
import { dirname, join, resolve } from "path";
import { runProcess } from "../src/core/process.runner.js";

interface CliResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

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

async function runCli(args: string[], env?: Record<string, string>): Promise<CliResult> {
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

function readJson(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(path, "utf-8")) as Record<string, unknown>;
}

async function testCliExitCodes(root: string): Promise<boolean> {
  console.log("\nCLI Exit Code Tests:");
  let passed = 0;
  let total = 0;

  total++;
  if (await runTest("returns 0 for a clean CI scan", async () => {
    const configPath = join(root, "clean-security.config.yml");
    const outputDir = join(root, "clean-reports").replace(/\\/g, "/");
    writeConfig(configPath, disabledScannerConfig(outputDir));

    const result = await runCli(["scan", "--ci", "--config", configPath, "--format", "json"]);
    assertEqual(result.exitCode, 0, "Clean scan should exit 0");
    assert(result.stdout.includes("SECURITY STATUS: PASSED"), "Should print passed status");
    assert(existsSync(join(outputDir, "security-report.json")), "Should write JSON report");
  })) passed++;

  total++;
  if (await runTest("returns 2 for configuration errors", async () => {
    const result = await runCli(["scan", "--ci", "--config", join(root, "missing.yml")]);
    assertEqual(result.exitCode, 2, "Missing config should exit 2");
    assert(result.stdout.includes("Configuration error"), "Should explain configuration failure");
  })) passed++;

  total++;
  if (await runTest("returns 1 when a required scanner is unavailable", async () => {
    const configPath = join(root, "static-security.config.yml");
    const outputDir = join(root, "static-reports").replace(/\\/g, "/");
    writeConfig(configPath, staticScannerConfig(outputDir));

    const result = await runCli(["scan", "--ci", "--config", configPath], {
      PATH: "",
      Path: "",
    });

    assertEqual(result.exitCode, 1, "Unavailable required scanner should exit 1");
    assert(result.stdout.includes("SECURITY STATUS: FAILED"), "Policy should fail the scan");
    const report = readJson(join(outputDir, "security-report.json"));
    const scannerStatus = report.scannerStatus as {
      unavailable: string[];
      failed: string[];
    };
    assert(scannerStatus.unavailable.includes("Trivy Static"), "Report should list unavailable scanner");
    assert(scannerStatus.failed.includes("Trivy Static"), "Report should list failed scanner gate");
  })) passed++;

  console.log(`  ${passed}/${total} tests passed`);
  return passed === total;
}

async function testMonorepoOptions(root: string): Promise<boolean> {
  console.log("\nMonorepo And Multi-Config Tests:");
  let passed = 0;
  let total = 0;

  total++;
  if (await runTest("resolves config paths from --workdir", async () => {
    const serviceDir = join(root, "service-a");
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

    assertEqual(result.exitCode, 0, "Workdir scan should exit 0");
    assert(existsSync(join(serviceDir, "reports", "security-report.json")), "Report should be relative to workdir");
  })) passed++;

  total++;
  if (await runTest("runs multiple configs with isolated report directories", async () => {
    const svcA = join(root, "svc-a", "security.config.yml");
    const svcB = join(root, "svc-b", "security.config.yml");
    const outputDir = join(root, "multi-reports");
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

    assertEqual(result.exitCode, 0, "Multi-config scan should exit 0");
    assert(result.stdout.includes("SECURITY CONFIG:"), "Should label each config in output");
    const reportFiles = findFiles(outputDir, "security-report.json");
    assertEqual(reportFiles.length, 2, "Should write one JSON report per config");
  })) passed++;

  console.log(`  ${passed}/${total} tests passed`);
  return passed === total;
}

async function testReportSchemaCompatibility(root: string): Promise<boolean> {
  console.log("\nReport Schema Compatibility Tests:");
  let passed = 0;
  let total = 0;

  total++;
  if (await runTest("emits required JSON report fields", async () => {
    const configPath = join(root, "schema-security.config.yml");
    const outputDir = join(root, "schema-reports").replace(/\\/g, "/");
    writeConfig(configPath, disabledScannerConfig(outputDir));

    const result = await runCli(["scan", "--ci", "--config", configPath, "--format", "json"]);
    assertEqual(result.exitCode, 0, "Schema scan should exit 0");

    const report = readJson(join(outputDir, "security-report.json"));
    assertEqual((report.metadata as Record<string, unknown>).schemaVersion, "1.3.0", "Schema version should remain compatible");
    assert(report.verdict !== undefined, "Report should include verdict");
    assert(report.scannerStatus !== undefined, "Report should include scanner status");
    assert(report.policy !== undefined, "Report should include active policy");
    assert(report.policyEvaluation !== undefined, "Report should include policy evaluation");
    assert(Array.isArray(report.findings), "Report findings should be an array");
  })) passed++;

  console.log(`  ${passed}/${total} tests passed`);
  return passed === total;
}

function findFiles(root: string, filename: string): string[] {
  if (!existsSync(root)) {
    return [];
  }

  const results: string[] = [];
  const entries = readdirSync(root, { withFileTypes: true }) as Dirent[];

  for (const entry of entries) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      results.push(...findFiles(path, filename));
    } else if (entry.isFile() && entry.name === filename) {
      results.push(path);
    }
  }

  return results;
}

async function main(): Promise<void> {
  const root = resolve("test-cli-output");
  rmSync(root, { recursive: true, force: true });
  mkdirSync(root, { recursive: true });

  try {
    const results = [
      await testCliExitCodes(root),
      await testMonorepoOptions(root),
      await testReportSchemaCompatibility(root),
    ];

    if (!results.every(Boolean)) {
      process.exit(1);
    }

    console.log("\n✓ CLI hardening tests passed");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error("CLI test runner failed:", err);
  process.exit(1);
});
