import { existsSync } from "fs";
import { join } from "path";
import { RawFinding } from "../../findings/raw.finding.js";
import { runProcess, checkCommand } from "../../core/process.runner.js";
import { ScannerUnavailableError } from "../../core/errors.js";
import { logger } from "../../core/logger.js";

const OSV_NAME = "OSV Scanner";
const NPM_AUDIT_NAME = "npm audit";

// OSV Scanner JSON output types
interface OsvResult {
  results?: OsvScanResult[];
}

interface OsvScanResult {
  source: { path: string; type: string };
  packages?: OsvPackage[];
}

interface OsvPackage {
  package: { name: string; version: string; ecosystem: string };
  vulnerabilities?: OsvVulnerability[];
}

interface OsvVulnerability {
  id: string;
  summary?: string;
  severity?: Array<{ type: string; score: string }>;
}

// npm audit v2 JSON output types
interface NpmAuditResult {
  vulnerabilities?: Record<string, NpmVulnerability>;
}

interface NpmVulnerability {
  name: string;
  severity: string;
  isDirect: boolean;
  range: string;
  fixAvailable: boolean | { name: string; version: string; isSemVerMajor: boolean };
  via: Array<
    | string
    | { name?: string; url?: string; title?: string; severity?: string; cwe?: string[] }
  >;
}

export async function runOsvScan(targetDir: string): Promise<RawFinding[]> {
  const hasOsv = await checkCommand("osv-scanner");
  if (hasOsv) {
    return runOsvScanner(targetDir);
  }

  logger.info(
    "osv-scanner not found — falling back to npm audit (install osv-scanner for richer results: https://google.github.io/osv-scanner)"
  );
  return runNpmAudit(targetDir);
}

async function runOsvScanner(targetDir: string): Promise<RawFinding[]> {
  try {
    logger.debug(`Running osv-scanner on ${targetDir}`);

    // -r = recursive lockfile search, --json = machine-readable output
    // osv-scanner exits 1 when vulnerabilities found — still a valid run
    const result = await runProcess("osv-scanner", ["-r", "--json", targetDir], {
      timeout: 120000,
    });

    if (result.exitCode > 1) {
      logger.warn(`osv-scanner error (exit ${result.exitCode}), falling back to npm audit`);
      return runNpmAudit(targetDir);
    }

    return parseOsvOutput(result.stdout);
  } catch {
    logger.warn("osv-scanner failed, falling back to npm audit");
    return runNpmAudit(targetDir);
  }
}

function parseOsvOutput(stdout: string): RawFinding[] {
  if (!stdout.trim()) return [];

  let data: OsvResult;
  try {
    data = JSON.parse(stdout) as OsvResult;
  } catch {
    logger.warn("Failed to parse OSV Scanner JSON output");
    return [];
  }

  const findings: RawFinding[] = [];
  for (const scanResult of data.results ?? []) {
    for (const pkg of scanResult.packages ?? []) {
      for (const vuln of pkg.vulnerabilities ?? []) {
        const cvssScore = vuln.severity?.find((s) => s.type.includes("CVSS"))?.score;
        findings.push({
          source: OSV_NAME,
          category: "Dependency Vulnerability",
          description: vuln.summary || `${vuln.id} affects ${pkg.package.name}`,
          severityHint: cvssScoreToSeverity(cvssScore),
          evidence: `${pkg.package.name}@${pkg.package.version}`,
          cve: vuln.id.startsWith("CVE-") ? vuln.id : undefined,
          package: pkg.package.name,
          version: pkg.package.version,
          reference: `https://osv.dev/vulnerability/${vuln.id}`,
        });
      }
    }
  }
  return findings;
}

async function runNpmAudit(targetDir: string): Promise<RawFinding[]> {
  const hasNpm = await checkCommand("npm");
  if (!hasNpm) {
    throw new ScannerUnavailableError(
      "Neither osv-scanner nor npm is available for dependency scanning",
      NPM_AUDIT_NAME,
      undefined,
      "Install Node.js (includes npm): https://nodejs.org"
    );
  }

  const lockFile = join(targetDir, "package-lock.json");
  const yarnLock = join(targetDir, "yarn.lock");
  const pkgJson = join(targetDir, "package.json");

  if (!existsSync(pkgJson)) {
    logger.debug("No package.json found, skipping dependency scan");
    return [];
  }

  if (!existsSync(lockFile) && !existsSync(yarnLock)) {
    logger.debug("No lockfile found — run `npm install` first to enable dependency scanning");
    return [];
  }

  try {
    logger.debug(`Running npm audit in ${targetDir}`);

    // npm audit exits 1 when vulnerabilities exist — stdout still has JSON
    const result = await runProcess("npm", ["audit", "--json"], {
      cwd: targetDir,
      timeout: 120000,
      shell: process.platform === "win32",
    });

    return parseNpmAuditOutput(result.stdout);
  } catch (err) {
    logger.warn(`npm audit failed: ${(err as Error).message}`);
    return [];
  }
}

function parseNpmAuditOutput(stdout: string): RawFinding[] {
  if (!stdout.trim()) return [];

  let data: NpmAuditResult;
  try {
    data = JSON.parse(stdout) as NpmAuditResult;
  } catch {
    logger.warn("Failed to parse npm audit JSON output");
    return [];
  }

  const findings: RawFinding[] = [];

  for (const [pkgName, vuln] of Object.entries(data.vulnerabilities ?? {})) {
    const viaItems = Array.isArray(vuln.via) ? vuln.via : [];
    const advisoryVia = viaItems.find(
      (v): v is { title?: string; url?: string; severity?: string; cwe?: string[] } =>
        typeof v === "object" && v !== null
    );

    const description = advisoryVia?.title
      ? advisoryVia.title
      : `Vulnerability in ${pkgName} (${vuln.severity})`;

    findings.push({
      source: NPM_AUDIT_NAME,
      category: "Dependency Vulnerability",
      description,
      severityHint: mapNpmSeverity(vuln.severity),
      evidence: `${pkgName} affected range: ${vuln.range}`,
      package: pkgName,
      cwe: advisoryVia?.cwe?.[0],
      reference: advisoryVia?.url,
    });
  }

  return findings;
}

function mapNpmSeverity(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "CRITICAL";
    case "high":
      return "HIGH";
    case "moderate":
      return "MEDIUM";
    case "low":
      return "LOW";
    default:
      return "LOW";
  }
}

function cvssScoreToSeverity(score: string | undefined): string {
  if (!score) return "MEDIUM";
  const num = parseFloat(score);
  if (isNaN(num)) return "MEDIUM";
  if (num >= 9.0) return "CRITICAL";
  if (num >= 7.0) return "HIGH";
  if (num >= 4.0) return "MEDIUM";
  return "LOW";
}
