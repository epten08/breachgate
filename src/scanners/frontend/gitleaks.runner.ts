import { tmpdir } from "os";
import { unlinkSync, existsSync, readFileSync } from "fs";
import { join } from "path";
import { RawFinding } from "../../findings/raw.finding.js";
import { runProcess, checkCommand } from "../../core/process.runner.js";
import { ScannerUnavailableError } from "../../core/errors.js";
import { logger } from "../../core/logger.js";

const SCANNER_NAME = "Gitleaks";

interface GitleaksLeak {
  Description: string;
  RuleID: string;
  Match: string;
  Secret: string;
  File: string;
  Line: number;
  Tags: string[];
}

export async function runGitleaksScan(targetDir: string): Promise<RawFinding[]> {
  const hasGitleaks = await checkCommand("gitleaks");
  if (!hasGitleaks) {
    throw new ScannerUnavailableError(
      "Gitleaks is not installed — secrets detection skipped",
      SCANNER_NAME,
      undefined,
      "Install gitleaks: brew install gitleaks  |  https://github.com/gitleaks/gitleaks#installing"
    );
  }

  const reportPath = join(tmpdir(), `breachgate-gitleaks-${Date.now()}.json`);

  try {
    logger.debug(`Running gitleaks on ${targetDir}`);

    // --no-git scans the working directory without git history (faster, no git required)
    // gitleaks exits 0 = no leaks, 1 = leaks found, 2+ = error
    const result = await runProcess(
      "gitleaks",
      [
        "detect",
        "--source",
        targetDir,
        "--report-format",
        "json",
        "--report-path",
        reportPath,
        "--no-git",
      ],
      { timeout: 120000 }
    );

    // Exit code 1 means leaks found — still a valid run
    if (result.exitCode > 1) {
      logger.warn(`Gitleaks error (exit ${result.exitCode}): ${result.stderr.slice(0, 200)}`);
      return [];
    }

    if (!existsSync(reportPath)) {
      return [];
    }

    const raw = readFileSync(reportPath, "utf-8");
    return parseGitleaksOutput(raw);
  } finally {
    try {
      if (existsSync(reportPath)) unlinkSync(reportPath);
    } catch {
      // non-fatal
    }
  }
}

function parseGitleaksOutput(raw: string): RawFinding[] {
  const trimmed = raw.trim();
  if (!trimmed || trimmed === "null" || trimmed === "[]") return [];

  let leaks: GitleaksLeak[];
  try {
    leaks = JSON.parse(trimmed) as GitleaksLeak[];
  } catch {
    logger.warn("Failed to parse Gitleaks JSON output");
    return [];
  }

  if (!Array.isArray(leaks)) return [];

  return leaks.map((leak) => ({
    source: SCANNER_NAME,
    category: "Exposed Secret",
    description: `${leak.Description} in ${leak.File}`,
    endpoint: `${leak.File}:${leak.Line}`,
    severityHint: "CRITICAL",
    evidence: leak.Match ? redact(leak.Match) : undefined,
    reference:
      "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
  }));
}

// Partially redact the matched secret so it's identifiable without being fully exposed in reports
function redact(match: string): string {
  if (match.length <= 8) return "***";
  return match.slice(0, 4) + "****" + match.slice(-2);
}
