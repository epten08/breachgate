import { existsSync, readFileSync } from "fs";
import { join } from "path";
import { RawFinding } from "../../findings/raw.finding.js";
import { runProcess } from "../../core/process.runner.js";
import { logger } from "../../core/logger.js";

const SCANNER_NAME = "Project Health";

interface PackageJson {
  scripts?: Record<string, string>;
}

interface CheckDefinition {
  aliases: string[];
  label: string;
  severityHint: string;
  category: string;
}

const CHECKS: CheckDefinition[] = [
  {
    aliases: ["lint", "eslint", "tslint"],
    label: "Lint",
    severityHint: "LOW",
    category: "Code Quality",
  },
  {
    aliases: ["typecheck", "type-check", "tsc", "check"],
    label: "Type Check",
    severityHint: "MEDIUM",
    category: "Type Safety",
  },
  {
    aliases: ["build"],
    label: "Build",
    severityHint: "HIGH",
    category: "Build Failure",
  },
];

export async function runProjectChecks(targetDir: string): Promise<RawFinding[]> {
  const pkgPath = join(targetDir, "package.json");
  if (!existsSync(pkgPath)) {
    logger.debug("No package.json found, skipping project health checks");
    return [];
  }

  let scripts: Record<string, string> = {};
  try {
    const raw = readFileSync(pkgPath, "utf-8");
    const pkg = JSON.parse(raw) as PackageJson;
    scripts = pkg.scripts ?? {};
  } catch {
    logger.warn("Failed to read package.json for project health checks");
    return [];
  }

  const findings: RawFinding[] = [];
  const isWindows = process.platform === "win32";

  for (const check of CHECKS) {
    const scriptName = check.aliases.find((alias) => alias in scripts);
    if (!scriptName) {
      logger.debug(`No ${check.label} script found in package.json, skipping`);
      continue;
    }

    logger.debug(`Running npm run ${scriptName} in ${targetDir}`);
    try {
      const result = await runProcess("npm", ["run", scriptName], {
        cwd: targetDir,
        timeout: 300000,
        shell: isWindows,
      });

      if (result.exitCode !== 0) {
        findings.push({
          source: SCANNER_NAME,
          category: check.category,
          description: `${check.label} failed — ${extractErrorSummary(result.stderr || result.stdout)}`,
          severityHint: check.severityHint,
          evidence: truncate(result.stderr || result.stdout, 500),
        });
      }
    } catch (err) {
      logger.debug(`${check.label} script could not be run: ${(err as Error).message}`);
    }
  }

  return findings;
}

function extractErrorSummary(output: string): string {
  const lines = output
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
  const errorLine = lines.find((l) => /error|Error|ERROR|failed|FAILED/i.test(l));
  const summary = errorLine ?? lines[lines.length - 1] ?? "check output for details";
  return summary.slice(0, 200);
}

function truncate(str: string, maxLen: number): string {
  return str.length <= maxLen ? str : str.slice(0, maxLen) + "…";
}
