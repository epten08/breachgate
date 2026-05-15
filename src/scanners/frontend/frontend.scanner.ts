import { Scanner } from "../scanner.js";
import { ExecutionContext } from "../../orchestrator/context.js";
import { RawFinding } from "../../findings/raw.finding.js";
import { logger } from "../../core/logger.js";
import { ScannerUnavailableError } from "../../core/errors.js";
import { runSemgrepScan } from "./semgrep.runner.js";
import { runGitleaksScan } from "./gitleaks.runner.js";
import { runOsvScan } from "./osv.runner.js";
import { runProjectChecks } from "./project.checks.js";

export interface FrontendScannerOptions {
  /** Filesystem path to the frontend project root. Defaults to process.cwd(). */
  targetDir?: string;
  framework?: "react" | "vue" | "angular" | "next" | "auto";
  skipSemgrep?: boolean;
  skipSecrets?: boolean;
  skipDeps?: boolean;
  skipProjectChecks?: boolean;
}

type Runner = [label: string, fn: () => Promise<RawFinding[]>];

export class FrontendScanner implements Scanner {
  name = "Frontend Security Scanner";
  category = "frontend" as const;

  constructor(private readonly opts: FrontendScannerOptions = {}) {}

  async run(_ctx: ExecutionContext): Promise<RawFinding[]> {
    const targetDir = this.opts.targetDir ?? process.cwd();
    logger.scanner(this.name, "start", `Scanning frontend at ${targetDir}`);

    const runners: Runner[] = [];

    if (!this.opts.skipSemgrep) {
      runners.push(["Static Analysis (Semgrep)", () => runSemgrepScan(targetDir)]);
    }
    if (!this.opts.skipSecrets) {
      runners.push(["Secrets Detection (Gitleaks)", () => runGitleaksScan(targetDir)]);
    }
    if (!this.opts.skipDeps) {
      runners.push(["Dependency Vulnerabilities (OSV/npm audit)", () => runOsvScan(targetDir)]);
    }
    if (!this.opts.skipProjectChecks) {
      runners.push(["Project Health (lint/typecheck/build)", () => runProjectChecks(targetDir)]);
    }

    const findings: RawFinding[] = [];

    for (const [label, run] of runners) {
      try {
        const result = await run();
        findings.push(...result);
        logger.debug(`Frontend [${label}]: ${result.length} issue(s)`);
      } catch (err) {
        if (err instanceof ScannerUnavailableError) {
          logger.warn(`Frontend [${label}] skipped: ${err.message}`);
          if (err.hint) logger.info(`  Hint: ${err.hint}`);
        } else {
          logger.warn(`Frontend [${label}] failed: ${(err as Error).message}`);
        }
      }
    }

    logger.scanner(this.name, "done", `Found ${findings.length} frontend issue(s)`);
    return findings;
  }
}
