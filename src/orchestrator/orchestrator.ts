import { Scanner, ScannerCategory } from "../scanners/scanner";
import { ExecutionContext } from "./context";
import { Finding } from "../findings/finding";
import { RawFinding } from "../findings/raw.finding";
import { normalizeFindings } from "../findings/normalizer";
import { logger } from "../core/logger";
import { ScannerError } from "../core/errors";

export interface OrchestratorOptions {
  enabledCategories?: ScannerCategory[];
  parallel?: boolean;
  continueOnError?: boolean;
}

/**
 * Result of a scan run - includes both findings AND scanner status
 * This is critical for reliability: SCAN FAILED ≠ NO VULNERABILITIES
 */
export interface ScanResult {
  findings: Finding[];
  failedScanners: string[];
  completedScanners: string[];
  isComplete: boolean;  // True only if all enabled scanners succeeded
}

export class Orchestrator {
  private scanners: Scanner[];
  private options: OrchestratorOptions;

  constructor(scanners: Scanner[], options: OrchestratorOptions = {}) {
    this.scanners = scanners;
    this.options = {
      enabledCategories: ["static", "container", "dynamic"],
      parallel: false,
      continueOnError: true,
      ...options,
    };
  }

  /**
   * @deprecated Use runWithStatus() instead for proper failure handling
   */
  async run(ctx: ExecutionContext): Promise<Finding[]> {
    const result = await this.runWithStatus(ctx);
    return result.findings;
  }

  /**
   * Run scanners and return both findings AND scanner status
   * This allows the caller to distinguish between "no vulnerabilities" and "scan failed"
   */
  async runWithStatus(ctx: ExecutionContext): Promise<ScanResult> {
    const enabledScanners = this.scanners.filter(
      (s) => this.options.enabledCategories?.includes(s.category)
    );

    if (enabledScanners.length === 0) {
      logger.warn("No scanners enabled");
      return {
        findings: [],
        failedScanners: [],
        completedScanners: [],
        isComplete: true,  // No scanners = technically complete
      };
    }

    logger.info(`Running ${enabledScanners.length} scanners`);

    let result: { rawFindings: RawFinding[]; failed: string[]; completed: string[] };

    if (this.options.parallel) {
      result = await this.runParallelWithStatus(enabledScanners, ctx);
    } else {
      result = await this.runSequentialWithStatus(enabledScanners, ctx);
    }

    const normalized = normalizeFindings(result.rawFindings);

    logger.info(`Scan complete: ${normalized.length} findings`);

    if (result.failed.length > 0) {
      logger.warn(`${result.failed.length} scanner(s) failed: ${result.failed.join(", ")}`);
    }

    return {
      findings: normalized,
      failedScanners: result.failed,
      completedScanners: result.completed,
      isComplete: result.failed.length === 0,
    };
  }

  private async runSequentialWithStatus(
    scanners: Scanner[],
    ctx: ExecutionContext
  ): Promise<{ rawFindings: RawFinding[]; failed: string[]; completed: string[] }> {
    const rawFindings: RawFinding[] = [];
    const failed: string[] = [];
    const completed: string[] = [];

    for (const scanner of scanners) {
      try {
        const results = await scanner.run(ctx);
        rawFindings.push(...results);
        completed.push(scanner.name);
      } catch (err) {
        failed.push(scanner.name);

        if (err instanceof ScannerError) {
          logger.error(`Scanner ${scanner.name} failed: ${err.message}`);
        } else {
          logger.error(`Scanner ${scanner.name} failed: ${(err as Error).message}`);
        }

        if (!this.options.continueOnError) {
          throw err;
        }
      }
    }

    return { rawFindings, failed, completed };
  }

  private async runParallelWithStatus(
    scanners: Scanner[],
    ctx: ExecutionContext
  ): Promise<{ rawFindings: RawFinding[]; failed: string[]; completed: string[] }> {
    const results = await Promise.allSettled(
      scanners.map((scanner) => scanner.run(ctx))
    );

    const rawFindings: RawFinding[] = [];
    const failed: string[] = [];
    const completed: string[] = [];

    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      const scanner = scanners[i];

      if (result.status === "fulfilled") {
        rawFindings.push(...result.value);
        completed.push(scanner.name);
      } else {
        failed.push(scanner.name);
        logger.error(`Scanner ${scanner.name} failed: ${result.reason}`);

        if (!this.options.continueOnError) {
          throw result.reason;
        }
      }
    }

    return { rawFindings, failed, completed };
  }

  // Keep old methods for backward compatibility
  private async runSequential(scanners: Scanner[], ctx: ExecutionContext): Promise<RawFinding[]> {
    const result = await this.runSequentialWithStatus(scanners, ctx);
    return result.rawFindings;
  }

  private async runParallel(scanners: Scanner[], ctx: ExecutionContext): Promise<RawFinding[]> {
    const result = await this.runParallelWithStatus(scanners, ctx);
    return result.rawFindings;
  }
}
