import { Scanner, ScannerCategory } from "../scanners/scanner.js";
import { ExecutionContext } from "./context.js";
import { Finding } from "../findings/finding.js";
import { RawFinding } from "../findings/raw.finding.js";
import { normalizeFindings } from "../findings/normalizer.js";
import { logger } from "../core/logger.js";
import { ScannerError, ScannerUnavailableError } from "../core/errors.js";

export interface OrchestratorOptions {
  enabledCategories?: ScannerCategory[];
  requiredCategories?: ScannerCategory[];
  parallel?: boolean;
  continueOnError?: boolean;
}

export type ScannerRunStatus = "completed" | "failed" | "skipped" | "unavailable";

export interface ScannerStatus {
  name: string;
  category: ScannerCategory;
  status: ScannerRunStatus;
  required: boolean;
  durationMs: number;
  message?: string;
}

/**
 * Result of a scan run - includes both findings AND scanner status.
 * This is critical for reliability: scan failed does not mean no vulnerabilities.
 */
export interface ScanResult {
  findings: Finding[];
  failedScanners: string[];
  completedScanners: string[];
  skippedScanners: string[];
  unavailableScanners: string[];
  scannerStatuses: ScannerStatus[];
  isComplete: boolean;
}

export class Orchestrator {
  private scanners: Scanner[];
  private options: OrchestratorOptions;

  constructor(scanners: Scanner[], options: OrchestratorOptions = {}) {
    this.scanners = scanners;
    this.options = {
      enabledCategories: ["static", "container", "dynamic"],
      requiredCategories: ["static", "container", "dynamic"],
      parallel: false,
      continueOnError: true,
      ...options,
    };
  }

  /**
   * @deprecated Use runWithStatus() instead for proper failure handling.
   */
  async run(ctx: ExecutionContext): Promise<Finding[]> {
    const result = await this.runWithStatus(ctx);
    return result.findings;
  }

  /**
   * Run scanners and return both findings and scanner status.
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
        skippedScanners: [],
        unavailableScanners: [],
        scannerStatuses: [],
        isComplete: true,
      };
    }

    logger.info(`Running ${enabledScanners.length} scanners`);

    const result = this.options.parallel
      ? await this.runParallelWithStatus(enabledScanners, ctx)
      : await this.runSequentialWithStatus(enabledScanners, ctx);

    const normalized = normalizeFindings(result.rawFindings);
    const summary = this.summarizeStatuses(result.statuses);

    logger.info(`Scan complete: ${normalized.length} findings`);

    if (summary.failed.length > 0) {
      logger.warn(`${summary.failed.length} required scanner(s) did not complete: ${summary.failed.join(", ")}`);
    }

    if (summary.skipped.length > 0) {
      logger.warn(`${summary.skipped.length} scanner(s) skipped: ${summary.skipped.join(", ")}`);
    }

    return {
      findings: normalized,
      failedScanners: summary.failed,
      completedScanners: summary.completed,
      skippedScanners: summary.skipped,
      unavailableScanners: summary.unavailable,
      scannerStatuses: result.statuses,
      isComplete: summary.failed.length === 0,
    };
  }

  private async runSequentialWithStatus(
    scanners: Scanner[],
    ctx: ExecutionContext
  ): Promise<{ rawFindings: RawFinding[]; statuses: ScannerStatus[] }> {
    const rawFindings: RawFinding[] = [];
    const statuses: ScannerStatus[] = [];

    for (const scanner of scanners) {
      const startedAt = Date.now();
      const required = this.isRequired(scanner);

      try {
        const results = await scanner.run(ctx);
        rawFindings.push(...results);
        statuses.push(this.completedStatus(scanner, startedAt, required));
      } catch (err) {
        const status = this.statusFromError(scanner, err, startedAt, required);
        statuses.push(status);
        this.logScannerStatus(scanner, status, err);

        if (!this.options.continueOnError && status.status !== "skipped") {
          throw err;
        }
      }
    }

    return { rawFindings, statuses };
  }

  private async runParallelWithStatus(
    scanners: Scanner[],
    ctx: ExecutionContext
  ): Promise<{ rawFindings: RawFinding[]; statuses: ScannerStatus[] }> {
    const startedAt = new Map<Scanner, number>();
    const results = await Promise.allSettled(
      scanners.map((scanner) => {
        startedAt.set(scanner, Date.now());
        return scanner.run(ctx);
      })
    );

    const rawFindings: RawFinding[] = [];
    const statuses: ScannerStatus[] = [];

    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      const scanner = scanners[i];
      const required = this.isRequired(scanner);
      const start = startedAt.get(scanner) ?? Date.now();

      if (result.status === "fulfilled") {
        rawFindings.push(...result.value);
        statuses.push(this.completedStatus(scanner, start, required));
      } else {
        const status = this.statusFromError(scanner, result.reason, start, required);
        statuses.push(status);
        this.logScannerStatus(scanner, status, result.reason);

        if (!this.options.continueOnError && status.status !== "skipped") {
          throw result.reason;
        }
      }
    }

    return { rawFindings, statuses };
  }

  private completedStatus(scanner: Scanner, startedAt: number, required: boolean): ScannerStatus {
    return {
      name: scanner.name,
      category: scanner.category,
      status: "completed",
      required,
      durationMs: Date.now() - startedAt,
    };
  }

  private isRequired(scanner: Scanner): boolean {
    return this.options.requiredCategories?.includes(scanner.category) ?? true;
  }

  private statusFromError(
    scanner: Scanner,
    err: unknown,
    startedAt: number,
    required: boolean
  ): ScannerStatus {
    const message = err instanceof Error ? err.message : String(err);

    if (err instanceof ScannerUnavailableError) {
      return {
        name: scanner.name,
        category: scanner.category,
        status: required ? "unavailable" : "skipped",
        required,
        durationMs: Date.now() - startedAt,
        message,
      };
    }

    return {
      name: scanner.name,
      category: scanner.category,
      status: "failed",
      required,
      durationMs: Date.now() - startedAt,
      message,
    };
  }

  private summarizeStatuses(statuses: ScannerStatus[]): {
    completed: string[];
    failed: string[];
    skipped: string[];
    unavailable: string[];
  } {
    const completed = statuses
      .filter((s) => s.status === "completed")
      .map((s) => s.name);
    const skipped = statuses
      .filter((s) => s.status === "skipped")
      .map((s) => s.name);
    const unavailable = statuses
      .filter((s) => s.status === "unavailable")
      .map((s) => s.name);
    const failed = statuses
      .filter((s) => s.status === "failed" || (s.status === "unavailable" && s.required))
      .map((s) => s.name);

    return { completed, failed, skipped, unavailable };
  }

  private logScannerStatus(scanner: Scanner, status: ScannerStatus, err: unknown): void {
    if (status.status === "skipped") {
      logger.warn(`Scanner ${scanner.name} skipped: ${status.message}`);
      return;
    }

    if (err instanceof ScannerError) {
      logger.error(`Scanner ${scanner.name} failed: ${err.message}`);
    } else {
      logger.error(`Scanner ${scanner.name} failed: ${status.message}`);
    }
  }

  // Keep old methods for backward compatibility.
  private async runSequential(scanners: Scanner[], ctx: ExecutionContext): Promise<RawFinding[]> {
    const result = await this.runSequentialWithStatus(scanners, ctx);
    return result.rawFindings;
  }

  private async runParallel(scanners: Scanner[], ctx: ExecutionContext): Promise<RawFinding[]> {
    const result = await this.runParallelWithStatus(scanners, ctx);
    return result.rawFindings;
  }
}
