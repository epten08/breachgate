import { Finding } from "../findings/finding.js";
import { ReportingConfig } from "../core/config.loader.js";
import { SecurityVerdict } from "../findings/attack.analyzer.js";
import { ScanResult, ScannerStatus } from "../orchestrator/orchestrator.js";
import { PolicyEvaluation } from "../policy/policy.js";

export interface JsonReport {
  metadata: {
    schemaVersion: string;
    generatedAt: string;
    version: string;
    targetUrl: string;
    scanDuration?: number;
  };
  verdict?: {
    status: SecurityVerdict["verdict"];
    reason: string;
    operationalConclusion: string;
    scanIncomplete: boolean;
    failedScanners: string[];
    confirmedExploits: number;
    criticalFindings: number;
  };
  scannerStatus?: {
    completed: string[];
    failed: string[];
    skipped: string[];
    unavailable: string[];
    details: ScannerStatus[];
  };
  policy?: {
    failOn: string;
    warnOn: string;
    profile?: string;
  };
  policyEvaluation?: PolicyEvaluation;
  summary: {
    total: number;
    bySeverity: Record<string, number>;
    byCategory: Record<string, number>;
    deduplicated: number;
  };
  findings: Finding[];
}

export interface JsonReporterOptions {
  targetUrl: string;
  scanDuration?: number;
  includeEvidence?: boolean;
  verdict?: SecurityVerdict;
  scanResult?: ScanResult;
  policy?: {
    failOn: string;
    warnOn: string;
    profile?: string;
  };
  policyEvaluation?: PolicyEvaluation;
}

export class JsonReporter {
  private config: ReportingConfig;

  constructor(config: ReportingConfig) {
    this.config = config;
  }

  generate(findings: Finding[], options: JsonReporterOptions): string {
    const report = this.buildReport(findings, options);
    return JSON.stringify(report, null, 2);
  }

  private buildReport(findings: Finding[], options: JsonReporterOptions): JsonReport {
    const bySeverity: Record<string, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
    };

    const byCategory: Record<string, number> = {};
    let deduplicated = 0;

    for (const finding of findings) {
      bySeverity[finding.severity]++;

      if (!byCategory[finding.category]) {
        byCategory[finding.category] = 0;
      }
      byCategory[finding.category]++;

      if (finding.deduplicated) {
        deduplicated++;
      }
    }

    // Optionally strip evidence for smaller reports
    const reportFindings = this.config.includeEvidence
      ? findings
      : findings.map((f) => ({ ...f, evidence: "[redacted]" }));

    return {
      metadata: {
        schemaVersion: "1.3.0",
        generatedAt: new Date().toISOString(),
        version: "1.0.0",
        targetUrl: options.targetUrl,
        scanDuration: options.scanDuration,
      },
      verdict: options.verdict
        ? {
            status: options.verdict.verdict,
            reason: options.verdict.reason,
            operationalConclusion: options.verdict.operationalConclusion,
            scanIncomplete: options.verdict.scanIncomplete ?? false,
            failedScanners: options.verdict.failedScanners ?? [],
            confirmedExploits: options.verdict.confirmedExploits.length,
            criticalFindings: options.verdict.criticalFindings.length,
          }
        : undefined,
      scannerStatus: options.scanResult
        ? {
            completed: options.scanResult.completedScanners,
            failed: options.scanResult.failedScanners,
            skipped: options.scanResult.skippedScanners,
            unavailable: options.scanResult.unavailableScanners,
            details: options.scanResult.scannerStatuses,
          }
        : undefined,
      policy: options.policy,
      policyEvaluation: options.policyEvaluation,
      summary: {
        total: findings.length,
        bySeverity,
        byCategory,
        deduplicated,
      },
      findings: reportFindings,
    };
  }
}
