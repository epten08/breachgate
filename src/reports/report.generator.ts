import { writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";
import { Finding } from "../findings/finding.js";
import { ReportFormat, ReportingConfig } from "../core/config.loader.js";
import { SecurityVerdict } from "../findings/attack.analyzer.js";
import { ScanResult } from "../orchestrator/orchestrator.js";
import { PolicyEvaluation } from "../policy/policy.js";
import { JsonReporter } from "./json.reporter.js";
import { MarkdownReporter } from "./markdown.reporter.js";
import { SarifReporter } from "./sarif.reporter.js";
import { HtmlReporter } from "./html.reporter.js";
import { CliSummary, CliSummaryOptions } from "./cli.summary.js";
import { logger } from "../core/logger.js";

export interface ReportOptions {
  targetUrl: string;
  scanDuration?: number;
  timestamp?: Date;
  verdict?: SecurityVerdict;
  scanResult?: ScanResult;
  policy?: {
    failOn: string;
    warnOn: string;
    profile?: string;
  };
  policyEvaluation?: PolicyEvaluation;
  stableFilenames?: boolean;
}

export interface GeneratedReport {
  format: string;
  path: string;
}

export class ReportGenerator {
  private config: ReportingConfig;
  private jsonReporter: JsonReporter;
  private markdownReporter: MarkdownReporter;
  private sarifReporter: SarifReporter;
  private htmlReporter: HtmlReporter;

  constructor(config: ReportingConfig) {
    this.config = config;
    this.jsonReporter = new JsonReporter(config);
    this.markdownReporter = new MarkdownReporter(config);
    this.sarifReporter = new SarifReporter();
    this.htmlReporter = new HtmlReporter(config);
  }

  async generate(findings: Finding[], options: ReportOptions): Promise<GeneratedReport[]> {
    const reports: GeneratedReport[] = [];
    const timestamp = options.timestamp || new Date();
    const dateStr = this.formatDate(timestamp);

    // Ensure output directory exists
    this.ensureOutputDir();

    for (const format of this.config.formats) {
      try {
        const report = this.generateReport(findings, format, options);
        const filename = this.getFilename(format, dateStr, options.stableFilenames);
        const filepath = join(this.config.outputDir, filename);

        writeFileSync(filepath, report, "utf-8");

        reports.push({ format, path: filepath });
      } catch (err) {
        logger.error(`Failed to generate ${format} report: ${(err as Error).message}`);
      }
    }

    return reports;
  }

  generateReport(
    findings: Finding[],
    format: ReportFormat,
    options: ReportOptions
  ): string {
    switch (format) {
      case "json":
        return this.jsonReporter.generate(findings, {
          targetUrl: options.targetUrl,
          scanDuration: options.scanDuration,
          includeEvidence: this.config.includeEvidence,
          verdict: options.verdict,
          scanResult: options.scanResult,
          policy: options.policy,
          policyEvaluation: options.policyEvaluation,
        });

      case "markdown":
        return this.markdownReporter.generate(findings, {
          targetUrl: options.targetUrl,
          scanDuration: options.scanDuration,
          verdict: options.verdict,
        });

      case "sarif":
        return this.sarifReporter.generate(findings, {
          targetUrl: options.targetUrl,
          verdict: options.verdict,
          policyEvaluation: options.policyEvaluation,
        });

      case "html":
        return this.htmlReporter.generate(findings, {
          targetUrl: options.targetUrl,
          scanDuration: options.scanDuration,
          verdict: options.verdict,
        });

      default:
        throw new Error(`Unsupported report format: ${format}`);
    }
  }

  renderCliSummary(findings: Finding[], options?: CliSummaryOptions): void {
    const summary = new CliSummary(options);
    summary.render(findings);
  }

  private ensureOutputDir(): void {
    if (!existsSync(this.config.outputDir)) {
      mkdirSync(this.config.outputDir, { recursive: true });
      logger.debug(`Created output directory: ${this.config.outputDir}`);
    }
  }

  private getFilename(format: ReportFormat, dateStr: string, stable = false): string {
    const ext: Record<ReportFormat, string> = { markdown: "md", json: "json", sarif: "sarif", html: "html" };
    const extension = ext[format] ?? format;
    if (stable) {
      return `security-report.${extension}`;
    }
    return `security-report-${dateStr}.${extension}`;
  }

  private formatDate(date: Date): string {
    return date.toISOString().split("T")[0];
  }
}
