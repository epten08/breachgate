import chalk from "chalk";
import { Finding, Severity } from "../findings/finding.js";
import { sortByRisk } from "../findings/normalizer.js";
import { RiskEngine } from "../findings/risk.engine.js";
import { AttackAnalyzer, SecurityVerdict } from "../findings/attack.analyzer.js";

export interface CliSummaryOptions {
  maxFindings?: number;
  showEvidence?: boolean;
  verbose?: boolean;
}

export class CliSummary {
  private options: Required<CliSummaryOptions>;
  private riskEngine: RiskEngine;
  private attackAnalyzer: AttackAnalyzer;

  constructor(options: CliSummaryOptions = {}) {
    this.options = {
      maxFindings: 10,
      showEvidence: false,
      verbose: false,
      ...options,
    };
    this.riskEngine = new RiskEngine();
    this.attackAnalyzer = new AttackAnalyzer();
  }

  render(findings: Finding[]): void {
    console.log();

    // Generate security verdict first
    const verdict = this.attackAnalyzer.generateVerdict(findings);

    this.renderHeader(findings);
    this.renderSecurityVerdict(verdict);
    this.renderSeverityBreakdown(findings);

    if (findings.length > 0) {
      // Show endpoint correlation in verbose mode
      if (this.options.verbose) {
        this.renderEndpointCorrelation(findings);
      }

      this.renderTopFindings(findings);

      if (this.options.verbose) {
        this.renderAttackChains(verdict);
        this.renderContextualRemediations(verdict);
        this.renderSourceBreakdown(findings);
      }
    }

    this.renderConclusion(verdict);
    console.log();
  }

  private renderHeader(findings: Finding[]): void {
    const total = findings.length;
    const critical = findings.filter((f) => f.severity === "CRITICAL").length;
    const high = findings.filter((f) => f.severity === "HIGH").length;

    console.log(chalk.bold("═".repeat(60)));
    console.log(chalk.bold.white("                    SCAN RESULTS"));
    console.log(chalk.bold("═".repeat(60)));
    console.log();

    if (total === 0) {
      console.log(chalk.green.bold("  ✓ No vulnerabilities found!"));
    } else {
      console.log(chalk.white(`  Total Findings: ${chalk.bold(total)}`));

      if (critical > 0) {
        console.log(
          chalk.red.bold(`  ⚠ ${critical} CRITICAL vulnerabilities require immediate attention`)
        );
      }
      if (high > 0) {
        console.log(chalk.yellow(`  ⚠ ${high} HIGH severity issues should be addressed promptly`));
      }
    }

    console.log();
  }

  private renderSeverityBreakdown(findings: Finding[]): void {
    const counts: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
    };

    for (const finding of findings) {
      counts[finding.severity]++;
    }

    console.log(chalk.bold("  Severity Breakdown:"));
    console.log();

    const maxCount = Math.max(...Object.values(counts), 1);
    const barWidth = 30;

    for (const severity of ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as Severity[]) {
      const count = counts[severity];
      const bar = this.renderBar(count, maxCount, barWidth);
      const color = this.getSeverityColor(severity);
      const label = severity.padEnd(8);

      console.log(`  ${color(label)} ${bar} ${count}`);
    }

    console.log();
  }

  private renderBar(value: number, max: number, width: number): string {
    if (max === 0) return chalk.gray("░".repeat(width));

    const filled = Math.round((value / max) * width);
    const empty = width - filled;

    return chalk.green("█".repeat(filled)) + chalk.gray("░".repeat(empty));
  }

  private renderTopFindings(findings: Finding[]): void {
    const sorted = sortByRisk(findings);
    const top = sorted.slice(0, this.options.maxFindings);

    console.log(chalk.bold("  Top Findings:"));
    console.log();

    for (let i = 0; i < top.length; i++) {
      const finding = top[i];
      const severity = this.getSeverityBadge(finding.severity);
      const title = this.truncate(finding.title, 50);
      const isAI = finding.sources.includes("AI Security Tester");
      const aiIndicator = isAI ? chalk.cyan(" [AI]") : "";

      console.log(`  ${chalk.gray(`${i + 1}.`)} ${severity} ${title}${aiIndicator}`);

      if (this.options.verbose) {
        console.log(chalk.gray(`     Category: ${finding.category}`));
        console.log(
          chalk.gray(
            `     Risk: ${finding.riskScore.toFixed(2)} | Confidence: ${finding.confidence.toFixed(2)} | Sources: ${finding.sources.join(", ")}`
          )
        );

        if (finding.cve) {
          console.log(chalk.gray(`     CVE: ${finding.cve}`));
        }

        // Show endpoint context if available
        if (finding.endpointContext) {
          const ctx = finding.endpointContext;
          const flags: string[] = [];
          if (ctx.acceptsUserInput) flags.push("user-input");
          if (ctx.handlesData) flags.push("sensitive-data");
          if (!ctx.requiresAuth) flags.push("no-auth");
          if (flags.length > 0) {
            console.log(chalk.gray(`     Endpoint Risk: ${flags.join(", ")}`));
          }
        }

        if (this.options.showEvidence && finding.evidence) {
          const evidence = this.truncate(finding.evidence, 80);
          console.log(chalk.gray(`     Evidence: ${evidence}`));
        }

        // Show remediation action
        const remediation = this.riskEngine.getRemediation(finding);
        console.log(chalk.cyan(`     Fix: ${remediation.action}`));

        console.log();
      }
    }

    if (findings.length > this.options.maxFindings) {
      console.log(
        chalk.gray(`  ... and ${findings.length - this.options.maxFindings} more findings`)
      );
    }

    console.log();
  }

  private renderCategoryBreakdown(findings: Finding[]): void {
    const byCategory: Record<string, number> = {};

    for (const finding of findings) {
      byCategory[finding.category] = (byCategory[finding.category] || 0) + 1;
    }

    const sorted = Object.entries(byCategory)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

    console.log(chalk.bold("  Top Categories:"));
    console.log();

    for (const [category, count] of sorted) {
      console.log(`  ${chalk.gray("•")} ${category}: ${count}`);
    }

    console.log();
  }

  private renderSourceBreakdown(findings: Finding[]): void {
    const bySource: Record<string, number> = {};

    for (const finding of findings) {
      for (const source of finding.sources) {
        bySource[source] = (bySource[source] || 0) + 1;
      }
    }

    console.log(chalk.bold("  Findings by Source:"));
    console.log();

    for (const [source, count] of Object.entries(bySource)) {
      console.log(`  ${chalk.gray("•")} ${source}: ${count}`);
    }

    console.log();
  }

  private renderSecurityVerdict(verdict: SecurityVerdict): void {
    console.log(chalk.bold("  SECURITY VERDICT:"));
    console.log();

    switch (verdict.verdict) {
      case "UNSAFE":
        console.log(
          chalk.bgRed.white.bold("  ╔════════════════════════════════════════════════════════╗")
        );
        console.log(
          chalk.bgRed.white.bold("  ║            ⛔  UNSAFE TO DEPLOY  ⛔                    ║")
        );
        console.log(
          chalk.bgRed.white.bold("  ╚════════════════════════════════════════════════════════╝")
        );
        break;
      case "REVIEW_REQUIRED":
        console.log(
          chalk.bgYellow.black.bold("  ╔════════════════════════════════════════════════════════╗")
        );
        console.log(
          chalk.bgYellow.black.bold("  ║           ⚠️  REVIEW REQUIRED  ⚠️                      ║")
        );
        console.log(
          chalk.bgYellow.black.bold("  ╚════════════════════════════════════════════════════════╝")
        );
        break;
      case "INCONCLUSIVE":
        console.log(
          chalk.bgMagenta.white.bold("  ╔════════════════════════════════════════════════════════╗")
        );
        console.log(
          chalk.bgMagenta.white.bold("  ║           ❓  SCAN INCOMPLETE  ❓                      ║")
        );
        console.log(
          chalk.bgMagenta.white.bold("  ╚════════════════════════════════════════════════════════╝")
        );
        break;
      case "SAFE":
        console.log(
          chalk.bgGreen.white.bold("  ╔════════════════════════════════════════════════════════╗")
        );
        console.log(
          chalk.bgGreen.white.bold("  ║            ✅  SAFE TO DEPLOY  ✅                      ║")
        );
        console.log(
          chalk.bgGreen.white.bold("  ╚════════════════════════════════════════════════════════╝")
        );
        break;
    }

    console.log();

    // Show operational conclusion prominently for breaches
    if (verdict.breaches && verdict.breaches.length > 0) {
      console.log(chalk.red.bold(`  BREACH CONFIRMED: ${verdict.operationalConclusion}`));
      console.log();
      console.log(chalk.red(`  Attacker Capabilities:`));
      for (const breach of verdict.breaches.slice(0, 5)) {
        console.log(chalk.red(`     • ${breach.capability}`));
      }
      console.log();
    } else {
      console.log(`  ${chalk.white("Assessment:")} ${verdict.reason}`);
      console.log();
    }
  }

  private renderEndpointCorrelation(findings: Finding[]): void {
    const correlations = this.attackAnalyzer.correlateByEndpoint(findings);
    const topEndpoints = correlations.slice(0, 5);

    if (topEndpoints.length === 0) return;

    console.log(chalk.bold("  Attack Surface (by endpoint):"));
    console.log();

    for (const corr of topEndpoints) {
      const riskColor =
        corr.combinedRisk >= 0.7 ? chalk.red : corr.combinedRisk >= 0.5 ? chalk.yellow : chalk.blue;
      const riskBar = this.renderRiskBar(corr.combinedRisk);

      console.log(`  ${riskColor(corr.endpoint || "no-endpoint")}`);
      console.log(`     Risk: ${riskBar} ${(corr.combinedRisk * 100).toFixed(0)}%`);

      // List findings for this endpoint
      const findingTypes = [...new Set(corr.findings.map((f) => f.category))];
      console.log(chalk.gray(`     ├── ${findingTypes.join(", ")}`));

      // Show attack chains if any
      if (corr.attackChains.length > 0) {
        const chain = corr.attackChains[0];
        console.log(chalk.yellow(`     └── Attack chain: ${chain.name}`));
      }

      console.log();
    }
  }

  private renderRiskBar(risk: number): string {
    const width = 20;
    const filled = Math.round(risk * width);
    const empty = width - filled;

    const color =
      risk >= 0.7 ? chalk.red : risk >= 0.5 ? chalk.yellow : risk >= 0.3 ? chalk.blue : chalk.green;

    return color("█".repeat(filled)) + chalk.gray("░".repeat(empty));
  }

  private renderAttackChains(verdict: SecurityVerdict): void {
    if (verdict.attackChains.length === 0) return;

    // Deduplicate chains by name
    const uniqueChains = new Map<string, (typeof verdict.attackChains)[0]>();
    for (const chain of verdict.attackChains) {
      if (!uniqueChains.has(chain.name)) {
        uniqueChains.set(chain.name, chain);
      }
    }

    console.log(chalk.bold("  Potential Attack Chains:"));
    console.log();

    for (const chain of uniqueChains.values()) {
      const impactColor =
        chain.impact === "critical"
          ? chalk.red
          : chain.impact === "high"
            ? chalk.yellow
            : chalk.blue;

      console.log(`  ${impactColor("→")} ${chain.name}`);
      console.log(chalk.gray(`     Likelihood: ${chain.likelihood} | Impact: ${chain.impact}`));

      for (let i = 0; i < chain.steps.length; i++) {
        const prefix = i === chain.steps.length - 1 ? "└──" : "├──";
        console.log(chalk.gray(`     ${prefix} ${i + 1}. ${chain.steps[i]}`));
      }

      console.log();
    }
  }

  private renderContextualRemediations(verdict: SecurityVerdict): void {
    const remediations = verdict.recommendations.slice(0, 5);
    if (remediations.length === 0) return;

    console.log(chalk.bold("  Recommended Fixes:"));
    console.log();

    for (const rem of remediations) {
      const priorityColor =
        rem.priority === "immediate"
          ? chalk.red
          : rem.priority === "high"
            ? chalk.yellow
            : chalk.blue;
      const priorityIcon =
        rem.priority === "immediate"
          ? "🚨"
          : rem.priority === "high"
            ? "⚠️"
            : rem.priority === "medium"
              ? "📋"
              : "📝";

      console.log(`  ${priorityIcon} ${priorityColor(rem.finding.category)}`);
      console.log(chalk.gray(`     Endpoint: ${rem.endpoint}`));
      console.log(chalk.cyan(`     Fix: ${rem.specificFix}`));

      if (rem.codeExample && this.options.verbose) {
        console.log(chalk.gray("     Example:"));
        const lines = rem.codeExample.split("\n").slice(0, 3);
        for (const line of lines) {
          console.log(chalk.gray(`       ${line}`));
        }
      }

      console.log();
    }
  }

  private renderConclusion(verdict: SecurityVerdict): void {
    console.log(chalk.bold("═".repeat(60)));

    switch (verdict.verdict) {
      case "UNSAFE":
        console.log(chalk.red.bold("  DEPLOYMENT BLOCKED"));
        if (verdict.breaches && verdict.breaches.length > 0) {
          console.log(chalk.red(`  ${verdict.operationalConclusion}`));
        } else {
          console.log(chalk.red(`  Critical vulnerabilities require remediation.`));
        }
        break;
      case "INCONCLUSIVE":
        console.log(chalk.magenta.bold("  SCAN INCOMPLETE"));
        console.log(chalk.magenta(`  ${verdict.reason}`));
        console.log(chalk.magenta("  Cannot verify security - failing safely."));
        break;
      case "REVIEW_REQUIRED":
        console.log(chalk.yellow.bold("  DEPLOYMENT REQUIRES REVIEW"));
        console.log(
          chalk.yellow(
            `  ${verdict.criticalFindings.length} exploitable finding(s) need security review.`
          )
        );
        break;
      case "SAFE":
        console.log(chalk.green.bold("  DEPLOYMENT APPROVED"));
        console.log(chalk.green("  No exploitable vulnerabilities detected."));
        break;
    }

    console.log(chalk.bold("═".repeat(60)));
  }

  private getSeverityColor(severity: Severity): (text: string) => string {
    switch (severity) {
      case "CRITICAL":
        return chalk.red.bold;
      case "HIGH":
        return chalk.yellow;
      case "MEDIUM":
        return chalk.blue;
      case "LOW":
        return chalk.gray;
    }
  }

  private getSeverityBadge(severity: Severity): string {
    switch (severity) {
      case "CRITICAL":
        return chalk.bgRed.white.bold(" CRIT ");
      case "HIGH":
        return chalk.bgYellow.black(" HIGH ");
      case "MEDIUM":
        return chalk.bgBlue.white(" MED  ");
      case "LOW":
        return chalk.bgGray.white(" LOW  ");
    }
  }

  private truncate(text: string, maxLength: number): string {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength - 3) + "...";
  }
}
