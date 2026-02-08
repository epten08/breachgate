import { Command } from "commander";
import { ScanOptions, parseSeverity, parseFormats } from "../options";
import { loadConfig, validateConfig, SecurityBotConfig } from "../../core/config.loader";
import { logger } from "../../core/logger";
import { AttackAnalyzer, SecurityVerdict } from "../../findings/attack.analyzer";
import { Orchestrator, ScanResult } from "../../orchestrator/orchestrator";
import { EnvironmentManager } from "../../orchestrator/environment.manager";
import { ExecutionContext } from "../../orchestrator/context";
import { TrivyStaticScanner } from "../../scanners/static/trivy.static";
import { TrivyImageScanner } from "../../scanners/container/trivy.image";
import { ZapApiScanner } from "../../scanners/dynamic/zap.api";
import { AIScanner } from "../../scanners/ai/ai.scanner";
import { Scanner, ScannerCategory } from "../../scanners/scanner";
import { ReportGenerator } from "../../reports/report.generator";

export function createRunCommand(): Command {
  const cmd = new Command("scan")
    .description("Run security scans against the target")
    .option("-c, --config <path>", "Path to config file")
    .option("-t, --target <url>", "Target URL (overrides config)")
    .option("-o, --output <dir>", "Output directory for reports")
    .option(
      "-f, --format <formats>",
      "Output formats (comma-separated: markdown,json)",
      parseFormats,
      []
    )
    .option(
      "--fail-on <severity>",
      "Fail if findings at this severity or above (LOW, MEDIUM, HIGH, CRITICAL)",
      parseSeverity
    )
    .option("-v, --verbose", "Enable verbose output")
    .option("-q, --quiet", "Suppress non-essential output")
    .option("--ci", "CI mode - minimal, deterministic output for pipelines")
    .option("--skip-static", "Skip static analysis")
    .option("--skip-container", "Skip container scanning")
    .option("--skip-dynamic", "Skip dynamic API scanning")
    .option("--skip-ai", "Skip AI-assisted testing")
    .action(async (options: ScanOptions) => {
      await runScan(options);
    });

  return cmd;
}

/**
 * Output deterministic CI result
 * Format:
 *   SECURITY STATUS: PASSED|FAILED|INCONCLUSIVE
 *   Reason: <one-line reason>
 */
function outputCiResult(verdict: SecurityVerdict): void {
  let status: string;

  switch (verdict.verdict) {
    case "SAFE":
      status = "PASSED";
      break;
    case "UNSAFE":
      status = "FAILED";
      break;
    case "REVIEW_REQUIRED":
      status = "PASSED";  // Don't fail CI, but note in reason
      break;
    case "INCONCLUSIVE":
      status = "INCONCLUSIVE";
      break;
  }

  console.log(`SECURITY STATUS: ${status}`);
  console.log(`Reason: ${verdict.reason}`);

  // For breaches, also output the operational conclusion
  if (verdict.breaches && verdict.breaches.length > 0) {
    console.log(`Breach: ${verdict.operationalConclusion}`);
  }
}

async function runScan(options: ScanOptions): Promise<void> {
  const isCiMode = options.ci === true;

  // In CI mode, suppress all logs except final output
  if (isCiMode) {
    logger.setLevel("error");
  } else if (options.verbose) {
    logger.setLevel("debug");
  } else if (options.quiet) {
    logger.setLevel("warn");
  }

  if (!isCiMode) {
    logger.banner("Security Bot - Scan");
  }

  // Load and validate config
  let config: SecurityBotConfig;
  try {
    config = loadConfig(options.config);

    // Apply CLI overrides
    if (options.target) {
      config.target.baseUrl = options.target;
      // Clear dockerCompose when explicit target is provided
      config.target.dockerCompose = undefined;
    }
    if (options.output) {
      config.reporting.outputDir = options.output;
    }
    if (options.format && options.format.length > 0) {
      config.reporting.formats = options.format as ("markdown" | "json")[];
    }
    if (options.failOn) {
      config.thresholds.failOn = options.failOn;
    }

    // Apply skip flags
    if (options.skipStatic) {
      config.scanners.static.enabled = false;
    }
    if (options.skipContainer) {
      config.scanners.container.enabled = false;
    }
    if (options.skipDynamic) {
      config.scanners.dynamic.enabled = false;
    }
    if (options.skipAi) {
      config.scanners.ai.enabled = false;
    }

    validateConfig(config);
  } catch (err) {
    if (isCiMode) {
      console.log("SECURITY STATUS: INCONCLUSIVE");
      console.log(`Reason: Configuration error: ${(err as Error).message}`);
    } else {
      logger.error(`Configuration error: ${(err as Error).message}`);
    }
    process.exit(2);
  }

  if (!isCiMode) {
    logger.info("Configuration loaded", {
      target: config.target.baseUrl || config.target.dockerCompose,
      failOn: config.thresholds.failOn,
    });

    // Log enabled scanners
    const enabledScanners: string[] = [];
    if (config.scanners.static.enabled) enabledScanners.push("static");
    if (config.scanners.container.enabled) enabledScanners.push("container");
    if (config.scanners.dynamic.enabled) enabledScanners.push("dynamic");
    if (config.scanners.ai.enabled) enabledScanners.push("ai");

    logger.info(`Enabled scanners: ${enabledScanners.join(", ") || "none"}`);
  }

  // Setup environment
  const envManager = new EnvironmentManager(config);
  let scanResult: ScanResult = {
    findings: [],
    failedScanners: [],
    completedScanners: [],
    isComplete: false,
  };
  const scanStartTime = Date.now();

  try {
    if (!isCiMode) {
      logger.banner("Environment Setup");
    }
    const envInfo = await envManager.setup();

    // Build execution context
    const ctx: ExecutionContext = {
      targetUrl: envInfo.baseUrl,
      environment: envInfo,
      auth: config.auth ? {
        type: config.auth.type,
        token: config.auth.token,
        apiKey: config.auth.apiKey,
        headerName: config.auth.headerName,
      } : undefined,
      config: {
        failOnSeverity: config.thresholds.failOn,
      },
      endpoints: config.target.endpoints,
    };

    // Create scanners based on config
    const scanners = createScanners(config);
    const enabledCategories = getEnabledCategories(config);

    // Run orchestrator with status tracking
    if (!isCiMode) {
      logger.banner("Running Scans");
    }
    const orchestrator = new Orchestrator(scanners, {
      enabledCategories,
      continueOnError: true,
    });

    // Use runWithStatus to track scanner failures
    scanResult = await orchestrator.runWithStatus(ctx);

    // Display CLI summary (skip in CI mode)
    if (!isCiMode) {
      logger.banner("Results");
      const reportGenerator = new ReportGenerator(config.reporting);
      reportGenerator.renderCliSummary(scanResult.findings, {
        verbose: options.verbose,
        showEvidence: config.reporting.includeEvidence,
      });

      // Generate reports
      if (config.reporting.formats.length > 0) {
        logger.banner("Generating Reports");
        const reports = await reportGenerator.generate(scanResult.findings, {
          targetUrl: ctx.targetUrl,
          scanDuration: Date.now() - scanStartTime,
        });

        for (const report of reports) {
          logger.info(`Generated ${report.format} report: ${report.path}`);
        }
      }
    }

  } catch (err) {
    if (isCiMode) {
      console.log("SECURITY STATUS: INCONCLUSIVE");
      console.log(`Reason: Scan failed: ${(err as Error).message}`);
    } else {
      logger.error(`Scan failed: ${(err as Error).message}`);
    }
    process.exit(1);
  } finally {
    await envManager.teardown();
  }

  // ==========================================================================
  // DETERMINE VERDICT
  // ==========================================================================
  // Key rules:
  // 1. If scanners failed → INCONCLUSIVE (not SAFE)
  // 2. If exploit confirmed → FAIL (automatic, not weighted)
  // 3. Otherwise use attack feasibility analysis

  const attackAnalyzer = new AttackAnalyzer();

  // Use generateVerdictWithStatus to properly handle scanner failures
  const verdict = attackAnalyzer.generateVerdictWithStatus(scanResult.findings, {
    isComplete: scanResult.isComplete,
    failedScanners: scanResult.failedScanners,
  });

  // CI mode: output deterministic result
  if (isCiMode) {
    outputCiResult(verdict);
  }

  // Determine exit code
  let exitCode = 0;

  switch (verdict.verdict) {
    case "UNSAFE":
      if (!isCiMode) {
        logger.error(`Deployment blocked: ${verdict.reason}`);
        if (verdict.confirmedExploits.length > 0) {
          logger.error(`${verdict.confirmedExploits.length} confirmed exploit(s) detected`);
        }
      }
      exitCode = 1;
      break;

    case "INCONCLUSIVE":
      // Scanner failure = cannot determine security status = fail safe
      if (!isCiMode) {
        logger.error(`Scan incomplete: ${verdict.reason}`);
        logger.error("Cannot verify security - failing safely");
      }
      exitCode = 1;
      break;

    case "REVIEW_REQUIRED":
      if (!isCiMode) {
        logger.warn(`Review required: ${verdict.reason}`);
      }
      exitCode = 0; // Don't fail CI, but warn
      break;

    case "SAFE":
      if (!isCiMode) {
        logger.info("Security analysis complete - safe to deploy");
      }
      exitCode = 0;
      break;
  }

  process.exit(exitCode);
}

function createScanners(config: SecurityBotConfig): Scanner[] {
  const scanners: Scanner[] = [
    new TrivyStaticScanner(),
    new TrivyImageScanner(),
    new ZapApiScanner(),
  ];

  // Add AI scanner if configured
  if (config.scanners.ai.enabled && config.scanners.ai.provider) {
    scanners.push(
      new AIScanner({
        provider: config.scanners.ai.provider,
        model: config.scanners.ai.model || "llama3",
        baseUrl: config.scanners.ai.baseUrl,
        maxTests: config.scanners.ai.maxTests,
      })
    );
  }

  return scanners;
}

function getEnabledCategories(config: SecurityBotConfig): ScannerCategory[] {
  const categories: ScannerCategory[] = [];
  if (config.scanners.static.enabled) categories.push("static");
  if (config.scanners.container.enabled) categories.push("container");
  if (config.scanners.dynamic.enabled) categories.push("dynamic");
  if (config.scanners.ai.enabled) categories.push("ai");
  return categories;
}
