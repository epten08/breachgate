import { Command } from "commander";
import { loadConfig, validateConfig } from "../../core/config.loader.js";
import { logger } from "../../core/logger.js";
import { AttackAnalyzer } from "../../findings/attack.analyzer.js";
import { Finding } from "../../findings/finding.js";
import type { Scanner } from "../../scanners/scanner.js";

export function createWatchCommand(): Command {
  return new Command("watch")
    .description("Continuously scan the target and report new or resolved findings")
    .option("-c, --config <path>", "Path to config file")
    .option("-i, --interval <seconds>", "Seconds between scans", "60")
    .option("-v, --verbose", "Enable verbose output")
    .action(async (options: { config?: string; interval: string; verbose?: boolean }) => {
      await runWatch(options);
    });
}

async function runWatch(options: {
  config?: string;
  interval: string;
  verbose?: boolean;
}): Promise<void> {
  const intervalMs = Math.max(10, parseInt(options.interval, 10)) * 1000;

  let config;
  try {
    config = loadConfig(options.config);
    validateConfig(config);
  } catch (err) {
    logger.error(`Configuration error: ${(err as Error).message}`);
    process.exit(2);
  }

  logger.banner("Breach Gate - Watch Mode");
  logger.info(`Target: ${config.target.baseUrl}`);
  logger.info(`Interval: ${intervalMs / 1000}s — press Ctrl+C to stop`);

  let previousFindings: Finding[] = [];
  let scanCount = 0;

  const runScan = async (): Promise<void> => {
    scanCount++;
    logger.info(`[Scan #${scanCount}] Starting…`);

    // Dynamically import to avoid circular deps at module load time.
    const { Orchestrator } = await import("../../orchestrator/orchestrator.js");
    const { EnvironmentManager } = await import("../../orchestrator/environment.manager.js");
    const { TrivyStaticScanner } = await import("../../scanners/static/trivy.static.js");
    const { TrivyImageScanner } = await import("../../scanners/container/trivy.image.js");
    const { ZapApiScanner } = await import("../../scanners/dynamic/zap.api.js");
    const { AIScanner } = await import("../../scanners/ai/ai.scanner.js");
    const { resolveAuthContexts } = await import("../../auth/auth.js");
    const { enforceTargetSafety } = await import("../../safety/safety.js");

    const envManager = new EnvironmentManager(config);
    try {
      const envInfo = await envManager.setup();
      enforceTargetSafety(config.safety, envInfo.baseUrl, false);

      const authContexts = await resolveAuthContexts(config.auth);
      const auth = authContexts[0] ?? { type: "none", role: "anonymous" };

      const scanners: Scanner[] = [
        new TrivyStaticScanner(),
        new TrivyImageScanner(),
        new ZapApiScanner(),
      ];
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

      const ctx = {
        targetUrl: envInfo.baseUrl,
        environment: envInfo,
        auth,
        config: { failOnSeverity: config.thresholds.failOn, safety: config.safety },
        endpoints: config.target.endpoints,
      };

      const orchestrator = new Orchestrator(scanners, { continueOnError: true });
      const result = await orchestrator.runWithStatus(ctx);
      const current = result.findings;

      // Diff against previous scan
      const prevIds = new Set(previousFindings.map((f) => f.id));
      const currIds = new Set(current.map((f) => f.id));

      const newFindings = current.filter((f) => !prevIds.has(f.id));
      const resolvedFindings = previousFindings.filter((f) => !currIds.has(f.id));

      if (newFindings.length > 0) {
        logger.warn(`[Scan #${scanCount}] ${newFindings.length} NEW finding(s):`);
        for (const f of newFindings) {
          logger.warn(`  [${f.severity}] ${f.title}`);
        }
      } else {
        logger.info(`[Scan #${scanCount}] No new findings.`);
      }

      if (resolvedFindings.length > 0) {
        logger.info(`[Scan #${scanCount}] ${resolvedFindings.length} resolved finding(s):`);
        for (const f of resolvedFindings) {
          logger.info(`  [RESOLVED] ${f.title}`);
        }
      }

      const analyzer = new AttackAnalyzer();
      const verdict = analyzer.generateVerdict(current);
      logger.info(`[Scan #${scanCount}] Verdict: ${verdict.verdict} — ${verdict.reason}`);

      previousFindings = current;
    } catch (err) {
      logger.error(`[Scan #${scanCount}] Scan failed: ${(err as Error).message}`);
    } finally {
      await envManager.teardown();
    }
  };

  // Run immediately, then on interval.
  await runScan();

  const timer = setInterval(async () => {
    await runScan();
  }, intervalMs);

  // Clean exit on Ctrl+C.
  process.on("SIGINT", () => {
    clearInterval(timer);
    logger.info("Watch mode stopped.");
    process.exit(0);
  });
}
