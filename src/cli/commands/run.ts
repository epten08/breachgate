import { Command } from "commander";
import { existsSync, readFileSync } from "fs";
import { dirname, isAbsolute, join, resolve } from "path";
import { parse as parseYaml } from "yaml";
import { OpenAPIObject } from "openapi3-ts/oas30";
import { ScanOptions, parseSeverity, parseFormats, parseConfigPaths } from "../options.js";
import { loadConfig, validateConfig, SecurityBotConfig } from "../../core/config.loader.js";
import { ConfigError, SecBotError } from "../../core/errors.js";
import { logger } from "../../core/logger.js";
import { AttackAnalyzer, SecurityVerdict } from "../../findings/attack.analyzer.js";
import { Finding } from "../../findings/finding.js";
import { Orchestrator, ScanResult, ScannerStatus } from "../../orchestrator/orchestrator.js";
import { EnvironmentManager } from "../../orchestrator/environment.manager.js";
import { AuthContext, EnvironmentContext, ExecutionContext } from "../../orchestrator/context.js";
import { TrivyStaticScanner } from "../../scanners/static/trivy.static.js";
import { TrivyImageScanner } from "../../scanners/container/trivy.image.js";
import { ZapApiScanner } from "../../scanners/dynamic/zap.api.js";
import { AIScanner } from "../../scanners/ai/ai.scanner.js";
import { Scanner, ScannerCategory } from "../../scanners/scanner.js";
import { ReportGenerator } from "../../reports/report.generator.js";
import {
  applyBaseline,
  evaluatePolicy,
  loadBaseline,
  PolicyEvaluation,
  resolvePolicyRules,
} from "../../policy/policy.js";
import { resolveAuthContexts } from "../../auth/auth.js";
import {
  enforceTargetSafety,
  shouldRunAiActiveTests,
} from "../../safety/safety.js";
import { sendNotifications } from "../../notifications/notifier.js";

export function createRunCommand(): Command {
  const cmd = new Command("scan")
    .description("Run security scans against the target")
    .option("-c, --config <path>", "Path to config file")
    .option("--configs <paths>", "Comma-separated config files for monorepo/multi-service scans", parseConfigPaths, [])
    .option("--workdir <path>", "Working directory for resolving config, compose, reports, and scanner paths")
    .option("-t, --target <url>", "Target URL (overrides config)")
    .option("-o, --output <dir>", "Output directory for reports")
    .option(
      "-f, --format <formats>",
      "Output formats (comma-separated: markdown,json,sarif)",
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
    .option("--profile <name>", "Policy profile to apply (pull-request, main, release, nightly)")
    .option("--baseline <path>", "Path to baseline/ignore file")
    .option("--differential", "Fail only on findings not covered by the baseline")
    .option("--skip-static", "Skip static analysis")
    .option("--skip-container", "Skip container scanning")
    .option("--skip-dynamic", "Skip dynamic API scanning")
    .option("--skip-ai", "Skip AI-assisted testing")
    .option("--explain-verdict", "Show how each finding's feasibility score was calculated")
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
function outputCiResult(verdict: SecurityVerdict, policyEvaluation?: PolicyEvaluation): void {
  let status: string;

  if (policyEvaluation) {
    status = policyEvaluation.status === "failed" ? "FAILED" : "PASSED";
    if (verdict.verdict === "INCONCLUSIVE" && policyEvaluation.status === "passed") {
      status = "INCONCLUSIVE";
    }
  } else {
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
  }

  console.log(`SECURITY STATUS: ${status}`);
  console.log(`Reason: ${verdict.reason}`);

  if (policyEvaluation) {
    console.log(`Policy: ${policyEvaluation.profile} ${policyEvaluation.status.toUpperCase()}`);
    if (policyEvaluation.suppressedFindings > 0) {
      console.log(`Baseline: ${policyEvaluation.suppressedFindings} finding(s) suppressed`);
    }
    for (const reason of policyEvaluation.reasons) {
      console.log(`Policy reason: ${reason}`);
    }
  }

  // For breaches, also output the operational conclusion
  if (verdict.breaches && verdict.breaches.length > 0) {
    console.log(`Breach: ${verdict.operationalConclusion}`);
  }
}

function printVerdictExplanation(analyzer: AttackAnalyzer, findings: Finding[]): void {
  logger.banner("Verdict Explanation — Attack Feasibility Scoring");
  console.log("Each finding is scored as: Reachability × Exploitability × Impact × Confidence");
  console.log("A score ≥ 0.6 = high risk  |  ≥ 0.3 = review required  |  < 0.3 = low risk");
  console.log("");

  const rows = findings.slice(0, 20).map(f => {
    const v = analyzer.analyzeAttackVector(f);
    const score = (v.feasibilityScore * 100).toFixed(0).padStart(3);
    const reach  = (v.reachability    * 100).toFixed(0).padStart(3);
    const exploit = (v.exploitability * 100).toFixed(0).padStart(3);
    const impact  = (v.impact         * 100).toFixed(0).padStart(3);
    const conf    = (v.confidence     * 100).toFixed(0).padStart(3);
    const confirmed = v.isConfirmed ? " [CONFIRMED]" : "";
    const title = f.title.length > 40 ? f.title.slice(0, 37) + "..." : f.title.padEnd(40);
    return `  ${score}%  ${title}  reach=${reach}% exploit=${exploit}% impact=${impact}% conf=${conf}%${confirmed}`;
  });

  console.log("  Score  Finding                                    Factors");
  console.log("  -----  ----------------------------------------   -------");
  for (const row of rows) {
    console.log(row);
  }
  console.log("");
}

async function runScan(options: ScanOptions): Promise<void> {
  const runs = expandScanRuns(options);
  let exitCode = 0;

  for (const run of runs) {
    if (runs.length > 1) {
      console.log(`SECURITY CONFIG: ${run.label}`);
    }

    const outcome = await withWorkingDirectory(run.workdir, () => runSingleScan(run.options));
    exitCode = combineExitCodes(exitCode, outcome.exitCode);
  }

  process.exit(exitCode);
}

interface ScanOutcome {
  exitCode: number;
}

interface PreparedScanRun {
  options: ScanOptions;
  workdir: string;
  label: string;
}

async function runSingleScan(options: ScanOptions): Promise<ScanOutcome> {
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
    logger.banner("Breach Gate - Scan");
  }

  // Load and validate config
  let config: SecurityBotConfig;
  let openApiSpec: OpenAPIObject | undefined;
  let policy: ReturnType<typeof resolvePolicyRules> | undefined;
  let baselineInfo: ReturnType<typeof loadBaseline> = {};
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
      config.reporting.formats = options.format;
    }
    if (options.failOn) {
      config.thresholds.failOn = options.failOn;
    }

    if (options.profile || options.baseline || options.differential) {
      config.policy = {
        ...config.policy,
        profile: options.profile || config.policy?.profile,
        baselinePath: options.baseline || config.policy?.baselinePath,
        differentialOnly: options.differential || config.policy?.differentialOnly,
      };
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

    applySafetyRunDefaults(config, isCiMode);

    validateConfig(config);
    openApiSpec = loadOpenApiSpec(config);

    const policyRequested = isCiMode || !!config.policy;
    policy = policyRequested
      ? resolvePolicyRules(config.policy, options.profile || (isCiMode ? "main" : undefined), options.differential)
      : undefined;
    baselineInfo = policyRequested
      ? loadBaseline(config.policy?.baselinePath, config.configFilePath)
      : {};
  } catch (err) {
    if (isCiMode) {
      console.log("SECURITY STATUS: INCONCLUSIVE");
      console.log(`Reason: Configuration error: ${(err as Error).message}`);
    } else {
      logger.error(`Configuration error: ${(err as Error).message}`);
      if (err instanceof SecBotError && err.hint) {
        logger.warn(`Hint: ${err.hint}`);
      }
    }
    return { exitCode: 2 };
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
    skippedScanners: [],
    unavailableScanners: [],
    scannerStatuses: [],
    isComplete: false,
    allScannersFailed: false,
  };
  const scanStartTime = Date.now();
  let targetUrlForReports = config.target.baseUrl || config.target.dockerCompose || "unknown";

  try {
    if (!isCiMode) {
      logger.banner("Environment Setup");
    }
    const envInfo = await envManager.setup();
    targetUrlForReports = envInfo.baseUrl;
    enforceTargetSafety(config.safety, envInfo.baseUrl, isCiMode);

    const authContexts = await resolveAuthContexts(config.auth);
    configureAiReplayArtifacts(config, isCiMode, authContexts.length);

    // Create scanners based on config
    const scanners = await createScanners(config);
    const enabledCategories = getEnabledCategories(config);

    // Run orchestrator with status tracking
    if (!isCiMode) {
      logger.banner("Running Scans");
    }
    scanResult = await runConfiguredScans({
      config,
      scanners,
      enabledCategories,
      envInfo,
      openApiSpec,
      authContexts,
      isCiMode,
    });

    // Display CLI summary (skip in CI mode)
    if (!isCiMode) {
      logger.banner("Results");
      const reportGenerator = new ReportGenerator(config.reporting);
      reportGenerator.renderCliSummary(scanResult.findings, {
        verbose: options.verbose,
        showEvidence: config.reporting.includeEvidence,
      });
    }

  } catch (err) {
    if (isCiMode) {
      console.log("SECURITY STATUS: INCONCLUSIVE");
      console.log(`Reason: Scan failed: ${(err as Error).message}`);
    } else {
      logger.error(`Scan failed: ${(err as Error).message}`);
      if (err instanceof SecBotError && err.hint) {
        logger.warn(`Hint: ${err.hint}`);
      }
    }
    return { exitCode: err instanceof ConfigError ? 2 : 1 };
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
  const baselineApplied = applyBaseline(scanResult.findings, baselineInfo.baseline);
  const findingsForVerdict = policy
    ? baselineApplied.effectiveFindings
    : scanResult.findings;

  // Use generateVerdictWithStatus to properly handle scanner failures
  const verdict = attackAnalyzer.generateVerdictWithStatus(findingsForVerdict, {
    isComplete: scanResult.isComplete,
    failedScanners: scanResult.failedScanners,
    allScannersFailed: scanResult.allScannersFailed,
  });
  const policyEvaluation: PolicyEvaluation | undefined = policy
    ? evaluatePolicy({
      allFindings: scanResult.findings,
      effectiveFindings: baselineApplied.effectiveFindings,
      suppressed: baselineApplied.suppressed,
      expired: baselineApplied.expired,
      verdict,
      scanResult,
      profile: policy.profile,
      rules: policy.rules,
      baselinePath: baselineInfo.path,
    })
    : undefined;

  // Determine exit code
  let exitCode = 0;

  if (policyEvaluation) {
    exitCode = policyEvaluation.status === "failed" ? 1 : 0;
    if (!isCiMode) {
      if (policyEvaluation.status === "failed") {
        logger.error(`Policy failed (${policyEvaluation.profile}): ${policyEvaluation.reasons.join("; ")}`);
      } else {
        logger.info(`Policy passed (${policyEvaluation.profile})`);
      }
    }
  } else {
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
  }

  if (options.explainVerdict && !isCiMode && scanResult.findings.length > 0) {
    printVerdictExplanation(attackAnalyzer, scanResult.findings);
  }

  const reports = await generateReports(config, scanResult, verdict, {
    targetUrl: targetUrlForReports,
    scanDuration: Date.now() - scanStartTime,
    stableFilenames: isCiMode,
    isCiMode,
    policyEvaluation,
  });

  // CI mode: output deterministic result plus artifact paths.
  if (isCiMode) {
    outputCiResult(verdict, policyEvaluation);
    for (const report of reports) {
      console.log(`Report: ${report.format} ${report.path}`);
    }
  }

  // Send notifications (non-blocking — failures are logged as warnings)
  await sendNotifications(config.notifications, verdict, scanResult.findings, targetUrlForReports);

  return { exitCode };
}

function expandScanRuns(options: ScanOptions): PreparedScanRun[] {
  const originalCwd = process.cwd();
  const explicitWorkdir = options.workdir
    ? resolve(originalCwd, options.workdir)
    : undefined;
  const configPaths = options.configs && options.configs.length > 0
    ? options.configs
    : options.config
      ? [options.config]
      : [undefined];
  const isMultiConfig = configPaths.length > 1;

  return configPaths.map((configPath, index) => {
    const configBase = explicitWorkdir || originalCwd;
    const config = configPath ? resolve(configBase, configPath) : undefined;
    const workdir = explicitWorkdir || (isMultiConfig && config ? dirname(config) : originalCwd);
    const output = scopeOutputDir(options.output, config, index, isMultiConfig, originalCwd);

    return {
      workdir,
      label: config || "default",
      options: {
        ...options,
        config,
        configs: [],
        output,
      },
    };
  });
}

function scopeOutputDir(
  output: string | undefined,
  configPath: string | undefined,
  index: number,
  isMultiConfig: boolean,
  originalCwd: string
): string | undefined {
  if (!output) {
    return undefined;
  }

  const resolvedOutput = resolve(originalCwd, output);
  if (!isMultiConfig) {
    return resolvedOutput;
  }

  return join(resolvedOutput, configPath ? slugForPath(configPath, originalCwd) : `config-${index + 1}`);
}

function slugForPath(path: string, baseDir: string): string {
  const relative = path.startsWith(baseDir)
    ? path.slice(baseDir.length)
    : path;
  return relative
    .replace(/^[\\/]+/, "")
    .replace(/\.[^.\\/]+$/, "")
    .replace(/[\\/]+/g, "-")
    .replace(/[^a-zA-Z0-9_-]+/g, "-")
    .replace(/^-|-$/g, "")
    || "config";
}

async function withWorkingDirectory<T>(workdir: string, fn: () => Promise<T>): Promise<T> {
  const originalCwd = process.cwd();
  process.chdir(workdir);
  try {
    return await fn();
  } finally {
    process.chdir(originalCwd);
  }
}

function combineExitCodes(current: number, next: number): number {
  if (current === 2 || next === 2) {
    return 2;
  }
  if (current === 1 || next === 1) {
    return 1;
  }
  return 0;
}

async function createScanners(config: SecurityBotConfig): Promise<Scanner[]> {
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
        deterministic: config.scanners.ai.deterministic,
        temperature: config.scanners.ai.temperature,
        maxTokens: config.scanners.ai.maxTokens,
        replayTests: config.scanners.ai.replayTests,
        saveTests: config.scanners.ai.saveTests,
      })
    );
  }

  // Load external plugin scanners
  for (const pluginPath of config.scanners.plugins ?? []) {
    const resolvedPath = resolve(pluginPath);
    const { pathToFileURL } = await import("url");
    const mod = await import(pathToFileURL(resolvedPath).href) as { default?: Scanner; scanner?: Scanner };
    const plugin = mod.default ?? mod.scanner;
    if (!plugin || typeof plugin.run !== "function") {
      throw new ConfigError(`Plugin at ${pluginPath} must export a default Scanner or a 'scanner' named export`);
    }
    scanners.push(plugin);
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

function applySafetyRunDefaults(config: SecurityBotConfig, isCiMode: boolean): void {
  if (!shouldRunAiActiveTests(config.safety)) {
    config.scanners.ai.enabled = false;
  }

  if (isCiMode && config.scanners.ai.enabled) {
    config.scanners.ai.deterministic = config.scanners.ai.deterministic ?? true;
  }
}

function configureAiReplayArtifacts(
  config: SecurityBotConfig,
  isCiMode: boolean,
  authContextCount: number
): void {
  if (!isCiMode || !config.scanners.ai.enabled || config.scanners.ai.replayTests || config.scanners.ai.saveTests) {
    return;
  }

  const filename = authContextCount > 1
    ? "ai-tests-{role}.json"
    : "ai-tests.json";
  config.scanners.ai.saveTests = join(config.reporting.outputDir, filename);
}

interface RunConfiguredScansOptions {
  config: SecurityBotConfig;
  scanners: Scanner[];
  enabledCategories: ScannerCategory[];
  envInfo: EnvironmentContext;
  openApiSpec?: OpenAPIObject;
  authContexts: AuthContext[];
  isCiMode: boolean;
}

async function runConfiguredScans(options: RunConfiguredScansOptions): Promise<ScanResult> {
  const authContexts = options.authContexts.length > 0
    ? options.authContexts
    : [{ type: "none", role: "anonymous" } satisfies AuthContext];

  if (authContexts.length === 1) {
    return runScannerSet({
      ...options,
      enabledCategories: options.enabledCategories,
      auth: authContexts[0],
    });
  }

  const sharedCategories = options.enabledCategories.filter((category) =>
    category === "static" || category === "container"
  );
  const roleCategories = options.enabledCategories.filter((category) =>
    category === "dynamic" || category === "ai"
  );
  const results: ScanResult[] = [];

  if (sharedCategories.length > 0) {
    results.push(await runScannerSet({
      ...options,
      enabledCategories: sharedCategories,
      auth: authContexts[0],
    }));
  }

  for (const auth of authContexts) {
    if (roleCategories.length === 0) {
      continue;
    }

    const roleResult = await runScannerSet({
      ...options,
      enabledCategories: roleCategories,
      auth,
    });
    results.push(labelRoleScanResult(roleResult, auth.role || auth.type));
  }

  return mergeScanResults(results);
}

async function runScannerSet(options: RunConfiguredScansOptions & {
  auth: AuthContext;
}): Promise<ScanResult> {
  const ctx = buildExecutionContext(
    options.config,
    options.envInfo,
    options.auth,
    options.openApiSpec
  );
  const orchestrator = new Orchestrator(options.scanners, {
    enabledCategories: options.enabledCategories,
    requiredCategories: options.isCiMode ? options.enabledCategories : [],
    continueOnError: true,
  });

  return orchestrator.runWithStatus(ctx);
}

function buildExecutionContext(
  config: SecurityBotConfig,
  envInfo: EnvironmentContext,
  auth: AuthContext,
  openApiSpec?: OpenAPIObject
): ExecutionContext {
  return {
    targetUrl: envInfo.baseUrl,
    environment: envInfo,
    auth,
    config: {
      failOnSeverity: config.thresholds.failOn,
      safety: config.safety,
    },
    endpoints: config.target.endpoints,
    openApi: openApiSpec,
  };
}

function labelRoleScanResult(result: ScanResult, role: string): ScanResult {
  const scannerStatuses = result.scannerStatuses.map((status) => ({
    ...status,
    name: `${status.name} [${role}]`,
  }));

  return summarizeScanResult(
    result.findings.map((finding) => ({ ...finding, role: finding.role || role })),
    scannerStatuses
  );
}

function mergeScanResults(results: ScanResult[]): ScanResult {
  const findings = results.flatMap((result) => result.findings);
  const scannerStatuses = results.flatMap((result) => result.scannerStatuses);
  return summarizeScanResult(findings, scannerStatuses);
}

function summarizeScanResult(
  findings: ScanResult["findings"],
  scannerStatuses: ScannerStatus[]
): ScanResult {
  const completedScanners = scannerStatuses
    .filter((status) => status.status === "completed")
    .map((status) => status.name);
  const skippedScanners = scannerStatuses
    .filter((status) => status.status === "skipped")
    .map((status) => status.name);
  const unavailableScanners = scannerStatuses
    .filter((status) => status.status === "unavailable")
    .map((status) => status.name);
  const failedScanners = scannerStatuses
    .filter((status) => status.status === "failed" || (status.status === "unavailable" && status.required))
    .map((status) => status.name);

  const allScannersFailed =
    completedScanners.length === 0 &&
    (failedScanners.length > 0 || unavailableScanners.length > 0 || skippedScanners.length > 0);

  return {
    findings,
    failedScanners,
    completedScanners,
    skippedScanners,
    unavailableScanners,
    scannerStatuses,
    isComplete: failedScanners.length === 0,
    allScannersFailed,
  };
}

interface GenerateReportOptions {
  targetUrl: string;
  scanDuration: number;
  stableFilenames: boolean;
  isCiMode: boolean;
  policyEvaluation?: PolicyEvaluation;
}

async function generateReports(
  config: SecurityBotConfig,
  scanResult: ScanResult,
  verdict: SecurityVerdict,
  options: GenerateReportOptions
) {
  if (config.reporting.formats.length === 0) {
    return [];
  }

  if (!options.isCiMode) {
    logger.banner("Generating Reports");
  }

  const reportGenerator = new ReportGenerator(config.reporting);
  const reports = await reportGenerator.generate(scanResult.findings, {
    targetUrl: options.targetUrl,
    scanDuration: options.scanDuration,
    verdict,
    scanResult,
    policy: {
      failOn: config.thresholds.failOn,
      warnOn: config.thresholds.warnOn,
      profile: options.policyEvaluation?.profile,
    },
    policyEvaluation: options.policyEvaluation,
    stableFilenames: options.stableFilenames,
  });

  if (!options.isCiMode) {
    for (const report of reports) {
      logger.info(`Generated ${report.format} report: ${report.path}`);
    }
  }

  return reports;
}

function loadOpenApiSpec(config: SecurityBotConfig): OpenAPIObject | undefined {
  const specPath = config.target.openApiSpec;
  if (!specPath) {
    return undefined;
  }

  const baseDir = config.configFilePath ? dirname(config.configFilePath) : process.cwd();
  const resolvedPath = isAbsolute(specPath) ? specPath : resolve(baseDir, specPath);

  if (!existsSync(resolvedPath)) {
    throw new ConfigError(`OpenAPI spec not found: ${resolvedPath}`);
  }

  try {
    const content = readFileSync(resolvedPath, "utf-8");
    const parsed = resolvedPath.endsWith(".json")
      ? JSON.parse(content)
      : parseYaml(content);

    if (!parsed || typeof parsed !== "object" || (!parsed.openapi && !parsed.swagger)) {
      throw new Error("missing openapi or swagger version field");
    }

    return parsed as OpenAPIObject;
  } catch (err) {
    if (err instanceof ConfigError) {
      throw err;
    }
    throw new ConfigError(`Failed to load OpenAPI spec ${resolvedPath}: ${(err as Error).message}`);
  }
}

