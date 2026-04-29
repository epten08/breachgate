import { Command } from "commander";
import { loadConfig, validateConfig, SecurityBotConfig } from "../../core/config.loader.js";
import { checkCommand } from "../../core/process.runner.js";
import { logger } from "../../core/logger.js";
import { waitForHealthy } from "../../utils/network.js";

interface DoctorOptions {
  config?: string;
  target?: string;
  ci?: boolean;
}

interface CheckResult {
  name: string;
  status: "ok" | "warn" | "fail";
  message: string;
}

export function createDoctorCommand(): Command {
  return new Command("doctor")
    .description("Check local or CI prerequisites for Breach Gate")
    .option("-c, --config <path>", "Path to config file")
    .option("-t, --target <url>", "Target URL override for health checks")
    .option("--ci", "Fail on missing prerequisites for enabled scanners")
    .action(async (options: DoctorOptions) => {
      await runDoctor(options);
    });
}

async function runDoctor(options: DoctorOptions): Promise<void> {
  if (options.ci) {
    logger.setLevel("error");
  }

  const results: CheckResult[] = [];
  results.push(checkNodeVersion());

  let config: SecurityBotConfig | undefined;

  try {
    config = loadConfig(options.config);
    if (options.target) {
      config.target.baseUrl = options.target;
      config.target.dockerCompose = undefined;
    }
    validateConfig(config);
    results.push({ name: "config", status: "ok", message: "Configuration is valid" });
  } catch (err) {
    results.push({ name: "config", status: "fail", message: (err as Error).message });
    renderResults(results);
    process.exit(2);
  }

  results.push(...(await checkScannerPrerequisites(config, options.ci === true)));
  results.push(await checkTarget(config));

  renderResults(results);

  const hasFailures = results.some((r) => r.status === "fail");
  process.exit(hasFailures ? 1 : 0);
}

function checkNodeVersion(): CheckResult {
  const major = Number.parseInt(process.versions.node.split(".")[0], 10);
  if (major >= 18) {
    return { name: "node", status: "ok", message: `Node.js ${process.version}` };
  }
  return { name: "node", status: "fail", message: `Node.js ${process.version}; expected >=18` };
}

async function checkScannerPrerequisites(
  config: SecurityBotConfig,
  ciMode: boolean
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const hasDocker = await checkCommand("docker");
  const hasTrivy = await checkCommand("trivy");
  const hasZap =
    (await checkCommand("zap.sh")) ||
    (await checkCommand("zap.bat")) ||
    (await checkCommand("zap-cli"));

  if (config.scanners.static.enabled || config.scanners.container.enabled) {
    results.push(
      toolResult(
        "trivy",
        hasTrivy || hasDocker,
        ciMode,
        "Trivy or Docker is required for enabled Trivy scans"
      )
    );
  }

  if (config.scanners.container.enabled || config.target.dockerCompose) {
    results.push(
      toolResult(
        "docker",
        hasDocker,
        ciMode,
        "Docker is required for container scans or Docker Compose targets"
      )
    );
  }

  if (config.scanners.dynamic.enabled) {
    results.push(
      toolResult(
        "zap",
        hasZap || hasDocker,
        ciMode,
        "ZAP CLI/API or Docker is required for dynamic scans"
      )
    );
  }

  if (config.scanners.ai.enabled) {
    const hasAiConfig =
      config.scanners.ai.provider === "ollama" ||
      !!process.env.OPENAI_API_KEY ||
      !!process.env.ANTHROPIC_API_KEY;
    results.push(
      toolResult("ai", hasAiConfig, ciMode, "AI provider configuration is required for AI scans")
    );
  }

  return results;
}

async function checkTarget(config: SecurityBotConfig): Promise<CheckResult> {
  if (!config.target.baseUrl || !config.scanners.dynamic.enabled) {
    return { name: "target", status: "ok", message: "Target health check not required" };
  }

  const healthy = await waitForHealthy({
    url: config.target.baseUrl,
    healthEndpoint: config.target.healthEndpoint,
    timeout: config.target.healthTimeout || 10000,
    maxAttempts: 2,
    interval: 1000,
  });

  if (healthy) {
    return {
      name: "target",
      status: "ok",
      message: `Target reachable at ${config.target.baseUrl}`,
    };
  }

  return {
    name: "target",
    status: "fail",
    message: `Target not reachable at ${config.target.baseUrl}`,
  };
}

function toolResult(name: string, ok: boolean, ciMode: boolean, message: string): CheckResult {
  if (ok) {
    return { name, status: "ok", message };
  }
  return { name, status: ciMode ? "fail" : "warn", message };
}

function renderResults(results: CheckResult[]): void {
  for (const result of results) {
    const label = result.status.toUpperCase().padEnd(4);
    console.log(`${label} ${result.name}: ${result.message}`);
  }
}
