import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { createInterface } from "readline/promises";
import { stdin as input, stdout as output } from "process";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";
import { Command } from "commander";
import { logger } from "../../core/logger.js";

interface InitOptions {
  output?: string;
  force?: boolean;
  baseline?: boolean;
  ciProvider?: "github" | "gitlab" | "azure";
  wizard?: boolean;
}

export function createInitCommand(): Command {
  return new Command("init")
    .description("Create starter Breach Gate configuration files")
    .option("-o, --output <path>", "Path for generated config", "security.config.yml")
    .option("--force", "Overwrite existing generated files")
    .option("--baseline", "Also create .breach-gate-baseline.yml")
    .option("--ci-provider <provider>", "Also create a CI template (github, gitlab, azure)")
    .option("--wizard", "Interactive setup — answer 5 questions to generate a tailored config")
    .action(async (options: InitOptions) => {
      if (options.wizard) {
        await runWizard(options);
      } else {
        runInit(options);
      }
    });
}

async function runWizard(options: InitOptions): Promise<void> {
  const rl = createInterface({ input, output });

  console.log("\nBreachGate Setup Wizard");
  console.log("=======================\n");
  console.log("Answer a few questions to generate a tailored security.config.yml.\n");

  try {
    // 1. Target URL
    const targetUrl = (await rl.question("1. Target URL (e.g. http://localhost:3000): ")).trim() || "http://localhost:3000";

    // 2. Auth type
    const authTypeRaw = (await rl.question("2. Auth type [none/jwt/apikey/session] (default: none): ")).trim().toLowerCase();
    const authType = ["jwt", "apikey", "session"].includes(authTypeRaw) ? authTypeRaw : "none";

    // 3. Which scanners
    const scannersRaw = (await rl.question("3. Enable scanners [static,container,dynamic,ai] (default: static,dynamic): ")).trim();
    const scannerList = scannersRaw
      ? scannersRaw.split(",").map(s => s.trim().toLowerCase())
      : ["static", "dynamic"];
    const enableStatic    = scannerList.includes("static");
    const enableContainer = scannerList.includes("container");
    const enableDynamic   = scannerList.includes("dynamic");
    const enableAi        = scannerList.includes("ai");

    // 4. CI provider
    const ciProviderRaw = (await rl.question("4. CI provider [github/gitlab/azure/none] (default: none): ")).trim().toLowerCase();
    const ciProvider = ["github", "gitlab", "azure"].includes(ciProviderRaw) ? ciProviderRaw as "github" | "gitlab" | "azure" : undefined;

    // 5. Fail threshold
    const failOnRaw = (await rl.question("5. Fail build on severity [LOW/MEDIUM/HIGH/CRITICAL] (default: HIGH): ")).trim().toUpperCase();
    const failOn = ["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(failOnRaw) ? failOnRaw : "HIGH";

    rl.close();

    const authBlock = buildAuthBlock(authType);
    const config = buildWizardConfig(targetUrl, authBlock, enableStatic, enableContainer, enableDynamic, enableAi, failOn);

    const outputPath = options.output || "security.config.yml";
    writeFile(outputPath, config, options.force === true);
    logger.info(`\nCreated ${outputPath}`);

    if (ciProvider) {
      try {
        const created = writeCiTemplate(ciProvider, options.force === true);
        logger.info(`Created ${created}`);
      } catch {
        // CI template write is non-fatal
      }
    }

    console.log("\nNext steps:");
    console.log(`  npx breach-gate scan --config ${outputPath} --ci`);
    console.log("");
  } catch {
    rl.close();
    throw new Error("Wizard cancelled");
  }
}

function buildAuthBlock(authType: string): string {
  switch (authType) {
    case "jwt":
      return `auth:\n  type: jwt\n  token: \${JWT_TOKEN}`;
    case "apikey":
      return `auth:\n  type: apikey\n  apiKey: \${API_KEY}\n  headerName: X-API-Key`;
    case "session":
      return `auth:\n  type: session\n  cookieName: session\n  cookieValue: \${SESSION_COOKIE}`;
    default:
      return `auth:\n  type: none`;
  }
}

function buildWizardConfig(
  targetUrl: string,
  authBlock: string,
  enableStatic: boolean,
  enableContainer: boolean,
  enableDynamic: boolean,
  enableAi: boolean,
  failOn: string
): string {
  return [
    `# yaml-language-server: $schema=./security.config.schema.json`,
    `version: "1.0"`,
    ``,
    `target:`,
    `  baseUrl: ${targetUrl}`,
    `  healthEndpoint: /health`,
    ``,
    authBlock,
    ``,
    `scanners:`,
    `  static:`,
    `    enabled: ${enableStatic}`,
    `  container:`,
    `    enabled: ${enableContainer}`,
    `  dynamic:`,
    `    enabled: ${enableDynamic}`,
    `  ai:`,
    `    enabled: ${enableAi}`,
    ...(enableAi ? [`    provider: ollama`, `    model: llama3:8b`, `    baseUrl: http://localhost:11434`] : []),
    ``,
    `thresholds:`,
    `  failOn: ${failOn}`,
    `  warnOn: MEDIUM`,
    ``,
    `reporting:`,
    `  outputDir: ./security-reports`,
    `  formats:`,
    `    - json`,
    `    - markdown`,
    `  includeEvidence: true`,
    ``,
  ].join("\n");
}

function runInit(options: InitOptions): void {
  const output = options.output || "security.config.yml";
  writeFile(output, CONFIG_TEMPLATE, options.force === true);
  logger.info(`Created ${output}`);

  if (options.baseline) {
    writeFile(".breach-gate-baseline.yml", BASELINE_TEMPLATE, options.force === true);
    logger.info("Created .breach-gate-baseline.yml");
  }

  if (options.ciProvider) {
    const created = writeCiTemplate(options.ciProvider, options.force === true);
    logger.info(`Created ${created}`);
  }
}

function writeCiTemplate(provider: string, force: boolean): string {
  switch (provider) {
    case "github":
      return copyTemplate(
        "docs/ci/templates/github-actions-security.yml",
        ".github/workflows/breach-gate.yml",
        force
      );
    case "gitlab":
      return copyTemplate("docs/ci/templates/gitlab-security.yml", ".gitlab-ci.yml", force);
    case "azure":
      return copyTemplate("docs/ci/templates/azure-pipelines-security.yml", "azure-pipelines-security.yml", force);
    default:
      throw new Error(`Unsupported CI provider: ${provider}. Use github, gitlab, or azure.`);
  }
}

function copyTemplate(source: string, target: string, force: boolean): string {
  const content = readFileSync(resolveTemplatePath(source), "utf-8");
  writeFile(target, content, force);
  return target;
}

function resolveTemplatePath(source: string): string {
  if (existsSync(source)) {
    return source;
  }

  const moduleDir = dirname(fileURLToPath(import.meta.url));
  const packageRoot = resolve(moduleDir, "../../..");
  return resolve(packageRoot, source);
}

function writeFile(path: string, content: string, force: boolean): void {
  if (existsSync(path) && !force) {
    throw new Error(`${path} already exists. Use --force to overwrite.`);
  }

  const dir = dirname(path);
  if (dir && dir !== ".") {
    mkdirSync(dir, { recursive: true });
  }

  writeFileSync(path, content, "utf-8");
}

const CONFIG_TEMPLATE = `version: "1.0"

target:
  baseUrl: http://localhost:3000
  healthEndpoint: /health
  # openApiSpec: ./openapi.yaml

auth:
  type: none
  # type: jwt
  # token: \${JWT_TOKEN}
  # preScan:
  #   command: node
  #   args: ["scripts/get-ci-token.js"]
  #   output: json
  # type: apikey
  # apiKey: \${API_KEY}
  # headerName: X-API-Key
  # roles:
  #   - name: anonymous
  #     type: none
  #   - name: user
  #     type: jwt
  #     token: \${USER_JWT}

scanners:
  static:
    enabled: true
    trivy:
      severityThreshold: MEDIUM
      ignoreUnfixed: false

  container:
    enabled: false
    images: []
    trivy:
      severityThreshold: MEDIUM
      ignoreUnfixed: false

  dynamic:
    enabled: true
    zap:
      apiScanType: api
      maxDuration: 300

  ai:
    enabled: false
    provider: ollama
    model: llama3:8b
    baseUrl: http://localhost:11434
    maxTests: 10
    deterministic: true
    # saveTests: ./security-reports/ai-tests-{role}.json
    # replayTests: ./security-reports/ai-tests-user.json

thresholds:
  failOn: HIGH
  warnOn: MEDIUM

safety:
  profile: safe-active
  allowProductionTargets: false
  allowedHosts:
    - localhost
    - 127.0.0.1
  excludedPaths: []
  maxRequestsPerSecond: 2
  allowDestructiveMethods: false

policy:
  profile: main
  # baselinePath: ./.breach-gate-baseline.yml
  # differentialOnly: true

reporting:
  outputDir: ./security-reports
  formats:
    - json
    - markdown
    - sarif
  includeEvidence: true
`;

const BASELINE_TEMPLATE = `version: "1.0"
findings:
  # Add accepted findings here. Fingerprints are shown in JSON reports as
  # policyEvaluation.effectiveFindingFingerprints or suppressedFindingFingerprints.
  #
  # - fingerprint: "0123456789abcdef"
  #   owner: "team-name"
  #   reason: "Accepted temporarily while legacy endpoint is replaced."
  #   expires: "2026-12-31"
`;

