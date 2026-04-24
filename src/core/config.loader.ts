import { readFileSync, existsSync } from "fs";
import { resolve } from "path";
import { parse } from "yaml";
import { ConfigError } from "./errors.js";
import { logger } from "./logger.js";
import { Severity } from "../findings/finding.js";
import { PolicyConfig } from "../policy/policy.js";

export interface EndpointConfig {
  path: string;
  method?: string;
  description?: string;
  params?: Record<string, string>;
  body?: Record<string, unknown>;
}

export interface TargetConfig {
  dockerCompose?: string;
  baseUrl?: string;
  openApiSpec?: string;
  healthEndpoint?: string;
  healthTimeout?: number;
  endpoints?: EndpointConfig[];
}

export interface AuthConfig {
  type: "jwt" | "apikey" | "session" | "none";
  role?: string;
  token?: string;
  apiKey?: string;
  headerName?: string;
  cookieName?: string;
  cookieValue?: string;
  headers?: Record<string, string>;
  preScan?: AuthHookConfig;
  roles?: AuthRoleConfig[];
}

export interface AuthRoleConfig {
  name: string;
  type?: "jwt" | "apikey" | "session" | "none";
  token?: string;
  apiKey?: string;
  headerName?: string;
  cookieName?: string;
  cookieValue?: string;
  headers?: Record<string, string>;
  preScan?: AuthHookConfig;
}

export interface AuthHookConfig {
  command: string;
  args?: string[];
  output?: "raw" | "json";
  tokenField?: string;
  apiKeyField?: string;
  cookieField?: string;
  headersField?: string;
  timeout?: number;
}

export type SafetyProfile = "passive" | "safe-active" | "full-active";

export interface SafetyConfig {
  profile?: SafetyProfile;
  allowProductionTargets?: boolean;
  allowedHosts?: string[];
  excludedPaths?: string[];
  maxRequestsPerSecond?: number;
  allowDestructiveMethods?: boolean;
}

export interface ScannersConfig {
  static: {
    enabled: boolean;
    trivy?: {
      severityThreshold?: Severity;
      ignoreUnfixed?: boolean;
    };
  };
  container: {
    enabled: boolean;
    images?: string[];
    trivy?: {
      severityThreshold?: Severity;
      ignoreUnfixed?: boolean;
    };
  };
  dynamic: {
    enabled: boolean;
    zap?: {
      apiScanType?: "api" | "full";
      maxDuration?: number;
    };
  };
  ai: {
    enabled: boolean;
    provider?: "ollama" | "openai" | "anthropic";
    model?: string;
    baseUrl?: string;
    maxTests?: number;
    deterministic?: boolean;
    temperature?: number;
    maxTokens?: number;
    replayTests?: string;
    saveTests?: string;
  };
}

export type ReportFormat = "markdown" | "json" | "sarif";

export interface ReportingConfig {
  outputDir: string;
  formats: ReportFormat[];
  includeEvidence: boolean;
}

export interface SecurityBotConfig {
  version: string;
  configFilePath?: string;
  target: TargetConfig;
  auth?: AuthConfig;
  scanners: ScannersConfig;
  thresholds: {
    failOn: Severity;
    warnOn: Severity;
  };
  safety?: SafetyConfig;
  policy?: PolicyConfig;
  reporting: ReportingConfig;
}

const DEFAULT_CONFIG: SecurityBotConfig = {
  version: "1.0",
  target: {},
  scanners: {
    static: { enabled: true },
    container: { enabled: true },
    dynamic: { enabled: true },
    ai: { enabled: false },
  },
  thresholds: {
    failOn: "HIGH",
    warnOn: "MEDIUM",
  },
  safety: {
    profile: "safe-active",
    allowProductionTargets: false,
    allowedHosts: [],
    excludedPaths: [],
    maxRequestsPerSecond: 2,
    allowDestructiveMethods: false,
  },
  reporting: {
    outputDir: "./security-reports",
    formats: ["markdown", "json"],
    includeEvidence: true,
  },
};

export function loadConfig(configPath?: string): SecurityBotConfig {
  const path = configPath || findConfigFile();

  if (!path) {
    logger.warn("No config file found, using defaults");
    return DEFAULT_CONFIG;
  }

  logger.info(`Loading config from ${path}`);

  try {
    const content = readFileSync(path, "utf-8");
    const parsed = interpolateEnvValues(parse(content)) as Partial<SecurityBotConfig>;
    return {
      ...mergeConfig(DEFAULT_CONFIG, parsed),
      configFilePath: resolve(path),
    };
  } catch (err) {
    if (err instanceof ConfigError) {
      throw err;
    }
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new ConfigError(`Config file not found: ${path}`);
    }
    throw new ConfigError(`Failed to parse config: ${(err as Error).message}`, err as Error);
  }
}

function findConfigFile(): string | null {
  const candidates = [
    "security.config.yml",
    "security.config.yaml",
    ".security.yml",
    ".security.yaml",
  ];

  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

function mergeConfig(
  defaults: SecurityBotConfig,
  overrides: Partial<SecurityBotConfig>
): SecurityBotConfig {
  return {
    version: overrides.version ?? defaults.version,
    configFilePath: overrides.configFilePath ?? defaults.configFilePath,
    target: { ...defaults.target, ...overrides.target },
    auth: overrides.auth ?? defaults.auth,
    scanners: {
      static: { ...defaults.scanners.static, ...overrides.scanners?.static },
      container: { ...defaults.scanners.container, ...overrides.scanners?.container },
      dynamic: { ...defaults.scanners.dynamic, ...overrides.scanners?.dynamic },
      ai: { ...defaults.scanners.ai, ...overrides.scanners?.ai },
    },
    thresholds: { ...defaults.thresholds, ...overrides.thresholds },
    safety: { ...defaults.safety, ...overrides.safety },
    policy: overrides.policy ? {
      ...defaults.policy,
      ...overrides.policy,
      profiles: {
        ...defaults.policy?.profiles,
        ...overrides.policy.profiles,
      },
    } : defaults.policy,
    reporting: { ...defaults.reporting, ...overrides.reporting },
  };
}

export function validateConfig(config: SecurityBotConfig): void {
  const errors: string[] = [];

  if (!config.target.dockerCompose && !config.target.baseUrl) {
    errors.push("Either target.dockerCompose or target.baseUrl must be specified");
  }

  if (config.scanners.ai.enabled) {
    if (!config.scanners.ai.provider) {
      errors.push("AI provider must be specified when AI scanning is enabled");
    }
  }

  const authHasRoles = (config.auth?.roles?.length || 0) > 0;

  if (config.auth?.type === "jwt" && !authHasRoles && !config.auth.token && !config.auth.preScan) {
    errors.push("JWT token or pre-scan hook must be provided when auth type is jwt");
  }

  if (config.auth?.type === "apikey" && !authHasRoles && !config.auth.apiKey && !config.auth.preScan) {
    errors.push("API key or pre-scan hook must be provided when auth type is apikey");
  }

  if (config.auth?.type === "session" && !authHasRoles && !config.auth.cookieValue && !config.auth.preScan) {
    errors.push("Cookie value or pre-scan hook must be provided when auth type is session");
  }

  for (const role of config.auth?.roles || []) {
    const type = role.type || config.auth?.type || "none";
    if (type === "jwt" && !role.token && !role.preScan && !config.auth?.preScan) {
      errors.push(`JWT token or pre-scan hook must be provided for auth role ${role.name}`);
    }
    if (type === "apikey" && !role.apiKey && !role.preScan && !config.auth?.preScan) {
      errors.push(`API key or pre-scan hook must be provided for auth role ${role.name}`);
    }
    if (type === "session" && !role.cookieValue && !role.preScan && !config.auth?.preScan) {
      errors.push(`Cookie value or pre-scan hook must be provided for auth role ${role.name}`);
    }
  }

  if (config.safety?.maxRequestsPerSecond !== undefined && config.safety.maxRequestsPerSecond < 0) {
    errors.push("safety.maxRequestsPerSecond must be zero or greater");
  }

  if (errors.length > 0) {
    throw new ConfigError(`Invalid configuration:\n  - ${errors.join("\n  - ")}`);
  }
}

function interpolateEnvValues(value: unknown, path = "config"): unknown {
  if (typeof value === "string") {
    return interpolateEnvString(value, path);
  }

  if (Array.isArray(value)) {
    return value.map((item, index) => interpolateEnvValues(item, `${path}[${index}]`));
  }

  if (value && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value)) {
      result[key] = interpolateEnvValues(nested, `${path}.${key}`);
    }
    return result;
  }

  return value;
}

function interpolateEnvString(value: string, path: string): string {
  return value.replace(/\$\{([A-Z0-9_]+)(?::-([^}]*))?\}/gi, (_match, name: string, fallback: string | undefined) => {
    const envValue = process.env[name];
    if (envValue !== undefined) {
      return envValue;
    }

    if (fallback !== undefined) {
      return fallback;
    }

    throw new ConfigError(`Missing environment variable ${name} referenced by ${path}`);
  });
}
