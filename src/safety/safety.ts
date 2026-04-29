import { ConfigError } from "../core/errors.js";
import { SafetyConfig, SafetyProfile } from "../core/config.loader.js";

const DEFAULT_PROFILE: SafetyProfile = "safe-active";
const PRODUCTION_TOKENS = new Set(["prod", "production", "live"]);
const DESTRUCTIVE_METHODS = new Set(["DELETE", "PUT", "PATCH"]);

export function enforceTargetSafety(
  safety: SafetyConfig | undefined,
  targetUrl: string,
  ciMode: boolean
): void {
  const target = parseHttpUrl(targetUrl);
  const hostname = target.hostname.toLowerCase();

  if (!isAllowedHost(hostname, safety?.allowedHosts)) {
    throw new ConfigError(`Target host ${hostname} is not in safety.allowedHosts`);
  }

  if (ciMode && !safety?.allowProductionTargets && isProductionLikeHost(hostname)) {
    throw new ConfigError(
      `Refusing to scan production-looking host ${hostname} in CI. ` +
        "Set safety.allowProductionTargets: true after confirming scope."
    );
  }
}

export function shouldRunZapActiveScan(safety?: SafetyConfig): boolean {
  return getProfile(safety) === "full-active";
}

export function shouldRunAiActiveTests(safety?: SafetyConfig): boolean {
  return getProfile(safety) !== "passive";
}

export function allowsDestructiveMethod(method: string, safety?: SafetyConfig): boolean {
  const normalized = method.toUpperCase();
  if (!DESTRUCTIVE_METHODS.has(normalized)) {
    return true;
  }

  return getProfile(safety) === "full-active" || safety?.allowDestructiveMethods === true;
}

export function requestDelayMs(safety?: SafetyConfig): number {
  const rate = safety?.maxRequestsPerSecond;
  if (!rate || rate <= 0) {
    return 0;
  }
  return Math.ceil(1000 / rate);
}

export function isPathExcluded(path: string, safety?: SafetyConfig): boolean {
  const patterns = safety?.excludedPaths || [];
  return patterns.some((pattern) => pathMatchesPattern(path, pattern));
}

export function isUrlInScope(url: URL, targetUrl: string, safety?: SafetyConfig): boolean {
  const target = parseHttpUrl(targetUrl);
  const hostname = url.hostname.toLowerCase();

  if (hostname === target.hostname.toLowerCase()) {
    return true;
  }

  return isAllowedHost(hostname, safety?.allowedHosts);
}

export function getProfile(safety?: SafetyConfig): SafetyProfile {
  return safety?.profile || DEFAULT_PROFILE;
}

function isAllowedHost(hostname: string, allowedHosts?: string[]): boolean {
  if (!allowedHosts || allowedHosts.length === 0) {
    return true;
  }

  return allowedHosts.some((pattern) => hostMatches(hostname, pattern.toLowerCase()));
}

function hostMatches(hostname: string, pattern: string): boolean {
  if (pattern === hostname) {
    return true;
  }

  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(1);
    return hostname.endsWith(suffix) && hostname.length > suffix.length;
  }

  return false;
}

function isProductionLikeHost(hostname: string): boolean {
  return hostname.split(/[.\-_]/).some((part) => PRODUCTION_TOKENS.has(part));
}

function pathMatchesPattern(path: string, pattern: string): boolean {
  if (pattern === path) {
    return true;
  }

  if (pattern.endsWith("*")) {
    return path.startsWith(pattern.slice(0, -1));
  }

  if (pattern.includes("*")) {
    const escaped = pattern.split("*").map(escapeRegExp).join(".*");
    return new RegExp(`^${escaped}$`).test(path);
  }

  return false;
}

function parseHttpUrl(value: string): URL {
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error(`unsupported protocol ${url.protocol}`);
    }
    return url;
  } catch (err) {
    throw new ConfigError(`Invalid target URL for safety checks: ${(err as Error).message}`);
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
