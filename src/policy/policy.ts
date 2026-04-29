import { existsSync, readFileSync } from "fs";
import { dirname, isAbsolute, resolve } from "path";
import { parse } from "yaml";
import { createHash } from "crypto";
import { Finding } from "../findings/finding.js";
import { SecurityVerdict } from "../findings/attack.analyzer.js";
import { ScanResult } from "../orchestrator/orchestrator.js";
import { ConfigError } from "../core/errors.js";

export type PolicyProfileName = "pull-request" | "main" | "release" | "nightly";

export interface PolicyRules {
  failOnConfirmedExploit: boolean;
  failOnInconclusive: boolean;
  failOnScannerFailure: boolean;
  maxCritical: number;
  maxHigh: number;
  differentialOnly: boolean;
}

export interface PolicyConfig {
  profile?: PolicyProfileName | string;
  baselinePath?: string;
  differentialOnly?: boolean;
  profiles?: Record<string, Partial<PolicyRules>>;
}

export interface BaselineEntry {
  fingerprint: string;
  reason: string;
  owner: string;
  expires: string;
}

export interface BaselineFile {
  version: string;
  findings: BaselineEntry[];
}

export interface SuppressedFinding {
  finding: Finding;
  fingerprint: string;
  baseline: BaselineEntry;
}

export interface ExpiredBaselineEntry {
  entry: BaselineEntry;
  expiredAt: string;
}

export interface PolicyEvaluation {
  profile: string;
  rules: PolicyRules;
  baselinePath?: string;
  differentialOnly: boolean;
  totalFindings: number;
  effectiveFindings: number;
  suppressedFindings: number;
  expiredBaselineEntries: ExpiredBaselineEntry[];
  matchedBaselineEntries: number;
  status: "passed" | "failed";
  reasons: string[];
  effectiveFindingFingerprints: string[];
  suppressedFindingFingerprints: string[];
}

export const DEFAULT_POLICY_PROFILES: Record<PolicyProfileName, PolicyRules> = {
  "pull-request": {
    failOnConfirmedExploit: true,
    failOnInconclusive: true,
    failOnScannerFailure: true,
    maxCritical: 0,
    maxHigh: 0,
    differentialOnly: true,
  },
  main: {
    failOnConfirmedExploit: true,
    failOnInconclusive: true,
    failOnScannerFailure: true,
    maxCritical: 0,
    maxHigh: 0,
    differentialOnly: false,
  },
  release: {
    failOnConfirmedExploit: true,
    failOnInconclusive: true,
    failOnScannerFailure: true,
    maxCritical: 0,
    maxHigh: 0,
    differentialOnly: false,
  },
  nightly: {
    failOnConfirmedExploit: true,
    failOnInconclusive: true,
    failOnScannerFailure: true,
    maxCritical: 0,
    maxHigh: 5,
    differentialOnly: false,
  },
};

export function resolvePolicyRules(
  policyConfig: PolicyConfig | undefined,
  profileOverride?: string,
  differentialOverride = false
): { profile: string; rules: PolicyRules } {
  const profile = profileOverride || policyConfig?.profile || "main";
  const defaults =
    DEFAULT_POLICY_PROFILES[profile as PolicyProfileName] ?? DEFAULT_POLICY_PROFILES.main;
  const configured = policyConfig?.profiles?.[profile] ?? {};

  return {
    profile,
    rules: {
      ...defaults,
      ...configured,
      differentialOnly: differentialOverride
        ? true
        : (policyConfig?.differentialOnly ??
          configured.differentialOnly ??
          defaults.differentialOnly),
    },
  };
}

export function loadBaseline(
  baselinePath: string | undefined,
  configFilePath?: string
): { path?: string; baseline?: BaselineFile } {
  if (!baselinePath) {
    return {};
  }

  const baseDir = configFilePath ? dirname(configFilePath) : process.cwd();
  const resolvedPath = isAbsolute(baselinePath) ? baselinePath : resolve(baseDir, baselinePath);

  if (!existsSync(resolvedPath)) {
    throw new ConfigError(`Baseline file not found: ${resolvedPath}`);
  }

  try {
    const parsed = parse(readFileSync(resolvedPath, "utf-8")) as Partial<BaselineFile>;
    return {
      path: resolvedPath,
      baseline: {
        version: parsed.version || "1.0",
        findings: parsed.findings || [],
      },
    };
  } catch (err) {
    throw new ConfigError(`Failed to parse baseline ${resolvedPath}: ${(err as Error).message}`);
  }
}

export function fingerprintFinding(finding: Finding): string {
  const stableParts = [
    finding.cve || "",
    finding.cwe || "",
    finding.category,
    normalizeText(finding.title),
    finding.endpoint || "",
    finding.package || "",
    finding.version || "",
  ];

  if (finding.role) {
    stableParts.push(finding.role);
  }

  return createHash("sha256").update(stableParts.join("|")).digest("hex").slice(0, 16);
}

export function applyBaseline(
  findings: Finding[],
  baseline?: BaselineFile
): {
  effectiveFindings: Finding[];
  suppressed: SuppressedFinding[];
  expired: ExpiredBaselineEntry[];
} {
  if (!baseline) {
    return {
      effectiveFindings: findings,
      suppressed: [],
      expired: [],
    };
  }

  const today = new Date();
  const baselineByFingerprint = new Map<string, BaselineEntry>();
  const expired: ExpiredBaselineEntry[] = [];

  for (const entry of baseline.findings) {
    if (isExpired(entry.expires, today)) {
      expired.push({ entry, expiredAt: entry.expires });
      continue;
    }
    baselineByFingerprint.set(entry.fingerprint, entry);
  }

  const effectiveFindings: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];

  for (const finding of findings) {
    const fingerprint = fingerprintFinding(finding);
    const baselineEntry = baselineByFingerprint.get(fingerprint);

    if (baselineEntry) {
      suppressed.push({ finding, fingerprint, baseline: baselineEntry });
    } else {
      effectiveFindings.push(finding);
    }
  }

  return { effectiveFindings, suppressed, expired };
}

export function evaluatePolicy(options: {
  allFindings: Finding[];
  effectiveFindings: Finding[];
  suppressed: SuppressedFinding[];
  expired: ExpiredBaselineEntry[];
  verdict: SecurityVerdict;
  scanResult: ScanResult;
  profile: string;
  rules: PolicyRules;
  baselinePath?: string;
}): PolicyEvaluation {
  const reasons: string[] = [];
  const criticalCount = options.effectiveFindings.filter((f) => f.severity === "CRITICAL").length;
  const highCount = options.effectiveFindings.filter((f) => f.severity === "HIGH").length;

  if (options.rules.failOnInconclusive && options.verdict.verdict === "INCONCLUSIVE") {
    reasons.push(options.verdict.reason);
  }

  if (options.rules.failOnScannerFailure && options.scanResult.failedScanners.length > 0) {
    reasons.push(
      `Required scanners failed or were unavailable: ${options.scanResult.failedScanners.join(", ")}`
    );
  }

  if (options.rules.failOnConfirmedExploit && options.verdict.confirmedExploits.length > 0) {
    reasons.push(`${options.verdict.confirmedExploits.length} confirmed exploit(s) detected`);
  }

  if (criticalCount > options.rules.maxCritical) {
    reasons.push(
      `${criticalCount} critical finding(s) exceed policy maximum ${options.rules.maxCritical}`
    );
  }

  if (highCount > options.rules.maxHigh) {
    reasons.push(`${highCount} high finding(s) exceed policy maximum ${options.rules.maxHigh}`);
  }

  return {
    profile: options.profile,
    rules: options.rules,
    baselinePath: options.baselinePath,
    differentialOnly: options.rules.differentialOnly,
    totalFindings: options.allFindings.length,
    effectiveFindings: options.effectiveFindings.length,
    suppressedFindings: options.suppressed.length,
    expiredBaselineEntries: options.expired,
    matchedBaselineEntries: options.suppressed.length,
    status: reasons.length > 0 ? "failed" : "passed",
    reasons,
    effectiveFindingFingerprints: options.effectiveFindings.map(fingerprintFinding),
    suppressedFindingFingerprints: options.suppressed.map((s) => s.fingerprint),
  };
}

function normalizeText(value: string): string {
  return value.toLowerCase().replace(/\s+/g, " ").trim();
}

function isExpired(value: string, now: Date): boolean {
  const expires = new Date(`${value}T23:59:59.999Z`);
  if (Number.isNaN(expires.getTime())) {
    return true;
  }
  return expires.getTime() < now.getTime();
}
