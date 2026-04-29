import { existsSync, readFileSync } from "fs";
import { resolve, dirname } from "path";
import { parse } from "yaml";
import { Finding } from "../findings/finding.js";
import { logger } from "../core/logger.js";

interface SuppressionRule {
  id?: string;          // exact finding ID
  pattern?: string;     // substring match against title or category
  endpoint?: string;    // substring match against endpoint
  reason: string;
  expires?: string;     // ISO date — rule ignored after this date
}

interface SuppressionFile {
  suppressions: SuppressionRule[];
}

export interface SuppressionResult {
  effectiveFindings: Finding[];
  suppressedFindings: Finding[];
  suppressedCount: number;
}

export function loadSuppressionRules(
  suppressionPath?: string,
  configFilePath?: string
): SuppressionRule[] {
  const candidates: string[] = [];

  if (suppressionPath) {
    const base = configFilePath ? dirname(configFilePath) : process.cwd();
    candidates.push(resolve(base, suppressionPath));
  }

  // Default: look for .breachgateignore in cwd
  candidates.push(resolve(process.cwd(), ".breachgateignore"));

  for (const candidate of candidates) {
    if (!existsSync(candidate)) continue;
    try {
      const raw = readFileSync(candidate, "utf-8");
      const parsed = parse(raw) as SuppressionFile;
      if (!Array.isArray(parsed?.suppressions)) return [];
      logger.debug(`Loaded ${parsed.suppressions.length} suppression rule(s) from ${candidate}`);
      return parsed.suppressions;
    } catch (err) {
      logger.warn(`Failed to parse suppression file ${candidate}: ${(err as Error).message}`);
    }
  }

  return [];
}

export function applySuppressions(
  findings: Finding[],
  rules: SuppressionRule[]
): SuppressionResult {
  if (rules.length === 0) {
    return { effectiveFindings: findings, suppressedFindings: [], suppressedCount: 0 };
  }

  const today = new Date().toISOString().slice(0, 10);
  const activeRules = rules.filter(r => !r.expires || r.expires >= today);

  if (activeRules.length < rules.length) {
    logger.debug(`${rules.length - activeRules.length} suppression rule(s) expired and ignored`);
  }

  const effectiveFindings: Finding[] = [];
  const suppressedFindings: Finding[] = [];

  for (const finding of findings) {
    const suppressed = activeRules.some(rule => matchesRule(finding, rule));
    if (suppressed) {
      suppressedFindings.push(finding);
    } else {
      effectiveFindings.push(finding);
    }
  }

  if (suppressedFindings.length > 0) {
    logger.info(`Suppressed ${suppressedFindings.length} finding(s) via .breachgateignore`);
  }

  return { effectiveFindings, suppressedFindings, suppressedCount: suppressedFindings.length };
}

function matchesRule(finding: Finding, rule: SuppressionRule): boolean {
  if (rule.id && finding.id === rule.id) return true;

  if (rule.pattern) {
    const pat = rule.pattern.toLowerCase();
    if (
      finding.title.toLowerCase().includes(pat) ||
      finding.category.toLowerCase().includes(pat)
    ) {
      // Further narrow by endpoint if specified
      if (rule.endpoint) {
        return !!finding.endpoint?.toLowerCase().includes(rule.endpoint.toLowerCase());
      }
      return true;
    }
  }

  if (rule.endpoint && !rule.pattern) {
    return !!finding.endpoint?.toLowerCase().includes(rule.endpoint.toLowerCase());
  }

  return false;
}
