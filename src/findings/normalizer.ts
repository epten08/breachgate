import { RawFinding } from "./raw.finding.js";
import { Finding, Severity } from "./finding.js";
import { RiskEngine } from "./risk.engine.js";
import { Deduplicator, DeduplicationOptions } from "./deduplicator.js";
import { v4 as uuid } from "uuid";

export interface NormalizationOptions {
  deduplicate?: boolean;
  deduplicationOptions?: DeduplicationOptions;
}

const riskEngine = new RiskEngine();

export function normalizeFindings(
  raw: RawFinding[],
  options: NormalizationOptions = {}
): Finding[] {
  const { deduplicate = true, deduplicationOptions } = options;

  // Convert raw findings to normalized findings
  const findings = raw.map((r) => normalizeSingle(r));

  // Deduplicate if enabled
  if (deduplicate && findings.length > 0) {
    const deduplicator = new Deduplicator(deduplicationOptions);
    return deduplicator.deduplicate(findings);
  }

  return findings;
}

function normalizeSingle(raw: RawFinding): Finding {
  const risk = riskEngine.calculateRisk(raw);
  const endpointContext = riskEngine.parseEndpointContext(raw.endpoint);

  return {
    id: uuid(),
    title: raw.description,
    category: raw.category,
    severity: mapSeverity(raw.severityHint),
    endpoint: raw.endpoint,
    endpointContext,
    role: raw.role,
    evidence: raw.evidence ?? "No evidence provided",
    exploitability: risk.exploitability,
    confidence: risk.confidence,
    riskScore: risk.riskScore,
    sources: [raw.source],
    deduplicated: false,
    duplicateCount: 0,
    cve: raw.cve,
    cwe: raw.cwe,
    package: raw.package,
    version: raw.version,
    fixedVersion: raw.fixedVersion,
    reference: raw.reference,
  };
}

function mapSeverity(hint?: string): Severity {
  const upper = hint?.toUpperCase();
  switch (upper) {
    case "CRITICAL":
      return "CRITICAL";
    case "HIGH":
      return "HIGH";
    case "MEDIUM":
      return "MEDIUM";
    case "LOW":
      return "LOW";
    default:
      return "LOW";
  }
}

export function sortByRisk(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    // First by severity
    const severityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    const severityDiff = severityOrder[b.severity] - severityOrder[a.severity];
    if (severityDiff !== 0) return severityDiff;

    // Then by risk score
    return b.riskScore - a.riskScore;
  });
}

export function filterBySeverity(findings: Finding[], minSeverity: Severity): Finding[] {
  const severityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const minLevel = severityOrder[minSeverity];

  return findings.filter((f) => severityOrder[f.severity] >= minLevel);
}
