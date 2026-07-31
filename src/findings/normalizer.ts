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

/**
 * INFO-level input is dropped at the door.
 *
 * ZAP and other scanners emit informational alerts by design. Previously these
 * were silently promoted to LOW and then flowed into the verdict, which is how
 * a timestamp disclosure became a deployment blocker. Informational output is
 * not a security finding and does not enter the pipeline.
 */
export function isInformational(hint?: string): boolean {
  const upper = hint?.toUpperCase();
  return upper === "INFO" || upper === "INFORMATIONAL" || upper === "NOTE";
}

export function normalizeFindings(
  raw: RawFinding[],
  options: NormalizationOptions = {}
): Finding[] {
  const { deduplicate = true, deduplicationOptions } = options;

  const findings = raw
    .filter((r) => !isInformational(r.severityHint))
    .map((r) => normalizeSingle(r));

  if (deduplicate && findings.length > 0) {
    const deduplicator = new Deduplicator(deduplicationOptions);
    return deduplicator.deduplicate(findings);
  }

  return findings;
}

function normalizeSingle(raw: RawFinding): Finding {
  const endpointContext = riskEngine.parseEndpointContext(raw.endpoint);

  return {
    id: uuid(),
    title: raw.description,
    category: raw.category,
    severity: riskEngine.mapSeverity(raw.severityHint),
    endpoint: raw.endpoint,
    endpointContext,
    role: raw.role,
    evidence: raw.evidence ?? "No evidence provided",
    proofs: raw.proofs ?? [],
    proofExcerpt: raw.proofExcerpt,
    confidence: riskEngine.calculateConfidence(raw),
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

export function sortByRisk(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    // Confirmed exploitation always sorts first, regardless of severity label.
    const aConfirmed = a.proofs.length > 0 ? 1 : 0;
    const bConfirmed = b.proofs.length > 0 ? 1 : 0;
    if (aConfirmed !== bConfirmed) return bConfirmed - aConfirmed;

    const severityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    const severityDiff = severityOrder[b.severity] - severityOrder[a.severity];
    if (severityDiff !== 0) return severityDiff;

    return b.confidence - a.confidence;
  });
}

export function filterBySeverity(findings: Finding[], minSeverity: Severity): Finding[] {
  const severityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const minLevel = severityOrder[minSeverity];

  return findings.filter((f) => severityOrder[f.severity] >= minLevel);
}
