import { Finding } from "./finding.js";
import { AttackAnalyzer, AttackVector, REVIEW_THRESHOLD } from "./attack.analyzer.js";

/**
 * One scorer, shared by every reporter and the CLI summary.
 *
 * Scores are computed on demand rather than stored on the Finding, so there is
 * exactly one implementation and no possibility of a report and a verdict
 * quoting different numbers for the same finding.
 */
const analyzer = new AttackAnalyzer();

export function scoreFinding(finding: Finding): AttackVector {
  return analyzer.analyzeAttackVector(finding);
}

export function feasibilityOf(finding: Finding): number {
  return analyzer.analyzeAttackVector(finding).feasibilityScore;
}

export function isConfirmed(finding: Finding): boolean {
  return finding.proofs.length > 0;
}

/** Short human label for a feasibility score. */
export function feasibilityLabel(finding: Finding): string {
  if (isConfirmed(finding)) return "CONFIRMED";
  const score = feasibilityOf(finding);
  if (score >= 0.5) return "High";
  if (score >= REVIEW_THRESHOLD) return "Review";
  return "Low";
}

/**
 * One-line explanation of where a finding's exploitability number came from.
 * This is what makes a verdict checkable in ten seconds.
 */
export function explainExploitability(finding: Finding): string {
  const vector = scoreFinding(finding);

  switch (vector.exploitabilityBasis) {
    case "kev":
      return `CISA KEV listed: ${finding.cve} is being exploited in the wild`;
    case "proof":
      return `Demonstrated during this scan: ${finding.proofs.join(", ")}`;
    case "epss":
      return `EPSS ${(finding.epssScore ?? 0).toFixed(4)} (${((finding.epssPercentile ?? 0) * 100).toFixed(0)}th percentile) probability of exploitation in 30 days`;
    case "category":
    default:
      return `No exploit intelligence and no demonstration. Category baseline for ${finding.category}.`;
  }
}
