import { Finding, FindingGroup, SEVERITY_WEIGHTS } from "./finding.js";
import { logger } from "../core/logger.js";

export interface DeduplicationOptions {
  similarityThreshold?: number;
  mergeSourcesFromDuplicates?: boolean;
}

export class Deduplicator {
  private options: Required<DeduplicationOptions>;

  constructor(options: DeduplicationOptions = {}) {
    this.options = {
      similarityThreshold: 0.8,
      mergeSourcesFromDuplicates: true,
      ...options,
    };
  }

  deduplicate(findings: Finding[]): Finding[] {
    if (findings.length === 0) return [];

    const groups = this.groupSimilarFindings(findings);
    const deduplicated = this.mergeGroups(groups);

    const removed = findings.length - deduplicated.length;
    if (removed > 0) {
      logger.debug(`Deduplicated ${removed} duplicate findings`);
    }

    return deduplicated;
  }

  private groupSimilarFindings(findings: Finding[]): FindingGroup[] {
    const groups: FindingGroup[] = [];
    const processed = new Set<string>();

    for (const finding of findings) {
      if (processed.has(finding.id)) continue;

      const group: FindingGroup = {
        primary: finding,
        duplicates: [],
      };

      processed.add(finding.id);

      // Find duplicates
      for (const other of findings) {
        if (processed.has(other.id)) continue;

        if (this.areSimilar(finding, other)) {
          group.duplicates.push(other);
          processed.add(other.id);
        }
      }

      groups.push(group);
    }

    return groups;
  }

  private areSimilar(a: Finding, b: Finding): boolean {
    if (a.role && b.role && a.role !== b.role) {
      return false;
    }

    // Exact CVE match
    if (a.cve && b.cve && a.cve === b.cve) {
      return true;
    }

    // Same package and version vulnerability
    if (a.package && b.package && a.version && b.version) {
      if (a.package === b.package && a.version === b.version) {
        return true;
      }
    }

    // Same endpoint vulnerability
    if (a.endpoint && b.endpoint && a.endpoint === b.endpoint) {
      if (a.category === b.category) {
        return true;
      }
    }

    // Title similarity check
    const titleSimilarity = this.calculateSimilarity(a.title, b.title);
    if (titleSimilarity >= this.options.similarityThreshold) {
      // Also check category matches
      if (a.category === b.category || this.categoriesRelated(a.category, b.category)) {
        return true;
      }
    }

    return false;
  }

  private calculateSimilarity(a: string, b: string): number {
    const wordsA = this.tokenize(a);
    const wordsB = this.tokenize(b);

    if (wordsA.length === 0 || wordsB.length === 0) return 0;

    const intersection = wordsA.filter((w) => wordsB.includes(w));
    const union = new Set([...wordsA, ...wordsB]);

    return intersection.length / union.size;
  }

  private tokenize(text: string): string[] {
    return text
      .toLowerCase()
      .replace(/[^a-z0-9\s]/g, " ")
      .split(/\s+/)
      .filter((w) => w.length > 2);
  }

  private categoriesRelated(a: string, b: string): boolean {
    const categoryGroups = [
      ["SQL Injection", "Injection", "Command Injection"],
      ["XSS", "Cross-Site Scripting", "Cross-Site Scripting (XSS)"],
      ["Broken Authentication", "Authentication Bypass", "Broken Access Control"],
      ["Dependency Vulnerability", "NPM Dependency Vulnerability", "Container Vulnerability"],
      ["Security Misconfiguration", "Missing Security Header"],
    ];

    for (const group of categoryGroups) {
      const aInGroup = group.some((g) => a.toLowerCase().includes(g.toLowerCase()));
      const bInGroup = group.some((g) => b.toLowerCase().includes(g.toLowerCase()));
      if (aInGroup && bInGroup) return true;
    }

    return false;
  }

  private mergeGroups(groups: FindingGroup[]): Finding[] {
    return groups.map((group) => this.mergeFindingGroup(group));
  }

  private mergeFindingGroup(group: FindingGroup): Finding {
    const { primary, duplicates } = group;

    if (duplicates.length === 0) {
      return {
        ...primary,
        deduplicated: false,
        duplicateCount: 0,
      };
    }

    // Merge sources from all duplicates
    const allSources = new Set(primary.sources);
    if (this.options.mergeSourcesFromDuplicates) {
      for (const dup of duplicates) {
        dup.sources.forEach((s) => allSources.add(s));
      }
    }

    // Pick the highest severity
    const allFindings = [primary, ...duplicates];
    const highestSeverity = this.getHighestSeverity(allFindings);

    // Pick the best evidence (longest, most detailed)
    const bestEvidence = this.getBestEvidence(allFindings);

    // Calculate average confidence, boosted by multiple sources
    const baseConfidence =
      allFindings.reduce((sum, f) => sum + f.confidence, 0) / allFindings.length;
    const confidenceBoost = Math.min(duplicates.length * 0.05, 0.2);
    const mergedConfidence = Math.min(baseConfidence + confidenceBoost, 1.0);

    // Take highest exploitability
    const maxExploitability = Math.max(...allFindings.map((f) => f.exploitability));

    // Recalculate risk score
    const severityWeight = SEVERITY_WEIGHTS[highestSeverity] / 4;
    const riskScore = severityWeight * 0.4 + maxExploitability * 0.35 + mergedConfidence * 0.25;

    // Merge CVE, CWE, references
    const cve = primary.cve || duplicates.find((d) => d.cve)?.cve;
    const cwe = primary.cwe || duplicates.find((d) => d.cwe)?.cwe;
    const reference = primary.reference || duplicates.find((d) => d.reference)?.reference;
    const fixedVersion =
      primary.fixedVersion || duplicates.find((d) => d.fixedVersion)?.fixedVersion;

    return {
      ...primary,
      severity: highestSeverity,
      evidence: bestEvidence,
      confidence: Math.round(mergedConfidence * 100) / 100,
      exploitability: maxExploitability,
      riskScore: Math.round(riskScore * 100) / 100,
      sources: Array.from(allSources),
      deduplicated: true,
      duplicateCount: duplicates.length,
      cve,
      cwe,
      reference,
      fixedVersion,
    };
  }

  private getHighestSeverity(findings: Finding[]): Finding["severity"] {
    const severities = findings.map((f) => f.severity);
    if (severities.includes("CRITICAL")) return "CRITICAL";
    if (severities.includes("HIGH")) return "HIGH";
    if (severities.includes("MEDIUM")) return "MEDIUM";
    return "LOW";
  }

  private getBestEvidence(findings: Finding[]): string {
    // Prefer evidence with more detail
    return findings.reduce((best, current) => {
      if (!best.evidence) return current;
      if (!current.evidence) return best;
      return current.evidence.length > best.evidence.length ? current : best;
    }).evidence;
  }
}
