import { Finding, Severity, SEVERITY_WEIGHTS, EndpointContext } from "./finding.js";
import { RawFinding } from "./raw.finding.js";

// =============================================================================
// Interfaces
// =============================================================================

export interface RiskFactors {
  severity: Severity;
  category: string;
  hasExploit: boolean;
  hasFix: boolean;
  isExposed: boolean;
  cvssScore?: number;
  endpointContext?: EndpointContext;
}

export interface RiskScore {
  exploitability: number;
  confidence: number;
  riskScore: number;
}

export interface RiskThreshold {
  minRiskScore: number;
  minConfidence: number;
}

export const RISK_THRESHOLDS: Record<string, RiskThreshold> = {
  strict: { minRiskScore: 0.6, minConfidence: 0.5 },
  standard: { minRiskScore: 0.7, minConfidence: 0.6 },
  relaxed: { minRiskScore: 0.8, minConfidence: 0.75 },
};

export interface Remediation {
  priority: "immediate" | "high" | "medium" | "low";
  action: string;
  details: string;
  effort: "minimal" | "moderate" | "significant";
}

// =============================================================================
// Exploitability Scores by Category
// =============================================================================

const CATEGORY_EXPLOITABILITY: Record<string, number> = {
  // Critical - Remote code execution potential
  "Remote Code Execution": 1.0,
  "Command Injection": 0.95,
  "SQL Injection": 0.95,
  Injection: 0.9,

  // High - Direct security impact
  "Path Traversal": 0.85,
  XSS: 0.8,
  "Cross-Site Scripting (XSS)": 0.8,
  "Broken Authentication": 0.85,
  "Broken Access Control": 0.8,
  "Hardcoded Secret": 0.75,
  "Sensitive Data Exposure": 0.75,

  // Medium - Indirect or conditional impact
  CSRF: 0.6,
  "Security Misconfiguration": 0.5,
  "Information Disclosure": 0.55,

  // Lower - Require specific conditions
  "TLS/SSL Issue": 0.4,
  "Security Vulnerability": 0.5,
  "Missing Security Header": 0.3,
  "Dependency Vulnerability": 0.5,
  "NPM Dependency Vulnerability": 0.5,
  "Application Dependency Vulnerability": 0.5,
  "OS Package Vulnerability": 0.4,
  "Container Vulnerability": 0.45,
};

// =============================================================================
// Source Confidence - AI findings should be treated as strong signals
// =============================================================================

const SOURCE_CONFIDENCE: Record<string, number> = {
  // Static analysis - high confidence, well-known vulnerabilities
  "Trivy Static": 0.95,
  "Trivy Image": 0.95,

  // Dynamic analysis - tests actual behavior
  "OWASP ZAP API": 0.85,

  // AI Security Tester - context-aware, tests business logic
  // Elevated confidence because AI understands endpoint semantics
  "AI Security Tester": 0.8,
};

// =============================================================================
// Remediation Templates
// =============================================================================

const REMEDIATION_TEMPLATES: Record<string, Remediation> = {
  "SQL Injection": {
    priority: "immediate",
    action: "Use parameterized queries or prepared statements",
    details:
      "Never concatenate user input into SQL queries. Use ORM/query builders with automatic escaping. Implement input validation as defense-in-depth.",
    effort: "moderate",
  },
  Injection: {
    priority: "immediate",
    action: "Validate and sanitize all input, use safe APIs",
    details:
      "Identify injection points and implement context-appropriate escaping. Use allowlists over blocklists.",
    effort: "moderate",
  },
  "Command Injection": {
    priority: "immediate",
    action: "Avoid shell commands; use safe library functions",
    details:
      "Replace shell execution with language-native APIs. If shell is required, use strict allowlist validation and never pass user input directly.",
    effort: "moderate",
  },
  "Path Traversal": {
    priority: "high",
    action: "Validate file paths against allowlist",
    details:
      "Normalize paths and verify they resolve within expected directories. Reject paths containing '..' or absolute paths from user input.",
    effort: "minimal",
  },
  XSS: {
    priority: "high",
    action: "Encode output and implement Content-Security-Policy",
    details:
      "Apply context-appropriate encoding (HTML, JS, URL). Use CSP headers to prevent inline scripts. Consider using auto-escaping template engines.",
    effort: "moderate",
  },
  "Cross-Site Scripting (XSS)": {
    priority: "high",
    action: "Encode output and implement Content-Security-Policy",
    details:
      "Apply context-appropriate encoding. Use CSP headers. Consider auto-escaping template engines.",
    effort: "moderate",
  },
  "Broken Authentication": {
    priority: "high",
    action: "Implement proper authentication checks",
    details:
      "Verify authentication on every request. Use secure session management. Implement rate limiting and account lockout.",
    effort: "moderate",
  },
  "Broken Access Control": {
    priority: "high",
    action: "Implement authorization checks at every endpoint",
    details:
      "Deny by default. Check user permissions server-side for every resource access. Log access control failures.",
    effort: "moderate",
  },
  "Information Disclosure": {
    priority: "medium",
    action: "Remove debug endpoints and sensitive data from responses",
    details:
      "Disable debug mode in production. Review API responses for unnecessary data. Implement proper error handling that doesn't leak internals.",
    effort: "minimal",
  },
  "Sensitive Data Exposure": {
    priority: "high",
    action: "Encrypt sensitive data and restrict access",
    details:
      "Use encryption at rest and in transit. Minimize data collection. Implement proper access controls.",
    effort: "significant",
  },
  "Security Misconfiguration": {
    priority: "medium",
    action: "Review and harden security configuration",
    details:
      "Add security headers (CSP, X-Frame-Options, etc). Disable unnecessary features. Keep software updated.",
    effort: "minimal",
  },
  "Hardcoded Secret": {
    priority: "high",
    action: "Move secrets to environment variables or secret manager",
    details:
      "Remove secrets from code. Use secret management solutions. Rotate exposed credentials immediately.",
    effort: "minimal",
  },
  CSRF: {
    priority: "medium",
    action: "Implement CSRF tokens on state-changing operations",
    details:
      "Use synchronizer token pattern. Verify Origin/Referer headers. Use SameSite cookie attribute.",
    effort: "moderate",
  },
  "Container Vulnerability": {
    priority: "medium",
    action: "Update base image and dependencies",
    details: "Use minimal base images. Keep dependencies updated. Scan images in CI/CD pipeline.",
    effort: "minimal",
  },
  "OS Package Vulnerability": {
    priority: "medium",
    action: "Update system packages to patched versions",
    details:
      "Apply security updates regularly. Use automated patch management. Consider container image rebuilds.",
    effort: "minimal",
  },
  "Dependency Vulnerability": {
    priority: "medium",
    action: "Update vulnerable dependencies",
    details:
      "Run dependency audit regularly. Use automated dependency updates. Review transitive dependencies.",
    effort: "minimal",
  },
  "NPM Dependency Vulnerability": {
    priority: "medium",
    action: "Run npm audit fix and update packages",
    details: "Use npm audit in CI. Consider using npm-check-updates. Pin dependency versions.",
    effort: "minimal",
  },
  "Application Dependency Vulnerability": {
    priority: "medium",
    action: "Update vulnerable application dependencies",
    details: "Review dependency tree. Update to patched versions. Test after updates.",
    effort: "minimal",
  },
};

const DEFAULT_REMEDIATION: Remediation = {
  priority: "medium",
  action: "Review and address the security finding",
  details:
    "Analyze the finding in context of your application. Implement appropriate controls based on risk level.",
  effort: "moderate",
};

// =============================================================================
// Risk Engine
// =============================================================================

export class RiskEngine {
  calculateRisk(raw: RawFinding): RiskScore {
    const factors = this.extractFactors(raw);
    const exploitability = this.calculateExploitability(factors, raw);
    const confidence = this.calculateConfidence(raw);
    const riskScore = this.calculateCompositeScore(factors, exploitability, confidence);

    return { exploitability, confidence, riskScore };
  }

  /**
   * Determine if findings exceed risk threshold
   * Uses risk-based logic instead of simple severity comparison
   */
  exceedsRiskThreshold(
    findings: Finding[],
    threshold: RiskThreshold = RISK_THRESHOLDS.standard
  ): { exceeds: boolean; reason: string; criticalFindings: Finding[] } {
    const criticalFindings = findings.filter(
      (f) => f.riskScore >= threshold.minRiskScore && f.confidence >= threshold.minConfidence
    );

    if (criticalFindings.length === 0) {
      return { exceeds: false, reason: "No findings exceed risk threshold", criticalFindings: [] };
    }

    // Build reason based on what was found
    const byCategory = this.groupByCategory(criticalFindings);
    const categories = Object.keys(byCategory).slice(0, 3);
    const reason = `${criticalFindings.length} high-risk finding(s) detected: ${categories.join(", ")}`;

    return { exceeds: true, reason, criticalFindings };
  }

  /**
   * Get remediation guidance for a finding
   */
  getRemediation(finding: Finding): Remediation {
    // Try exact category match
    let remediation = REMEDIATION_TEMPLATES[finding.category];

    if (!remediation) {
      // Try partial match
      const category = finding.category.toLowerCase();
      for (const [key, value] of Object.entries(REMEDIATION_TEMPLATES)) {
        if (category.includes(key.toLowerCase()) || key.toLowerCase().includes(category)) {
          remediation = value;
          break;
        }
      }
    }

    if (!remediation) {
      remediation = { ...DEFAULT_REMEDIATION };

      // Adjust priority based on risk score
      if (finding.riskScore >= 0.8) {
        remediation.priority = "immediate";
      } else if (finding.riskScore >= 0.7) {
        remediation.priority = "high";
      } else if (finding.riskScore >= 0.5) {
        remediation.priority = "medium";
      } else {
        remediation.priority = "low";
      }
    }

    return remediation;
  }

  /**
   * Calculate endpoint context for better risk assessment
   */
  parseEndpointContext(endpoint?: string): EndpointContext | undefined {
    if (!endpoint) return undefined;

    const parts = endpoint.split(" ");
    const method = parts[0]?.toUpperCase();
    const path = parts[1] || endpoint;

    // Determine if endpoint handles sensitive operations
    const handlesData =
      path.includes("/user") ||
      path.includes("/data") ||
      path.includes("/file") ||
      path.includes("/admin") ||
      method === "POST" ||
      method === "PUT" ||
      method === "DELETE";

    const acceptsUserInput =
      method === "POST" ||
      method === "PUT" ||
      method === "PATCH" ||
      path.includes("?") ||
      path.includes(":id") ||
      path.includes("{");

    // Heuristic: endpoints with certain paths likely require auth
    const requiresAuth =
      path.includes("/admin") ||
      path.includes("/user") ||
      path.includes("/private") ||
      (path.includes("/api/") && !path.includes("/public"));

    return {
      method,
      path,
      acceptsUserInput,
      requiresAuth,
      handlesData,
    };
  }

  private extractFactors(raw: RawFinding): RiskFactors {
    const endpointContext = this.parseEndpointContext(raw.endpoint);

    return {
      severity: this.mapSeverity(raw.severityHint),
      category: raw.category,
      hasExploit: this.hasKnownExploit(raw),
      hasFix: !!raw.fixedVersion,
      isExposed: this.isExternallyExposed(raw),
      endpointContext,
    };
  }

  private calculateExploitability(factors: RiskFactors, raw: RawFinding): number {
    let score = 0.5; // Base score

    // Category-based exploitability
    const categoryScore = this.getCategoryExploitability(factors.category);
    score = categoryScore;

    // Adjust for severity
    score *= 0.7 + SEVERITY_WEIGHTS[factors.severity] * 0.075;

    // Known exploit increases exploitability
    if (factors.hasExploit) {
      score = Math.min(score * 1.2, 1.0);
    }

    // Available fix slightly decreases urgency
    if (factors.hasFix) {
      score *= 0.95;
    }

    // External exposure increases risk
    if (factors.isExposed) {
      score = Math.min(score * 1.1, 1.0);
    }

    // Endpoint context adjustments
    if (factors.endpointContext) {
      const ctx = factors.endpointContext;

      // Endpoints that accept user input are more exploitable
      if (ctx.acceptsUserInput) {
        score = Math.min(score * 1.1, 1.0);
      }

      // Endpoints handling sensitive data increase risk
      if (ctx.handlesData) {
        score = Math.min(score * 1.05, 1.0);
      }

      // Unauthenticated endpoints are more exposed
      if (!ctx.requiresAuth) {
        score = Math.min(score * 1.05, 1.0);
      }
    }

    // CVE presence indicates confirmed vulnerability
    if (raw.cve) {
      score = Math.min(score * 1.05, 1.0);
    }

    return Math.round(score * 100) / 100;
  }

  private getCategoryExploitability(category: string): number {
    // Direct match
    if (CATEGORY_EXPLOITABILITY[category] !== undefined) {
      return CATEGORY_EXPLOITABILITY[category];
    }

    // Partial match
    const lowerCategory = category.toLowerCase();
    for (const [key, value] of Object.entries(CATEGORY_EXPLOITABILITY)) {
      if (lowerCategory.includes(key.toLowerCase()) || key.toLowerCase().includes(lowerCategory)) {
        return value;
      }
    }

    return 0.5; // Default
  }

  private calculateConfidence(raw: RawFinding): number {
    let confidence = SOURCE_CONFIDENCE[raw.source] ?? 0.7;

    // Evidence quality affects confidence
    if (raw.evidence) {
      if (raw.evidence.length > 100) {
        confidence = Math.min(confidence + 0.1, 1.0);
      } else if (raw.evidence.length > 50) {
        confidence = Math.min(confidence + 0.05, 1.0);
      }

      // Response patterns increase confidence for dynamic findings
      if (raw.evidence.includes("Response Status:") && raw.evidence.includes("Matched:")) {
        confidence = Math.min(confidence + 0.1, 1.0);
      }
    }

    // CVE/CWE increases confidence (confirmed vulnerability)
    if (raw.cve) {
      confidence = Math.min(confidence + 0.1, 1.0);
    }
    if (raw.cwe) {
      confidence = Math.min(confidence + 0.05, 1.0);
    }

    // Reference URL increases confidence
    if (raw.reference) {
      confidence = Math.min(confidence + 0.05, 1.0);
    }

    return Math.round(confidence * 100) / 100;
  }

  private calculateCompositeScore(
    factors: RiskFactors,
    exploitability: number,
    confidence: number
  ): number {
    // Weighted formula prioritizing exploitability and confidence
    const severityWeight = SEVERITY_WEIGHTS[factors.severity] / 4; // Normalize to 0-1
    const composite = severityWeight * 0.3 + exploitability * 0.4 + confidence * 0.3;

    return Math.round(composite * 100) / 100;
  }

  private mapSeverity(hint?: string): Severity {
    const upper = hint?.toUpperCase();
    if (upper === "CRITICAL") return "CRITICAL";
    if (upper === "HIGH") return "HIGH";
    if (upper === "MEDIUM") return "MEDIUM";
    return "LOW";
  }

  private hasKnownExploit(raw: RawFinding): boolean {
    if (raw.cve) {
      // Critical CVEs more likely to have exploits
      return raw.severityHint === "CRITICAL";
    }
    return false;
  }

  private isExternallyExposed(raw: RawFinding): boolean {
    if (raw.endpoint) {
      return true;
    }

    const exposedCategories = [
      "XSS",
      "SQL Injection",
      "CSRF",
      "Broken Authentication",
      "Broken Access Control",
      "Command Injection",
      "Path Traversal",
    ];

    return exposedCategories.some((cat) => raw.category.toLowerCase().includes(cat.toLowerCase()));
  }

  private groupByCategory(findings: Finding[]): Record<string, Finding[]> {
    const groups: Record<string, Finding[]> = {};
    for (const finding of findings) {
      if (!groups[finding.category]) {
        groups[finding.category] = [];
      }
      groups[finding.category].push(finding);
    }
    return groups;
  }

  recalculateAfterDedup(finding: Finding, duplicateCount: number): Finding {
    // Increase confidence when multiple sources report the same issue
    const confidenceBoost = Math.min(duplicateCount * 0.05, 0.2);
    const newConfidence = Math.min(finding.confidence + confidenceBoost, 1.0);

    // Recalculate risk score
    const severityWeight = SEVERITY_WEIGHTS[finding.severity] / 4;
    const newRiskScore = severityWeight * 0.3 + finding.exploitability * 0.4 + newConfidence * 0.3;

    return {
      ...finding,
      confidence: Math.round(newConfidence * 100) / 100,
      riskScore: Math.round(newRiskScore * 100) / 100,
      duplicateCount,
    };
  }
}
