import { Finding, Severity, EndpointContext } from "./finding.js";
import { RawFinding } from "./raw.finding.js";

/**
 * The risk engine does exactly one job: turn a RawFinding into a normalised
 * Finding with a source confidence attached.
 *
 * It deliberately does NOT compute a risk score. There is a single scoring
 * model in this codebase and it lives in AttackAnalyzer. Having two engines
 * that both wrote a number called "risk" was the source of contradictory
 * reports, so the second one is gone.
 */

export interface Remediation {
  priority: "immediate" | "high" | "medium" | "low";
  action: string;
  details: string;
  effort: "minimal" | "moderate" | "significant";
}

// =============================================================================
// Source Confidence
//
// How much do we trust that this source correctly identified what it claims?
// This is about detector reliability, not about severity or exploitability.
// =============================================================================

const SOURCE_CONFIDENCE: Record<string, number> = {
  // Package version comparison against a vulnerability database. Very reliable
  // at answering "is this version affected", which is all it claims.
  "Trivy Static": 0.95,

  // Active HTTP probing. Reliable for what it observed, but ZAP's passive rules
  // produce a lot of low-signal alerts, so this is deliberately not 1.0.
  "OWASP ZAP API": 0.75,

  // LLM-generated tests. The payload is context-aware, but the model can also
  // mislabel what it is testing, so confidence starts moderate and only rises
  // when the response carries actual proof.
  "AI Security Tester": 0.65,
};

const DEFAULT_SOURCE_CONFIDENCE = 0.6;

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
  "Server-Side Request Forgery (SSRF)": {
    priority: "high",
    action: "Allowlist outbound request destinations",
    details:
      "Never fetch attacker-supplied URLs directly. Resolve and validate the destination host, block link-local and private ranges, and disable redirects.",
    effort: "moderate",
  },
  "Mass Assignment": {
    priority: "high",
    action: "Bind request bodies through an explicit field allowlist",
    details:
      "Never pass a request body straight into a model constructor or update call. Enumerate the fields a caller may set.",
    effort: "minimal",
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
    priority: "low",
    action: "Review and harden security configuration",
    details:
      "Add security headers (CSP, X-Frame-Options, etc). Disable unnecessary features. Keep software updated. These are defence in depth, not exploitable on their own.",
    effort: "minimal",
  },
  CSRF: {
    priority: "medium",
    action: "Implement CSRF tokens on state-changing operations",
    details:
      "Use synchronizer token pattern. Verify Origin/Referer headers. Use SameSite cookie attribute.",
    effort: "moderate",
  },
  "Dependency Vulnerability": {
    priority: "medium",
    action: "Update vulnerable dependencies",
    details:
      "Run dependency audit regularly. Use automated dependency updates. Review transitive dependencies.",
    effort: "minimal",
  },
  "OS Package Vulnerability": {
    priority: "medium",
    action: "Update system packages to patched versions",
    details:
      "Apply security updates regularly. Use automated patch management. Consider container image rebuilds.",
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
  /**
   * Confidence that the detector correctly identified what it reports.
   *
   * Evidence length is deliberately NOT used here. A long response body says
   * nothing about whether the detector was right, and using it as a proxy for
   * confidence inflated scores for verbose APIs.
   */
  calculateConfidence(raw: RawFinding): number {
    let confidence = SOURCE_CONFIDENCE[raw.source] ?? DEFAULT_SOURCE_CONFIDENCE;

    // Positive exploitation proof means the detector demonstrably found a real
    // issue, whatever else it got wrong.
    if (raw.proofs && raw.proofs.length > 0) {
      confidence = Math.max(confidence, 0.9);
      if (raw.proofs.length > 1) {
        confidence = Math.min(confidence + 0.05, 1.0);
      }
    }

    // A CVE identifier means the vulnerability itself is a matter of public
    // record. That raises confidence in the finding, not in its exploitability.
    if (raw.cve) {
      confidence = Math.min(confidence + 0.05, 1.0);
    }

    return Math.round(confidence * 100) / 100;
  }

  /**
   * Get remediation guidance for a finding.
   */
  getRemediation(finding: Finding): Remediation {
    let remediation = REMEDIATION_TEMPLATES[finding.category];

    if (!remediation) {
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
      remediation.priority = finding.proofs.length > 0 ? "immediate" : "medium";
    }

    return remediation;
  }

  /**
   * Derive endpoint context used by reachability scoring.
   */
  parseEndpointContext(endpoint?: string): EndpointContext | undefined {
    if (!endpoint) return undefined;

    const parts = endpoint.split(" ");
    const method = parts[0]?.toUpperCase();
    const path = parts[1] || endpoint;

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

    // Path-based heuristic. This is a weak signal and is documented as such;
    // it is not reachability analysis.
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

  mapSeverity(hint?: string): Severity {
    const upper = hint?.toUpperCase();
    if (upper === "CRITICAL") return "CRITICAL";
    if (upper === "HIGH") return "HIGH";
    if (upper === "MEDIUM") return "MEDIUM";
    return "LOW";
  }

  /**
   * Multiple independent sources reporting the same issue raises confidence
   * that the detection is correct.
   */
  recalculateAfterDedup(finding: Finding, duplicateCount: number): Finding {
    const confidenceBoost = Math.min(duplicateCount * 0.05, 0.2);
    const newConfidence = Math.min(finding.confidence + confidenceBoost, 1.0);

    return {
      ...finding,
      confidence: Math.round(newConfidence * 100) / 100,
      duplicateCount,
    };
  }
}
