import { Finding, EndpointContext } from "./finding.js";

// =============================================================================
// Attack Feasibility Analysis
// =============================================================================
// This module determines whether an attacker can ACTUALLY compromise the system.
// Key distinction:
// - Vulnerability = theoretical weakness (from static analysis, CVE databases)
// - Confirmed Exploit = PROVEN breach capability (AI/dynamic testing succeeded)
//
// A confirmed exploit is not a "high-scoring finding" - it's proof of breach.
// The system should fail immediately when exploitation is demonstrated.

export type BreachType =
  | "remote_code_execution"  // Attacker can execute arbitrary code
  | "data_exfiltration"      // Attacker can steal sensitive data
  | "privilege_escalation"   // Attacker can gain elevated access
  | "authentication_bypass"  // Attacker can bypass auth entirely
  | "none";                  // No confirmed breach

export interface ConfirmedBreach {
  type: BreachType;
  endpoint: string;
  capability: string;        // Human-readable: "Unauthenticated remote command execution"
  finding: Finding;
  evidence: string;
}

export interface AttackVector {
  endpoint: string;
  findings: Finding[];
  reachability: number;      // 0-1: Can attacker access this?
  exploitability: number;    // 0-1: Is exploit demonstrated?
  impact: number;            // 0-1: What damage is possible?
  confidence: number;        // 0-1: How strong is evidence?
  feasibilityScore: number;  // Multiplicative: reach × exploit × impact × conf
  attackChain?: string[];    // Potential attack sequence
  isConfirmed: boolean;      // AI/dynamic exploitation succeeded
}

export interface EndpointCorrelation {
  endpoint: string;
  method?: string;
  path?: string;
  findings: Finding[];
  attackVectors: AttackVector[];
  combinedRisk: number;
  attackChains: AttackChain[];
}

export interface AttackChain {
  name: string;
  steps: string[];
  likelihood: "high" | "medium" | "low";
  impact: "critical" | "high" | "medium" | "low";
}

// INCONCLUSIVE = scan failed, cannot determine security status
export type DeploymentVerdict = "SAFE" | "UNSAFE" | "REVIEW_REQUIRED" | "INCONCLUSIVE";

export interface SecurityVerdict {
  verdict: DeploymentVerdict;
  reason: string;
  breaches: ConfirmedBreach[];           // Proven attack capabilities
  operationalConclusion: string;         // E.g., "Unauthenticated RCE is possible"
  criticalFindings: Finding[];           // High-risk but unconfirmed
  confirmedExploits: Finding[];          // Backward compat - findings that were exploited
  attackChains: AttackChain[];
  recommendations: ContextualRemediation[];
  scanIncomplete?: boolean;              // True if scanners failed
  failedScanners?: string[];             // Which scanners failed
}

export interface ContextualRemediation {
  finding: Finding;
  endpoint: string;
  specificFix: string;
  codeExample?: string;
  priority: "immediate" | "high" | "medium" | "low";
}

// =============================================================================
// Impact Scores by Category
// =============================================================================

const IMPACT_SCORES: Record<string, number> = {
  // Critical - Full system compromise
  "Remote Code Execution": 1.0,
  "Command Injection": 1.0,
  "SQL Injection": 0.95,

  // High - Significant data/access compromise
  "Path Traversal": 0.85,
  "Broken Access Control": 0.85,
  "Broken Authentication": 0.85,
  "Sensitive Data Exposure": 0.8,
  "Cross-Site Scripting (XSS)": 0.75,
  "XSS": 0.75,

  // Medium - Limited compromise
  "CSRF": 0.6,
  "Information Disclosure": 0.5,
  "Security Misconfiguration": 0.45,
  "Hardcoded Secret": 0.7,

  // Lower - Minimal direct impact
  "Missing Security Header": 0.25,
  "TLS/SSL Issue": 0.35,
  "Dependency Vulnerability": 0.5,
  "Container Vulnerability": 0.45,
};

// =============================================================================
// Attack Analyzer
// =============================================================================

export class AttackAnalyzer {
  /**
   * Correlate findings by endpoint to understand attack surface
   */
  correlateByEndpoint(findings: Finding[]): EndpointCorrelation[] {
    const byEndpoint = new Map<string, Finding[]>();

    // Group findings by normalized endpoint
    for (const finding of findings) {
      const key = this.normalizeEndpoint(finding.endpoint);
      const existing = byEndpoint.get(key) || [];
      existing.push(finding);
      byEndpoint.set(key, existing);
    }

    // Create correlations with attack analysis
    const correlations: EndpointCorrelation[] = [];

    for (const [endpoint, endpointFindings] of byEndpoint) {
      const attackVectors = endpointFindings.map(f => this.analyzeAttackVector(f));
      const attackChains = this.identifyAttackChains(endpointFindings);
      const combinedRisk = this.calculateCombinedRisk(attackVectors);

      // Parse endpoint parts
      const parts = endpoint.split(" ");
      const method = parts.length > 1 ? parts[0] : undefined;
      const path = parts.length > 1 ? parts[1] : endpoint;

      correlations.push({
        endpoint,
        method,
        path,
        findings: endpointFindings,
        attackVectors,
        combinedRisk,
        attackChains,
      });
    }

    // Sort by combined risk
    return correlations.sort((a, b) => b.combinedRisk - a.combinedRisk);
  }

  /**
   * Analyze a single finding as an attack vector
   */
  private analyzeAttackVector(finding: Finding): AttackVector {
    const reachability = this.calculateReachability(finding);
    const exploitability = this.calculateExploitability(finding);
    const impact = this.calculateImpact(finding);
    const confidence = this.calculateConfidence(finding);
    const isConfirmed = this.isExploitConfirmed(finding);

    // Multiplicative score - all factors must be present for high risk
    let feasibilityScore = reachability * exploitability * impact * confidence;

    // Confirmed exploits get boosted to ensure they're prioritized
    if (isConfirmed) {
      feasibilityScore = Math.max(feasibilityScore, 0.8);
    }

    return {
      endpoint: finding.endpoint || "unknown",
      findings: [finding],
      reachability,
      exploitability,
      impact,
      confidence,
      feasibilityScore: Math.round(feasibilityScore * 100) / 100,
      isConfirmed,
      attackChain: this.getAttackChainForFinding(finding),
    };
  }

  /**
   * Calculate reachability - can an attacker access this?
   */
  private calculateReachability(finding: Finding): number {
    const ctx = finding.endpointContext;

    // No endpoint = likely internal/static finding
    if (!finding.endpoint) {
      return 0.4;
    }

    let score = 0.7; // Base score for any endpoint

    if (ctx) {
      // Public endpoints are more reachable
      if (!ctx.requiresAuth) {
        score += 0.2;
      }

      // Endpoints accepting user input are attack entry points
      if (ctx.acceptsUserInput) {
        score += 0.1;
      }
    }

    // API endpoints are typically exposed
    if (finding.endpoint.includes("/api/")) {
      score += 0.1;
    }

    // Admin/internal endpoints may be protected
    if (finding.endpoint.includes("/admin") || finding.endpoint.includes("/internal")) {
      score -= 0.2;
    }

    return Math.min(Math.max(score, 0), 1);
  }

  /**
   * Calculate exploitability - is exploitation demonstrated?
   */
  private calculateExploitability(finding: Finding): number {
    let score = 0.5; // Base score

    // AI-confirmed exploitation is strongest signal
    if (finding.sources.includes("AI Security Tester")) {
      // AI actually tested and found exploitable
      score = 0.85;

      // Check evidence for successful exploitation markers
      if (finding.evidence) {
        const evidence = finding.evidence.toLowerCase();
        if (evidence.includes("response status: 200") ||
            evidence.includes("matched:") ||
            evidence.includes("vulnerable")) {
          score = 0.95;
        }
      }
    }

    // ZAP dynamic testing demonstrates exploitability
    if (finding.sources.includes("OWASP ZAP API")) {
      score = Math.max(score, 0.75);
    }

    // CVE with known exploits
    if (finding.cve) {
      score = Math.max(score, 0.7);
    }

    // Static findings are theoretical
    if (finding.sources.includes("Trivy Static") || finding.sources.includes("Trivy Image")) {
      score = Math.min(score, 0.5);
    }

    return score;
  }

  /**
   * Calculate impact - what can attacker do?
   */
  private calculateImpact(finding: Finding): number {
    // Direct category match
    if (IMPACT_SCORES[finding.category]) {
      return IMPACT_SCORES[finding.category];
    }

    // Partial match
    const category = finding.category.toLowerCase();
    for (const [key, value] of Object.entries(IMPACT_SCORES)) {
      if (category.includes(key.toLowerCase()) || key.toLowerCase().includes(category)) {
        return value;
      }
    }

    // Check for high-impact keywords in description
    const text = (finding.title + finding.category).toLowerCase();
    if (text.includes("command") || text.includes("rce") || text.includes("execute")) {
      return 1.0;
    }
    if (text.includes("sql") || text.includes("injection")) {
      return 0.95;
    }
    if (text.includes("auth") || text.includes("access") || text.includes("bypass")) {
      return 0.85;
    }

    return 0.5; // Default moderate impact
  }

  /**
   * Calculate confidence - how strong is the evidence?
   */
  private calculateConfidence(finding: Finding): number {
    let score = finding.confidence; // Use existing confidence

    // Multiple sources increase confidence
    if (finding.sources.length > 1) {
      score = Math.min(score + 0.15, 1.0);
    }

    // Deduplicated findings are more reliable
    if (finding.deduplicated && finding.duplicateCount > 0) {
      score = Math.min(score + finding.duplicateCount * 0.05, 1.0);
    }

    // Strong evidence boosts confidence
    if (finding.evidence && finding.evidence.length > 100) {
      score = Math.min(score + 0.1, 1.0);
    }

    return score;
  }

  /**
   * Check if exploitation was confirmed (not just detected)
   */
  private isExploitConfirmed(finding: Finding): boolean {
    // AI successfully exploited
    if (finding.sources.includes("AI Security Tester")) {
      if (finding.evidence) {
        const evidence = finding.evidence.toLowerCase();
        return evidence.includes("response status:") &&
               (evidence.includes("matched:") || evidence.includes("vulnerable"));
      }
      return true; // AI findings are from successful tests
    }

    // ZAP active scan confirmed
    if (finding.sources.includes("OWASP ZAP API")) {
      return true;
    }

    return false;
  }

  /**
   * Identify potential attack chains from correlated findings
   */
  private identifyAttackChains(findings: Finding[]): AttackChain[] {
    const chains: AttackChain[] = [];
    const categories = findings.map(f => f.category.toLowerCase());

    // Auth bypass → Data access chain
    if ((categories.some(c => c.includes("auth") || c.includes("access"))) &&
        (categories.some(c => c.includes("data") || c.includes("exposure") || c.includes("disclosure")))) {
      chains.push({
        name: "Authentication Bypass → Data Exfiltration",
        steps: [
          "Bypass authentication/authorization",
          "Access sensitive data endpoints",
          "Exfiltrate user/system data"
        ],
        likelihood: "high",
        impact: "critical",
      });
    }

    // Injection → RCE chain
    if (categories.some(c => c.includes("injection") || c.includes("sql"))) {
      chains.push({
        name: "Injection → System Compromise",
        steps: [
          "Inject malicious payload",
          "Execute arbitrary commands",
          "Establish persistence/exfiltrate data"
        ],
        likelihood: "high",
        impact: "critical",
      });
    }

    // IDOR → Data breach chain
    if (categories.some(c => c.includes("access") || c.includes("idor"))) {
      chains.push({
        name: "IDOR → Data Breach",
        steps: [
          "Enumerate resource IDs",
          "Access unauthorized resources",
          "Collect sensitive information"
        ],
        likelihood: "high",
        impact: "high",
      });
    }

    // XSS → Account takeover chain
    if (categories.some(c => c.includes("xss") || c.includes("script"))) {
      chains.push({
        name: "XSS → Session Hijacking",
        steps: [
          "Inject malicious script",
          "Steal session cookies",
          "Impersonate legitimate users"
        ],
        likelihood: "medium",
        impact: "high",
      });
    }

    // Command injection → Full compromise
    if (categories.some(c => c.includes("command") || c.includes("execute"))) {
      chains.push({
        name: "Command Injection → Full System Compromise",
        steps: [
          "Inject shell commands",
          "Execute with server privileges",
          "Pivot to internal systems"
        ],
        likelihood: "high",
        impact: "critical",
      });
    }

    return chains;
  }

  /**
   * Get attack chain description for a single finding
   */
  private getAttackChainForFinding(finding: Finding): string[] | undefined {
    const category = finding.category.toLowerCase();

    if (category.includes("sql injection")) {
      return ["Inject SQL payload", "Dump database", "Extract credentials"];
    }
    if (category.includes("command")) {
      return ["Inject command", "Execute on server", "Establish backdoor"];
    }
    if (category.includes("xss")) {
      return ["Inject script", "Steal session", "Hijack account"];
    }
    if (category.includes("path traversal")) {
      return ["Traverse directories", "Read sensitive files", "Extract secrets"];
    }
    if (category.includes("auth") || category.includes("access")) {
      return ["Bypass auth", "Access restricted data", "Elevate privileges"];
    }

    return undefined;
  }

  /**
   * Calculate combined risk for an endpoint
   */
  private calculateCombinedRisk(vectors: AttackVector[]): number {
    if (vectors.length === 0) return 0;

    // Take the highest feasibility score
    const maxFeasibility = Math.max(...vectors.map(v => v.feasibilityScore));

    // Boost if multiple attack vectors exist
    const vectorBonus = Math.min((vectors.length - 1) * 0.05, 0.15);

    // Boost if any exploit is confirmed
    const confirmedBonus = vectors.some(v => v.isConfirmed) ? 0.1 : 0;

    return Math.min(maxFeasibility + vectorBonus + confirmedBonus, 1.0);
  }

  /**
   * Analyze confirmed breaches - not vulnerabilities, but proven attack capabilities
   */
  private analyzeBreaches(findings: Finding[]): ConfirmedBreach[] {
    const breaches: ConfirmedBreach[] = [];

    for (const finding of findings) {
      if (!this.isExploitConfirmed(finding)) continue;

      const breach = this.classifyBreach(finding);
      if (breach.type !== "none") {
        breaches.push(breach);
      }
    }

    return breaches;
  }

  /**
   * Classify a confirmed exploit into a breach type with operational meaning
   */
  private classifyBreach(finding: Finding): ConfirmedBreach {
    const category = finding.category.toLowerCase();
    const endpoint = finding.endpoint || "application";
    const ctx = finding.endpointContext;
    const isUnauthenticated = !ctx?.requiresAuth;
    const authPrefix = isUnauthenticated ? "Unauthenticated " : "";

    // Command Injection / RCE
    if (category.includes("command") || category.includes("rce") || category.includes("execute")) {
      return {
        type: "remote_code_execution",
        endpoint,
        capability: `${authPrefix}remote command execution on ${endpoint}`,
        finding,
        evidence: finding.evidence,
      };
    }

    // SQL Injection
    if (category.includes("sql") || category.includes("injection")) {
      return {
        type: "data_exfiltration",
        endpoint,
        capability: `${authPrefix}database access via SQL injection on ${endpoint}`,
        finding,
        evidence: finding.evidence,
      };
    }

    // Path Traversal / File Read
    if (category.includes("path") || category.includes("traversal") || category.includes("file")) {
      return {
        type: "data_exfiltration",
        endpoint,
        capability: `${authPrefix}arbitrary file read via ${endpoint}`,
        finding,
        evidence: finding.evidence,
      };
    }

    // Authentication Bypass
    if (category.includes("auth") && (category.includes("bypass") || category.includes("broken"))) {
      return {
        type: "authentication_bypass",
        endpoint,
        capability: `Authentication bypass on ${endpoint}`,
        finding,
        evidence: finding.evidence,
      };
    }

    // Access Control / IDOR
    if (category.includes("access") || category.includes("idor")) {
      return {
        type: "privilege_escalation",
        endpoint,
        capability: `Unauthorized data access via ${endpoint}`,
        finding,
        evidence: finding.evidence,
      };
    }

    // Sensitive Data Exposure (if confirmed by dynamic testing)
    if (category.includes("sensitive") || category.includes("exposure") || category.includes("disclosure")) {
      return {
        type: "data_exfiltration",
        endpoint,
        capability: `Sensitive data leak from ${endpoint}`,
        finding,
        evidence: finding.evidence,
      };
    }

    return { type: "none", endpoint, capability: "", finding, evidence: "" };
  }

  /**
   * Generate deployment verdict with scan status awareness
   * CRITICAL: If scanners failed, verdict is INCONCLUSIVE (not SAFE)
   */
  generateVerdictWithStatus(
    findings: Finding[],
    scanStatus: { isComplete: boolean; failedScanners: string[] }
  ): SecurityVerdict {
    // First check for scanner failures
    if (!scanStatus.isComplete && scanStatus.failedScanners.length > 0) {
      // SCAN FAILED ≠ NO VULNERABILITIES
      // We cannot claim safety if we didn't complete the scan
      return {
        verdict: "INCONCLUSIVE",
        reason: `Scan incomplete: ${scanStatus.failedScanners.join(", ")} failed. Cannot determine security status.`,
        breaches: [],
        operationalConclusion: "",
        criticalFindings: [],
        confirmedExploits: [],
        attackChains: [],
        recommendations: [],
        scanIncomplete: true,
        failedScanners: scanStatus.failedScanners,
      };
    }

    // Otherwise, use normal verdict logic
    return this.generateVerdict(findings);
  }

  /**
   * Generate deployment verdict - based on attacker capability, not vulnerability counts
   */
  generateVerdict(findings: Finding[]): SecurityVerdict {
    const correlations = this.correlateByEndpoint(findings);

    // STEP 1: Identify confirmed breaches (proof of attack success)
    const breaches = this.analyzeBreaches(findings);
    const confirmedExploits = findings.filter(f => this.isExploitConfirmed(f));

    // STEP 2: Determine operational conclusion
    let operationalConclusion = "";
    if (breaches.length > 0) {
      // Prioritize by severity
      const rce = breaches.find(b => b.type === "remote_code_execution");
      const dataLeak = breaches.find(b => b.type === "data_exfiltration");
      const authBypass = breaches.find(b => b.type === "authentication_bypass");
      const privEsc = breaches.find(b => b.type === "privilege_escalation");

      if (rce) {
        operationalConclusion = rce.capability;
      } else if (dataLeak) {
        operationalConclusion = dataLeak.capability;
      } else if (authBypass) {
        operationalConclusion = authBypass.capability;
      } else if (privEsc) {
        operationalConclusion = privEsc.capability;
      } else {
        operationalConclusion = breaches[0].capability;
      }
    }

    // STEP 3: Identify unconfirmed but high-risk findings (supporting evidence)
    const criticalFindings = findings.filter(f => {
      if (this.isExploitConfirmed(f)) return false; // Already in breaches
      const vector = this.analyzeAttackVector(f);
      return vector.feasibilityScore >= 0.6;
    });

    // Collect attack chains
    const allChains: AttackChain[] = [];
    for (const corr of correlations) {
      allChains.push(...corr.attackChains);
    }

    // Generate remediations - prioritize breaches
    const prioritizedFindings = [...confirmedExploits, ...criticalFindings];
    const recommendations = this.generateContextualRemediations(prioritizedFindings);

    // STEP 4: Determine verdict based on attacker capability
    let verdict: DeploymentVerdict;
    let reason: string;

    if (breaches.length > 0) {
      // Confirmed breach = FAIL. Not a high score, but proof of compromise.
      verdict = "UNSAFE";
      reason = operationalConclusion;
    } else if (criticalFindings.some(f => this.calculateImpact(f) >= 0.9)) {
      // Unconfirmed but high-impact (RCE-level) - still unsafe
      verdict = "UNSAFE";
      const types = [...new Set(criticalFindings.filter(f => this.calculateImpact(f) >= 0.9).map(f => f.category))];
      reason = `Critical vulnerability class detected: ${types.slice(0, 2).join(", ")}. Exploitation likely.`;
    } else if (criticalFindings.length > 0) {
      // Moderate risk - needs human review
      verdict = "REVIEW_REQUIRED";
      reason = `${criticalFindings.length} exploitable vulnerabilities detected. Security review required.`;
    } else if (findings.length > 0) {
      // Low-risk only - informational
      verdict = "SAFE";
      reason = `${findings.length} low-risk findings. No exploitable vulnerabilities detected.`;
    } else {
      verdict = "SAFE";
      reason = "No security vulnerabilities detected.";
    }

    return {
      verdict,
      reason,
      breaches,
      operationalConclusion,
      criticalFindings,
      confirmedExploits,
      attackChains: allChains,
      recommendations,
    };
  }

  /**
   * Generate contextual, specific remediation suggestions
   */
  private generateContextualRemediations(findings: Finding[]): ContextualRemediation[] {
    return findings.slice(0, 10).map(finding => {
      const specific = this.getSpecificRemediation(finding);
      return {
        finding,
        endpoint: finding.endpoint || "application-wide",
        specificFix: specific.fix,
        codeExample: specific.code,
        priority: this.getRemediationPriority(finding),
      };
    });
  }

  /**
   * Get specific remediation based on finding context
   */
  private getSpecificRemediation(finding: Finding): { fix: string; code?: string } {
    const category = finding.category.toLowerCase();
    const endpoint = finding.endpoint || "";
    const ctx = finding.endpointContext;

    // SQL Injection with endpoint context
    if (category.includes("sql")) {
      const param = this.extractParamFromEvidence(finding.evidence);
      return {
        fix: `Parameterize query on ${endpoint}${param ? ` for parameter '${param}'` : ""}`,
        code: `// Instead of:\ndb.query(\`SELECT * FROM users WHERE id = \${${param || "id"}}\`);\n\n// Use:\ndb.query('SELECT * FROM users WHERE id = ?', [${param || "id"}]);`,
      };
    }

    // Command Injection
    if (category.includes("command") || category.includes("execute")) {
      return {
        fix: `Remove shell execution on ${endpoint}. Use safe library functions instead.`,
        code: `// Instead of:\nexec(\`echo \${userInput}\`);\n\n// Use:\nconst { execFile } = require('child_process');\nexecFile('echo', [userInput]); // or avoid shell entirely`,
      };
    }

    // Path Traversal
    if (category.includes("path") || category.includes("traversal") || category.includes("file")) {
      return {
        fix: `Validate file paths on ${endpoint}. Ensure path resolves within allowed directory.`,
        code: `const path = require('path');\nconst safePath = path.normalize(userPath);\nif (!safePath.startsWith(ALLOWED_DIR)) {\n  throw new Error('Invalid path');\n}`,
      };
    }

    // Broken Access Control / IDOR
    if (category.includes("access") || category.includes("idor") || category.includes("auth")) {
      return {
        fix: `Enforce ownership check on ${endpoint}. Verify resource belongs to authenticated user.`,
        code: `// Add authorization check:\nif (resource.userId !== req.user.id) {\n  return res.status(403).json({ error: 'Forbidden' });\n}`,
      };
    }

    // XSS
    if (category.includes("xss") || category.includes("script")) {
      return {
        fix: `Encode output on ${endpoint}. Implement Content-Security-Policy header.`,
        code: `// Encode before rendering:\nconst escaped = escapeHtml(userInput);\n\n// Add CSP header:\nres.setHeader('Content-Security-Policy', "default-src 'self'");`,
      };
    }

    // Information Disclosure
    if (category.includes("disclosure") || category.includes("debug") || category.includes("info")) {
      return {
        fix: `Remove or protect ${endpoint}. Disable verbose errors in production.`,
        code: `// Remove debug endpoint in production:\nif (process.env.NODE_ENV === 'production') {\n  // Don't register debug routes\n}\n\n// Sanitize error responses:\nres.status(500).json({ error: 'Internal server error' });`,
      };
    }

    // Sensitive Data Exposure
    if (category.includes("sensitive") || category.includes("exposure")) {
      return {
        fix: `Mask sensitive data in ${endpoint} response. Never return passwords/tokens.`,
        code: `// Sanitize response:\nconst sanitized = {\n  ...user,\n  password: undefined,\n  apiKey: undefined,\n};`,
      };
    }

    // Dependency vulnerability
    if (category.includes("dependency") || category.includes("vulnerability")) {
      const pkg = finding.package || "affected package";
      const fixed = finding.fixedVersion;
      return {
        fix: `Update ${pkg}${fixed ? ` to version ${fixed}` : " to latest secure version"}.`,
        code: fixed ? `npm install ${pkg}@${fixed}` : `npm update ${pkg}`,
      };
    }

    // Default
    return {
      fix: `Review and address ${finding.category} on ${endpoint || "affected component"}.`,
    };
  }

  /**
   * Extract parameter name from evidence if available
   */
  private extractParamFromEvidence(evidence?: string): string | undefined {
    if (!evidence) return undefined;

    // Look for common patterns
    const patterns = [
      /param(?:eter)?[:\s]+['"]?(\w+)/i,
      /(\w+)\s*=\s*['"]?[^'"]+/,
      /input[:\s]+['"]?(\w+)/i,
    ];

    for (const pattern of patterns) {
      const match = evidence.match(pattern);
      if (match) return match[1];
    }

    return undefined;
  }

  /**
   * Determine remediation priority based on attack feasibility
   */
  private getRemediationPriority(finding: Finding): "immediate" | "high" | "medium" | "low" {
    const vector = this.analyzeAttackVector(finding);

    if (vector.isConfirmed) return "immediate";
    if (vector.feasibilityScore >= 0.7) return "immediate";
    if (vector.feasibilityScore >= 0.5) return "high";
    if (vector.feasibilityScore >= 0.3) return "medium";
    return "low";
  }

  /**
   * Normalize endpoint for grouping
   */
  private normalizeEndpoint(endpoint?: string): string {
    if (!endpoint) return "no-endpoint";

    // Normalize path parameters
    let normalized = endpoint
      .replace(/\/\d+/g, "/:id")
      .replace(/\/[a-f0-9-]{36}/gi, "/:uuid")
      .replace(/\?.*/g, ""); // Remove query string

    return normalized;
  }
}
