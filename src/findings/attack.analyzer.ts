import { Finding, ExploitProof } from "./finding.js";
import { exploitabilityFromIntel } from "../intel/exploit.intel.js";

// =============================================================================
// Attack Feasibility Analysis
// =============================================================================
//
// This module answers one question: can an attacker actually compromise this
// system right now?
//
// The single most important rule in this file:
//
//   CONFIRMED means a scanner observed positive proof of exploitation in a
//   response. It NEVER means "this finding came from an active scanner".
//
// The previous implementation treated the source label as proof, so a passive
// alert from ZAP and a header miss from an LLM test both became "confirmed
// exploits" and blocked deploys. Confirmation now requires a Finding to carry
// an ExploitProof that a scanner explicitly attached after seeing the evidence.
//
// The second rule: the feasibility formula has no floors and no bonuses. If a
// score comes out low, that is the model telling you something. Patching the
// output with Math.max was how the old model hid its own disagreements.

export type BreachType =
  | "remote_code_execution"
  | "data_exfiltration"
  | "privilege_escalation"
  | "authentication_bypass"
  | "session_hijacking"
  | "none";

export interface ConfirmedBreach {
  type: BreachType;
  endpoint: string;
  capability: string;
  finding: Finding;
  evidence: string;
  /** The exact response substring that proves this, for fast verification. */
  proofExcerpt?: string;
  proofs: ExploitProof[];
}

export interface AttackVector {
  endpoint: string;
  findings: Finding[];
  reachability: number;
  exploitability: number;
  impact: number;
  confidence: number;
  /** Multiplicative: reachability x exploitability x impact x confidence */
  feasibilityScore: number;
  attackChain?: string[];
  isConfirmed: boolean;
  /** Where the exploitability number came from, for the explain view. */
  exploitabilityBasis: "kev" | "epss" | "proof" | "category";
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

export type DeploymentVerdict = "SAFE" | "UNSAFE" | "REVIEW_REQUIRED" | "INCONCLUSIVE";

export interface SecurityVerdict {
  verdict: DeploymentVerdict;
  reason: string;
  breaches: ConfirmedBreach[];
  operationalConclusion: string;
  criticalFindings: Finding[];
  confirmedExploits: Finding[];
  attackChains: AttackChain[];
  recommendations: ContextualRemediation[];
  scanIncomplete?: boolean;
  failedScanners?: string[];
}

export interface ContextualRemediation {
  finding: Finding;
  endpoint: string;
  specificFix: string;
  codeExample?: string;
  priority: "immediate" | "high" | "medium" | "low";
}

// =============================================================================
// Thresholds
// =============================================================================

/**
 * Feasibility at or above this, without proof, means a human should look.
 * Deliberately not a deploy blocker: unproven findings do not block.
 */
export const REVIEW_THRESHOLD = 0.35;

// =============================================================================
// Impact Scores by Category
//
// "If this were exploited, how bad is it?" Impact is a property of the
// vulnerability class, so a lookup table is the honest representation. It is
// exploitability, not impact, that must come from real-world data.
// =============================================================================

const IMPACT_SCORES: Record<string, number> = {
  // Full system compromise
  "Remote Code Execution": 1.0,
  "Command Injection": 1.0,
  "Code Injection": 0.95,
  "SQL Injection": 0.95,

  // Significant data or access compromise
  "Path Traversal": 0.85,
  "Broken Access Control": 0.85,
  "Broken Authentication": 0.85,
  "Broken Authentication (JWT)": 0.9,
  "Server-Side Request Forgery (SSRF)": 0.8,
  "Sensitive Data Exposure": 0.8,
  "Mass Assignment": 0.75,
  "Cross-Site Scripting (XSS)": 0.75,
  XSS: 0.75,

  // Limited compromise
  CSRF: 0.6,
  "Information Disclosure": 0.5,
  "Dependency Vulnerability": 0.5,
  "OS Package Vulnerability": 0.45,
  "Security Misconfiguration": 0.3,

  // Defence in depth only. Not exploitable on their own, and scoring them
  // higher than this is what made header checks look like breaches.
  "Missing Security Header": 0.15,
  "TLS/SSL Issue": 0.35,
};

/**
 * Exploitability when we have neither exploit intelligence nor proof.
 *
 * These are deliberately low. An unproven finding on a running API is a
 * hypothesis, and the scoring model should say so rather than assume the
 * worst. Findings that matter will be confirmed by proof or by KEV/EPSS.
 */
const UNPROVEN_EXPLOITABILITY: Record<string, number> = {
  "Remote Code Execution": 0.5,
  "Command Injection": 0.5,
  "SQL Injection": 0.5,
  "Path Traversal": 0.45,
  "Broken Access Control": 0.4,
  "Broken Authentication": 0.4,
  "Server-Side Request Forgery (SSRF)": 0.4,
  "Cross-Site Scripting (XSS)": 0.35,
  XSS: 0.35,
  "Mass Assignment": 0.35,
  CSRF: 0.25,
  "Information Disclosure": 0.25,
  "Security Misconfiguration": 0.15,
  "Missing Security Header": 0.1,
};

const DEFAULT_UNPROVEN_EXPLOITABILITY = 0.3;

/** Exploitability when a scanner observed real proof of exploitation. */
const PROVEN_EXPLOITABILITY = 0.95;

// =============================================================================
// Attack Analyzer
// =============================================================================

export class AttackAnalyzer {
  /**
   * Group findings by endpoint so multi-finding attack surfaces are visible.
   */
  correlateByEndpoint(findings: Finding[]): EndpointCorrelation[] {
    const byEndpoint = new Map<string, Finding[]>();

    for (const finding of findings) {
      const key = this.normalizeEndpoint(finding.endpoint);
      const existing = byEndpoint.get(key) || [];
      existing.push(finding);
      byEndpoint.set(key, existing);
    }

    const correlations: EndpointCorrelation[] = [];

    for (const [endpoint, endpointFindings] of byEndpoint.entries()) {
      const attackVectors = endpointFindings.map((f) => this.analyzeAttackVector(f));
      const attackChains = this.identifyAttackChains(endpointFindings);
      const combinedRisk = this.calculateCombinedRisk(attackVectors);

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

    return correlations.sort((a, b) => b.combinedRisk - a.combinedRisk);
  }

  /**
   * Score a single finding as an attack vector.
   *
   * feasibility = reachability x exploitability x impact x confidence
   *
   * No floors. No bonuses. If you disagree with a score, fix a factor.
   */
  analyzeAttackVector(finding: Finding): AttackVector {
    const reachability = this.calculateReachability(finding);
    const { value: exploitability, basis } = this.calculateExploitability(finding);
    const impact = this.calculateImpact(finding);
    const confidence = finding.confidence;
    const isConfirmed = this.isExploitConfirmed(finding);

    const feasibilityScore = reachability * exploitability * impact * confidence;

    return {
      endpoint: finding.endpoint || "unknown",
      findings: [finding],
      reachability,
      exploitability,
      impact,
      confidence,
      feasibilityScore: Math.round(feasibilityScore * 100) / 100,
      isConfirmed,
      exploitabilityBasis: basis,
      attackChain: this.getAttackChainForFinding(finding),
    };
  }

  /**
   * Can an attacker reach this?
   *
   * This is a path and auth heuristic, not call-graph reachability analysis.
   * It is named honestly in the docs and should not be described as more.
   */
  private calculateReachability(finding: Finding): number {
    // No endpoint means a repository-level finding: real, but not directly
    // addressable over the network.
    if (!finding.endpoint) {
      return 0.4;
    }

    let score = 0.7;
    const ctx = finding.endpointContext;

    if (ctx) {
      if (!ctx.requiresAuth) score += 0.2;
      if (ctx.acceptsUserInput) score += 0.1;
    }

    if (finding.endpoint.includes("/admin") || finding.endpoint.includes("/internal")) {
      score -= 0.2;
    }

    return Math.min(Math.max(score, 0), 1);
  }

  /**
   * How likely is exploitation?
   *
   * Priority order, best evidence first:
   *   1. CISA KEV       - confirmed exploitation in the wild
   *   2. Proof          - we exploited it ourselves during this scan
   *   3. EPSS           - modelled 30-day exploitation probability
   *   4. Category table - a guess, and treated as one
   */
  private calculateExploitability(finding: Finding): {
    value: number;
    basis: AttackVector["exploitabilityBasis"];
  } {
    if (finding.knownExploited) {
      return { value: exploitabilityFromIntel(finding) ?? 0.95, basis: "kev" };
    }

    if (this.isExploitConfirmed(finding)) {
      return { value: PROVEN_EXPLOITABILITY, basis: "proof" };
    }

    const intel = exploitabilityFromIntel(finding);
    if (intel !== undefined) {
      return { value: intel, basis: "epss" };
    }

    return { value: this.categoryExploitability(finding.category), basis: "category" };
  }

  private categoryExploitability(category: string): number {
    if (UNPROVEN_EXPLOITABILITY[category] !== undefined) {
      return UNPROVEN_EXPLOITABILITY[category];
    }

    const lower = category.toLowerCase();
    for (const [key, value] of Object.entries(UNPROVEN_EXPLOITABILITY)) {
      if (lower.includes(key.toLowerCase()) || key.toLowerCase().includes(lower)) {
        return value;
      }
    }

    return DEFAULT_UNPROVEN_EXPLOITABILITY;
  }

  private calculateImpact(finding: Finding): number {
    if (IMPACT_SCORES[finding.category] !== undefined) {
      return IMPACT_SCORES[finding.category];
    }

    const category = finding.category.toLowerCase();
    for (const [key, value] of Object.entries(IMPACT_SCORES)) {
      if (category.includes(key.toLowerCase()) || key.toLowerCase().includes(category)) {
        return value;
      }
    }

    return 0.5;
  }

  /**
   * Was exploitation actually demonstrated?
   *
   * The entire answer is: did a scanner attach positive proof? Scanner
   * identity, evidence string shape, and severity label are all irrelevant
   * here, and treating any of them as proof is what produced fabricated
   * breach reports.
   */
  isExploitConfirmed(finding: Finding): boolean {
    return finding.proofs.length > 0;
  }

  /**
   * Identify multi-step attack paths across findings on the same endpoint.
   * Only proven findings can participate: a chain built from two hypotheses
   * is a story, not a threat.
   */
  private identifyAttackChains(findings: Finding[]): AttackChain[] {
    const chains: AttackChain[] = [];
    const confirmed = findings.filter((f) => this.isExploitConfirmed(f));
    if (confirmed.length === 0) {
      return chains;
    }

    const categories = confirmed.map((f) => f.category.toLowerCase());

    if (
      categories.some((c) => c.includes("auth") || c.includes("access")) &&
      categories.some(
        (c) => c.includes("data") || c.includes("exposure") || c.includes("disclosure")
      )
    ) {
      chains.push({
        name: "Authentication Bypass to Data Exfiltration",
        steps: [
          "Bypass authentication or authorization",
          "Access sensitive data endpoints",
          "Exfiltrate user or system data",
        ],
        likelihood: "high",
        impact: "critical",
      });
    }

    if (categories.some((c) => c.includes("command") || c.includes("execute"))) {
      chains.push({
        name: "Command Injection to Full System Compromise",
        steps: [
          "Inject shell commands",
          "Execute with server privileges",
          "Pivot to internal systems",
        ],
        likelihood: "high",
        impact: "critical",
      });
    } else if (categories.some((c) => c.includes("injection") || c.includes("sql"))) {
      chains.push({
        name: "Injection to System Compromise",
        steps: [
          "Inject malicious payload",
          "Read or modify database contents",
          "Extract credentials and escalate",
        ],
        likelihood: "high",
        impact: "critical",
      });
    }

    if (categories.some((c) => c.includes("idor") || c.includes("access"))) {
      chains.push({
        name: "IDOR to Data Breach",
        steps: [
          "Enumerate resource identifiers",
          "Access unauthorized resources",
          "Collect sensitive information",
        ],
        likelihood: "high",
        impact: "high",
      });
    }

    if (categories.some((c) => c.includes("xss") || c.includes("cross-site scripting"))) {
      chains.push({
        name: "XSS to Session Hijacking",
        steps: ["Inject script payload", "Steal session credentials", "Impersonate the victim"],
        likelihood: "medium",
        impact: "high",
      });
    }

    return chains;
  }

  private getAttackChainForFinding(finding: Finding): string[] | undefined {
    if (!this.isExploitConfirmed(finding)) {
      return undefined;
    }

    const category = finding.category.toLowerCase();

    if (category.includes("sql")) {
      return ["Inject SQL payload", "Read database contents", "Extract credentials"];
    }
    if (category.includes("command") || category.includes("execute")) {
      return ["Inject command", "Execute on server", "Establish persistence"];
    }
    if (category.includes("ssrf") || category.includes("server-side request")) {
      return ["Supply internal URL", "Reach instance metadata", "Steal cloud credentials"];
    }
    if (category.includes("xss") || category.includes("cross-site scripting")) {
      return ["Inject script", "Steal session credentials", "Impersonate victim"];
    }
    if (category.includes("path") || category.includes("traversal")) {
      return ["Traverse directories", "Read sensitive files", "Extract secrets"];
    }
    if (category.includes("auth") || category.includes("access")) {
      return ["Bypass authorization", "Access restricted data", "Escalate privileges"];
    }

    return undefined;
  }

  private calculateCombinedRisk(vectors: AttackVector[]): number {
    if (vectors.length === 0) return 0;
    return Math.max(...vectors.map((v) => v.feasibilityScore));
  }

  /**
   * A breach is a proven attack capability, expressed in operational terms.
   * Only confirmed findings can produce one.
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

  private classifyBreach(finding: Finding): ConfirmedBreach {
    const category = finding.category.toLowerCase();
    const endpoint = finding.endpoint || "application";
    const ctx = finding.endpointContext;
    const isUnauthenticated = !ctx?.requiresAuth;
    const authPrefix = isUnauthenticated ? "Unauthenticated " : "";
    const base = {
      endpoint,
      finding,
      evidence: finding.evidence,
      proofExcerpt: finding.proofExcerpt,
      proofs: finding.proofs,
    };

    if (category.includes("command") || category.includes("rce") || category.includes("execute")) {
      return {
        ...base,
        type: "remote_code_execution",
        capability: `${authPrefix}remote command execution on ${endpoint}`,
      };
    }

    if (category.includes("sql") || category.includes("injection")) {
      return {
        ...base,
        type: "data_exfiltration",
        capability: `${authPrefix}database access via SQL injection on ${endpoint}`,
      };
    }

    if (category.includes("ssrf") || category.includes("server-side request")) {
      return {
        ...base,
        type: "data_exfiltration",
        capability: `${authPrefix}server-side request forgery reaching internal services from ${endpoint}`,
      };
    }

    if (category.includes("path") || category.includes("traversal")) {
      return {
        ...base,
        type: "data_exfiltration",
        capability: `${authPrefix}arbitrary file read via ${endpoint}`,
      };
    }

    if (category.includes("auth") && (category.includes("bypass") || category.includes("broken"))) {
      return {
        ...base,
        type: "authentication_bypass",
        capability: `Authentication bypass on ${endpoint}`,
      };
    }

    if (category.includes("mass assignment")) {
      return {
        ...base,
        type: "privilege_escalation",
        capability: `Privilege escalation via mass assignment on ${endpoint}`,
      };
    }

    if (category.includes("access") || category.includes("idor")) {
      return {
        ...base,
        type: "privilege_escalation",
        capability: `Unauthorized data access via ${endpoint}`,
      };
    }

    if (
      category.includes("xss") ||
      category.includes("cross-site scripting") ||
      category.includes("csrf")
    ) {
      return {
        ...base,
        type: "session_hijacking",
        capability: `${authPrefix}client-side script injection on ${endpoint} enabling session hijacking`,
      };
    }

    if (
      category.includes("sensitive") ||
      category.includes("exposure") ||
      category.includes("disclosure")
    ) {
      return {
        ...base,
        type: "data_exfiltration",
        capability: `Sensitive data leak from ${endpoint}`,
      };
    }

    return { ...base, type: "none", capability: "", evidence: "" };
  }

  /**
   * Generate a deployment verdict with scan status awareness.
   * A failed scan is never a passing scan.
   */
  generateVerdictWithStatus(
    findings: Finding[],
    scanStatus: { isComplete: boolean; failedScanners: string[]; allScannersFailed?: boolean }
  ): SecurityVerdict {
    const incompleteWithFailures = !scanStatus.isComplete && scanStatus.failedScanners.length > 0;
    const noScannerCompleted = scanStatus.allScannersFailed === true;

    if (incompleteWithFailures || noScannerCompleted) {
      const failedList =
        scanStatus.failedScanners.length > 0
          ? `${scanStatus.failedScanners.join(", ")} failed`
          : "no scanners completed";
      return {
        verdict: "INCONCLUSIVE",
        reason: `Scan incomplete: ${failedList}. Cannot determine security status.`,
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

    return this.generateVerdict(findings);
  }

  /**
   * The deploy gate.
   *
   *   UNSAFE          - exploitation was proven. Block.
   *   REVIEW_REQUIRED - plausible but unproven. Do not block, do surface.
   *   SAFE            - nothing proven, nothing above the review threshold.
   *
   * Nothing except positive proof produces UNSAFE. An unproven finding, no
   * matter how scary its category label, cannot block a deploy. That is the
   * whole point of a gate that developers will keep switched on.
   */
  generateVerdict(findings: Finding[]): SecurityVerdict {
    const correlations = this.correlateByEndpoint(findings);
    const breaches = this.analyzeBreaches(findings);
    const confirmedExploits = findings.filter((f) => this.isExploitConfirmed(f));

    let operationalConclusion = "";
    if (breaches.length > 0) {
      const priority: BreachType[] = [
        "remote_code_execution",
        "data_exfiltration",
        "authentication_bypass",
        "privilege_escalation",
        "session_hijacking",
      ];
      const ranked = priority
        .map((type) => breaches.find((b) => b.type === type))
        .filter((b): b is ConfirmedBreach => !!b);
      operationalConclusion = (ranked[0] ?? breaches[0]).capability;
    }

    // Unproven findings worth a human look.
    const reviewFindings = findings.filter((f) => {
      if (this.isExploitConfirmed(f)) return false;
      return this.analyzeAttackVector(f).feasibilityScore >= REVIEW_THRESHOLD;
    });

    const allChains: AttackChain[] = [];
    for (const corr of correlations) {
      allChains.push(...corr.attackChains);
    }

    const recommendations = this.generateContextualRemediations([
      ...confirmedExploits,
      ...reviewFindings,
    ]);

    let verdict: DeploymentVerdict;
    let reason: string;

    if (breaches.length > 0) {
      verdict = "UNSAFE";
      reason = operationalConclusion;
    } else if (confirmedExploits.length > 0) {
      verdict = "UNSAFE";
      const types = [...new Set(confirmedExploits.map((f) => f.category))];
      reason = `Exploitation confirmed against ${types.slice(0, 2).join(", ")}.`;
    } else if (reviewFindings.length > 0) {
      verdict = "REVIEW_REQUIRED";
      reason = `${reviewFindings.length} unconfirmed finding(s) above the review threshold. No exploitation was demonstrated.`;
    } else if (findings.length > 0) {
      verdict = "SAFE";
      reason = `${findings.length} low-risk finding(s). No exploitation demonstrated and nothing above the review threshold.`;
    } else {
      verdict = "SAFE";
      reason = "No security findings.";
    }

    return {
      verdict,
      reason,
      breaches,
      operationalConclusion,
      criticalFindings: reviewFindings,
      confirmedExploits,
      attackChains: allChains,
      recommendations,
    };
  }

  private generateContextualRemediations(findings: Finding[]): ContextualRemediation[] {
    return findings.slice(0, 10).map((finding) => {
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

  private getSpecificRemediation(finding: Finding): { fix: string; code?: string } {
    const category = finding.category.toLowerCase();
    const endpoint = finding.endpoint || "";

    if (category.includes("sql")) {
      const param = this.extractParamFromEvidence(finding.evidence);
      return {
        fix: `Parameterize query on ${endpoint}${param ? ` for parameter '${param}'` : ""}`,
        code: `// Instead of:\ndb.query(\`SELECT * FROM users WHERE id = \${${param || "id"}}\`);\n\n// Use:\ndb.query('SELECT * FROM users WHERE id = ?', [${param || "id"}]);`,
      };
    }

    if (category.includes("command") || category.includes("execute")) {
      return {
        fix: `Remove shell execution on ${endpoint}. Use safe library functions instead.`,
        code: `// Instead of:\nexec(\`echo \${userInput}\`);\n\n// Use:\nconst { execFile } = require('child_process');\nexecFile('echo', [userInput]); // no shell involved`,
      };
    }

    if (category.includes("ssrf") || category.includes("server-side request")) {
      return {
        fix: `Allowlist outbound destinations on ${endpoint} and block link-local and private address ranges.`,
        code: `const ALLOWED = new Set(['api.partner.com']);\nconst url = new URL(userSuppliedUrl);\nif (!ALLOWED.has(url.hostname)) {\n  throw new Error('Destination not allowed');\n}\n// Also resolve DNS and reject 169.254.0.0/16, 10/8, 172.16/12, 192.168/16`,
      };
    }

    if (category.includes("mass assignment")) {
      return {
        fix: `Bind only explicitly allowed fields on ${endpoint}.`,
        code: `// Instead of:\nawait User.update(req.body, { where: { id } });\n\n// Use an allowlist:\nconst { name, email } = req.body;\nawait User.update({ name, email }, { where: { id } });`,
      };
    }

    if (category.includes("path") || category.includes("traversal")) {
      return {
        fix: `Validate file paths on ${endpoint}. Ensure the path resolves within the allowed directory.`,
        code: `const path = require('path');\nconst safePath = path.resolve(ALLOWED_DIR, userPath);\nif (!safePath.startsWith(ALLOWED_DIR)) {\n  throw new Error('Invalid path');\n}`,
      };
    }

    if (category.includes("access") || category.includes("idor") || category.includes("auth")) {
      return {
        fix: `Enforce an ownership check on ${endpoint}. Verify the resource belongs to the authenticated caller.`,
        code: `if (resource.userId !== req.user.id) {\n  return res.status(403).json({ error: 'Forbidden' });\n}`,
      };
    }

    if (category.includes("xss") || category.includes("script")) {
      return {
        fix: `Encode output on ${endpoint} and set a Content-Security-Policy header.`,
        code: `const escaped = escapeHtml(userInput);\nres.setHeader('Content-Security-Policy', "default-src 'self'");`,
      };
    }

    if (
      category.includes("disclosure") ||
      category.includes("debug") ||
      category.includes("info")
    ) {
      return {
        fix: `Remove or protect ${endpoint}. Disable verbose errors in production.`,
        code: `if (process.env.NODE_ENV === 'production') {\n  // Do not register debug routes\n}\n\nres.status(500).json({ error: 'Internal server error' });`,
      };
    }

    if (category.includes("sensitive") || category.includes("exposure")) {
      return {
        fix: `Mask sensitive data in the ${endpoint} response. Never return passwords or tokens.`,
        code: `const sanitized = {\n  ...user,\n  password: undefined,\n  apiKey: undefined,\n};`,
      };
    }

    if (category.includes("dependency") || category.includes("vulnerability")) {
      const pkg = finding.package || "affected package";
      const fixed = finding.fixedVersion;
      const kevNote = finding.knownExploited
        ? " This CVE is in the CISA KEV catalog and is being exploited in the wild."
        : "";
      return {
        fix: `Update ${pkg}${fixed ? ` to version ${fixed}` : " to the latest secure version"}.${kevNote}`,
        code: fixed ? `npm install ${pkg}@${fixed}` : `npm update ${pkg}`,
      };
    }

    if (category.includes("header") || category.includes("misconfiguration")) {
      return {
        fix: `Add the missing response headers at your edge or in the application. This is defence in depth, not an exploitable issue on its own.`,
        code: `app.use(helmet());`,
      };
    }

    return {
      fix: `Review and address ${finding.category} on ${endpoint || "the affected component"}.`,
    };
  }

  private extractParamFromEvidence(evidence?: string): string | undefined {
    if (!evidence) return undefined;

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

  private getRemediationPriority(finding: Finding): "immediate" | "high" | "medium" | "low" {
    if (this.isExploitConfirmed(finding)) return "immediate";
    if (finding.knownExploited) return "immediate";

    const vector = this.analyzeAttackVector(finding);
    if (vector.feasibilityScore >= 0.5) return "high";
    if (vector.feasibilityScore >= REVIEW_THRESHOLD) return "medium";
    return "low";
  }

  private normalizeEndpoint(endpoint?: string): string {
    if (!endpoint) return "no-endpoint";

    return endpoint
      .replace(/\/\d+/g, "/:id")
      .replace(/\/[a-f0-9-]{36}/gi, "/:uuid")
      .replace(/\?.*/g, "");
  }
}
