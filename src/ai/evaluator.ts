import { AIClient, AIConfig } from "./adversary.js";
import { PromptBuilder } from "./prompt.builder.js";
import { TestResult } from "./executor.js";
import { ExecutionContext } from "../orchestrator/context.js";
import { RawFinding } from "../findings/raw.finding.js";
import { ExploitProof } from "../findings/finding.js";
import { logger } from "../core/logger.js";

/**
 * Turns executed test results into findings.
 *
 * The central inversion versus the previous implementation: classification is
 * driven by WHAT WE OBSERVED, not by what the test case intended to probe.
 *
 * Previously this dispatched on `testCase.category` first, so a test merely
 * named "SQL injection" produced a CRITICAL SQL Injection finding even when the
 * only thing matched was a missing response header. Proof type now decides the
 * category, and the test's own label is used only to disambiguate.
 */

export interface VulnerabilityAssessment {
  isVulnerable: boolean;
  confidence: number;
  vulnerability?: {
    type: string;
    severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    evidence: string;
    recommendation: string;
  };
}

interface Classification {
  type: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  recommendation: string;
}

/**
 * What each proof actually demonstrates.
 *
 * Every entry here is anchored to an observed response signal, so the category
 * cannot drift away from the evidence.
 */
const PROOF_CLASSIFICATION: Record<ExploitProof, Classification> = {
  "sql-error": {
    type: "SQL Injection",
    severity: "CRITICAL",
    recommendation:
      "Use parameterized queries or prepared statements. Never concatenate user input into SQL.",
  },
  "command-output": {
    type: "Command Injection",
    severity: "CRITICAL",
    recommendation:
      "Never pass user input to a shell. Use language-native APIs or execFile with an argument array.",
  },
  "cloud-metadata": {
    type: "Server-Side Request Forgery (SSRF)",
    severity: "CRITICAL",
    recommendation:
      "Allowlist outbound destinations, resolve DNS before fetching, and block link-local and private ranges.",
  },
  "path-disclosure": {
    type: "Path Traversal",
    severity: "HIGH",
    recommendation:
      "Resolve the requested path against an allowed root and reject anything that escapes it.",
  },
  "payload-reflected": {
    type: "Cross-Site Scripting (XSS)",
    severity: "HIGH",
    recommendation:
      "Encode output for its rendering context and set a restrictive Content-Security-Policy.",
  },
  "privileged-field": {
    type: "Mass Assignment",
    severity: "HIGH",
    recommendation:
      "Bind request bodies through an explicit field allowlist. Never pass a raw body to a model update.",
  },
  "auth-bypass": {
    type: "Broken Access Control",
    severity: "HIGH",
    recommendation:
      "Verify authorization server-side on every request. Deny by default and check resource ownership.",
  },
  "timing-oracle": {
    type: "Blind Injection (Time-based)",
    severity: "HIGH",
    recommendation:
      "Use parameterized queries and avoid passing user input into system calls. Confirm manually before shipping a fix.",
  },
  "stack-trace": {
    type: "Information Disclosure",
    severity: "MEDIUM",
    recommendation:
      "Disable detailed error output in production and return a generic error body to callers.",
  },
};

/** Ranked worst-first so the reported category matches the worst thing proven. */
const PROOF_PRIORITY: ExploitProof[] = [
  "command-output",
  "sql-error",
  "cloud-metadata",
  "path-disclosure",
  "auth-bypass",
  "privileged-field",
  "payload-reflected",
  "timing-oracle",
  "stack-trace",
];

export class TestEvaluator {
  private client: AIClient;
  private promptBuilder: PromptBuilder;
  private useAI: boolean;
  private ctx: ExecutionContext;

  constructor(ctx: ExecutionContext, aiConfig?: AIConfig) {
    this.ctx = ctx;
    this.promptBuilder = new PromptBuilder(ctx);

    if (aiConfig) {
      this.client = new AIClient(aiConfig);
      this.useAI = true;
    } else {
      this.client = null as unknown as AIClient;
      this.useAI = false;
    }
  }

  async evaluate(results: TestResult[]): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];

    for (const result of results) {
      // Only proven exploitation becomes a confirmed finding. No proof, no
      // finding from this path, regardless of what the test was called.
      if (result.proofs.length === 0) {
        continue;
      }

      const classification = this.classifyFromProofs(result);

      findings.push({
        source: "AI Security Tester",
        category: classification.type,
        description: `${result.testCase.name}: ${result.testCase.description}`,
        endpoint: result.testCase.endpoint,
        role: this.ctx.auth?.role,
        severityHint: classification.severity,
        evidence: this.buildEvidence(result),
        reference: classification.recommendation,
        proofs: result.proofs,
        proofExcerpt: result.proofExcerpt,
      });
    }

    // Missing security headers are reported once for the whole scan, at LOW,
    // with no proof attached. They are defence in depth, not a breach, and
    // must never be able to influence the deploy verdict.
    const headerFinding = this.summarizeMissingHeaders(results);
    if (headerFinding) {
      findings.push(headerFinding);
    }

    return findings;
  }

  /**
   * Pick the category from the worst proof observed.
   *
   * The test case's own category is consulted only to choose between two
   * readings of the same signal, never to override the evidence.
   */
  private classifyFromProofs(result: TestResult): Classification {
    const worst = PROOF_PRIORITY.find((p) => result.proofs.includes(p)) ?? result.proofs[0];
    const base = PROOF_CLASSIFICATION[worst];

    // An auth-bypass proof on a test that was probing object references is more
    // precisely described as IDOR. Same evidence, narrower name.
    if (worst === "auth-bypass") {
      const category = result.testCase.category.toLowerCase();
      if (category.includes("idor") || category.includes("object reference")) {
        return { ...base, type: "Broken Access Control (IDOR)" };
      }
      if (category.includes("jwt")) {
        return { ...base, type: "Broken Authentication (JWT)", severity: "CRITICAL" };
      }
    }

    return base;
  }

  private summarizeMissingHeaders(results: TestResult[]): RawFinding | undefined {
    const missing = new Set<string>();
    for (const result of results) {
      for (const header of result.missingHeaders) {
        missing.add(header);
      }
    }

    if (missing.size === 0) {
      return undefined;
    }

    return {
      source: "AI Security Tester",
      category: "Missing Security Header",
      description: `Response headers not set: ${[...missing].join(", ")}`,
      severityHint: "LOW",
      evidence:
        `The following headers were absent from responses: ${[...missing].join(", ")}. ` +
        "This is defence in depth. No exploitation was demonstrated and this finding does not block deployment. " +
        "If these are set at your CDN or ingress rather than the origin, this finding is expected.",
      reference: "https://owasp.org/www-project-secure-headers/",
      proofs: [],
    };
  }

  /**
   * Optional second opinion from the model.
   *
   * The model can add narrative but cannot manufacture a confirmation: proofs
   * come only from observed response signals in the executor.
   */
  async describeWithAI(result: TestResult): Promise<string | undefined> {
    if (!this.useAI) return undefined;

    try {
      const prompt = this.promptBuilder.buildEvaluationPrompt(
        JSON.stringify(result.testCase, null, 2),
        result.response
      );
      const response = await this.client.generate(prompt);
      const parsed = this.parseAssessment(response);
      return parsed.vulnerability?.evidence;
    } catch (err) {
      logger.debug(`AI evaluation failed: ${(err as Error).message}`);
      return undefined;
    }
  }

  private parseAssessment(response: string): VulnerabilityAssessment {
    try {
      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        return { isVulnerable: false, confidence: 0 };
      }

      const parsed = JSON.parse(jsonMatch[0]) as VulnerabilityAssessment;
      return {
        isVulnerable: parsed.isVulnerable ?? false,
        confidence: parsed.confidence ?? 0.5,
        vulnerability: parsed.vulnerability,
      };
    } catch {
      return { isVulnerable: false, confidence: 0 };
    }
  }

  /**
   * Evidence a developer can check in ten seconds: the request we sent, the
   * status we got, the exact substring that proves it, and the response.
   */
  private buildEvidence(result: TestResult): string {
    const parts: string[] = [];

    parts.push(`Request: ${result.testCase.request.method} ${result.testCase.request.path}`);
    parts.push(`Response Status: ${result.response.status}`);
    parts.push(`Proof: ${result.proofs.join(", ")}`);

    if (result.proofExcerpt) {
      parts.push(`Proof excerpt: ${result.proofExcerpt}`);
    }

    if (result.matchedCriteria.length > 0) {
      parts.push(`Observations: ${result.matchedCriteria.join(", ")}`);
    }

    const bodySnippet = result.response.body.substring(0, 200);
    if (bodySnippet) {
      parts.push(`Response: ${bodySnippet}${result.response.body.length > 200 ? "..." : ""}`);
    }

    return parts.join("\n");
  }
}
