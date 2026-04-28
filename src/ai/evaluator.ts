import { AIClient, AIConfig } from "./adversary.js";
import { PromptBuilder } from "./prompt.builder.js";
import { TestResult } from "./executor.js";
import { SecurityTestCase } from "./test.generator.js";
import { ExecutionContext } from "../orchestrator/context.js";
import { RawFinding } from "../findings/raw.finding.js";
import { logger } from "../core/logger.js";

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
      if (!result.isVulnerable) continue;

      // Use rule-based evaluation first since it's reliable and fast
      // The test executor already identified these as vulnerable based on response patterns
      let assessment = this.evaluateWithRules(result);

      // If rule-based evaluation didn't classify it, try AI for more nuanced analysis
      if (!assessment.isVulnerable && this.useAI) {
        logger.debug(`Using AI to evaluate: ${result.testCase.name}`);
        assessment = await this.evaluateWithAI(result);
      }

      if (assessment.isVulnerable && assessment.vulnerability) {
        findings.push({
          source: "AI Security Tester",
          category: assessment.vulnerability.type,
          description: `${result.testCase.name}: ${result.testCase.description}`,
          endpoint: result.testCase.endpoint,
          role: this.ctx.auth?.role,
          severityHint: assessment.vulnerability.severity,
          evidence: assessment.vulnerability.evidence,
          reference: assessment.vulnerability.recommendation,
        });
      }
    }

    return findings;
  }

  private async evaluateWithAI(result: TestResult): Promise<VulnerabilityAssessment> {
    try {
      const prompt = this.promptBuilder.buildEvaluationPrompt(
        JSON.stringify(result.testCase, null, 2),
        result.response
      );

      const response = await this.client.generate(prompt);
      return this.parseAssessment(response);
    } catch (err) {
      logger.debug(`AI evaluation failed: ${(err as Error).message}`);
      return this.evaluateWithRules(result);
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

  private evaluateWithRules(result: TestResult): VulnerabilityAssessment {
    const { testCase, response, matchedCriteria } = result;

    // Calculate confidence based on matched criteria
    const confidence = Math.min(0.3 + matchedCriteria.length * 0.15, 0.95);

    // Determine vulnerability type and severity
    const vulnInfo = this.classifyVulnerability(testCase, matchedCriteria);

    if (!vulnInfo) {
      return { isVulnerable: false, confidence: 0 };
    }

    return {
      isVulnerable: true,
      confidence,
      vulnerability: {
        type: vulnInfo.type,
        severity: vulnInfo.severity,
        evidence: this.buildEvidence(result),
        recommendation: vulnInfo.recommendation,
      },
    };
  }

  private classifyVulnerability(
    testCase: SecurityTestCase,
    matchedCriteria: string[]
  ): { type: string; severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"; recommendation: string } | null {
    const category = testCase.category.toLowerCase();
    const criteriaStr = matchedCriteria.join(" ").toLowerCase();

    // SQL Injection
    if (category.includes("injection") || criteriaStr.includes("sql")) {
      return {
        type: "SQL Injection",
        severity: "CRITICAL",
        recommendation: "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
      };
    }

    // XSS
    if (category.includes("xss") || criteriaStr.includes("script")) {
      return {
        type: "Cross-Site Scripting (XSS)",
        severity: "HIGH",
        recommendation: "Encode all user input before rendering. Use Content-Security-Policy headers.",
      };
    }

    // Authentication bypass
    if (category.includes("auth") || category.includes("access")) {
      return {
        type: "Broken Access Control",
        severity: "HIGH",
        recommendation: "Implement proper authentication and authorization checks. Use middleware to verify access.",
      };
    }

    // Sensitive data exposure
    if (criteriaStr.includes("sensitive") || criteriaStr.includes("password")) {
      return {
        type: "Sensitive Data Exposure",
        severity: "HIGH",
        recommendation: "Never expose sensitive data in responses. Implement proper data masking.",
      };
    }

    // Security headers — only report when there is no other substantive finding.
    // All criteria being header-miss only means no actual exploitation occurred.
    if (criteriaStr.includes("security header")) {
      const substantive = matchedCriteria.filter(
        (c) => !c.startsWith("Missing security header")
      );
      if (substantive.length === 0) {
        return {
          type: "Security Misconfiguration",
          severity: "MEDIUM",
          recommendation: "Add security headers: X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security.",
        };
      }
    }

    // Stack trace / error disclosure
    if (criteriaStr.includes("stack trace") || criteriaStr.includes("exception")) {
      return {
        type: "Information Disclosure",
        severity: "MEDIUM",
        recommendation: "Disable detailed error messages in production. Log errors server-side only.",
      };
    }

    // Command Injection
    if (category.includes("command") || category.includes("execute")) {
      return {
        type: "Command Injection",
        severity: "CRITICAL",
        recommendation: "Never pass user input directly to shell commands. Use allowlists for permitted operations.",
      };
    }

    // Information Disclosure (debug endpoints, etc.)
    if (category.includes("disclosure") || category.includes("debug") || category.includes("info")) {
      return {
        type: "Information Disclosure",
        severity: "MEDIUM",
        recommendation: "Remove or protect debug endpoints. Never expose system information in production.",
      };
    }

    // Path Traversal / File access
    if (category.includes("file") || category.includes("path") || category.includes("traversal")) {
      return {
        type: "Path Traversal",
        severity: "HIGH",
        recommendation: "Validate and sanitize file paths. Use allowlists for permitted directories.",
      };
    }

    // Generic vulnerability — only fire when there is substantive evidence beyond header misses.
    // Pure header-miss findings are already handled above.
    const substantiveCriteria = matchedCriteria.filter(
      (c) => !c.startsWith("Missing security header")
    );
    if (substantiveCriteria.length > 0) {
      return {
        type: testCase.category || "Security Vulnerability",
        severity: "MEDIUM",
        recommendation: "Review the endpoint for security issues based on the matched criteria.",
      };
    }

    return null;
  }

  private buildEvidence(result: TestResult): string {
    const parts: string[] = [];

    parts.push(`Request: ${result.testCase.request.method} ${result.testCase.request.path}`);
    parts.push(`Response Status: ${result.response.status}`);

    if (result.matchedCriteria.length > 0) {
      parts.push(`Matched: ${result.matchedCriteria.join(", ")}`);
    }

    // Include relevant response snippet
    const bodySnippet = result.response.body.substring(0, 200);
    if (bodySnippet) {
      parts.push(`Response: ${bodySnippet}${result.response.body.length > 200 ? "..." : ""}`);
    }

    return parts.join("\n");
  }
}
