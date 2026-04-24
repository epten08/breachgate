import { AIClient, AIConfig } from "./adversary.js";
import { PromptBuilder, EndpointInfo } from "./prompt.builder.js";
import { ExecutionContext } from "../orchestrator/context.js";
import { logger } from "../core/logger.js";

export interface SecurityTestCase {
  name: string;
  endpoint: string;
  category: string;
  description: string;
  request: {
    method: string;
    path: string;
    headers?: Record<string, string>;
    body?: unknown;
  };
  expectedVulnerable: {
    statusCodes?: number[];
    bodyContains?: string[];
    headerMissing?: string[];
  };
}

export interface AbuseScenario {
  name: string;
  attack: string;
  impact: string;
  testPayload: {
    method: string;
    path: string;
    headers?: Record<string, string>;
    body?: unknown;
  };
}

export interface AbuseAnalysis {
  riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  scenarios: AbuseScenario[];
}

export class TestGenerator {
  private client: AIClient;
  private promptBuilder: PromptBuilder;
  private ctx: ExecutionContext;

  constructor(ctx: ExecutionContext, aiConfig: AIConfig) {
    this.ctx = ctx;
    this.client = new AIClient(aiConfig);
    this.promptBuilder = new PromptBuilder(ctx);
  }

  async generateTestCases(maxTests: number = 10): Promise<SecurityTestCase[]> {
    logger.debug("Generating AI security test cases");

    const endpoints = this.promptBuilder.extractEndpoints();
    logger.debug(`Found ${endpoints.length} endpoints to test`);

    const systemPrompt = this.promptBuilder.buildSystemPrompt();
    const prompt = this.promptBuilder.buildTestGenerationPrompt(endpoints);

    try {
      const response = await this.client.generate(prompt, systemPrompt);
      const testCases = this.parseTestCases(response);

      // Limit to maxTests
      return testCases.slice(0, maxTests);
    } catch (err) {
      logger.warn(`Failed to generate test cases: ${(err as Error).message}`);
      return this.getFallbackTestCases(endpoints);
    }
  }

  async analyzeEndpoint(endpoint: EndpointInfo): Promise<AbuseAnalysis> {
    logger.debug(`Analyzing endpoint: ${endpoint.method} ${endpoint.path}`);

    const systemPrompt = this.promptBuilder.buildSystemPrompt();
    const prompt = this.promptBuilder.buildAbuseScenarioPrompt(endpoint);

    try {
      const response = await this.client.generate(prompt, systemPrompt);
      return this.parseAbuseAnalysis(response);
    } catch (err) {
      logger.warn(`Failed to analyze endpoint: ${(err as Error).message}`);
      return {
        riskLevel: "MEDIUM",
        scenarios: [],
      };
    }
  }

  async isAvailable(): Promise<boolean> {
    return this.client.isAvailable();
  }

  private parseTestCases(response: string): SecurityTestCase[] {
    try {
      // Extract JSON from response (may be wrapped in markdown)
      const jsonMatch = response.match(/\[[\s\S]*\]/);
      if (!jsonMatch) {
        logger.warn("No JSON array found in AI response");
        return [];
      }

      // Try to fix common JSON issues from LLMs
      let jsonStr = jsonMatch[0];

      // Replace single quotes with double quotes (common LLM mistake)
      // But be careful not to replace quotes inside strings
      jsonStr = this.fixJsonQuotes(jsonStr);

      const parsed = JSON.parse(jsonStr) as SecurityTestCase[];

      // Validate structure
      return parsed.filter((tc) => {
        return (
          tc.name &&
          tc.endpoint &&
          tc.request?.method &&
          tc.request?.path
        );
      });
    } catch (err) {
      logger.warn(`Failed to parse test cases: ${(err as Error).message}`);
      // Try fallback: use configured endpoints directly
      return this.getFallbackTestCases(this.promptBuilder.extractEndpoints());
    }
  }

  private fixJsonQuotes(jsonStr: string): string {
    // Replace single quotes used as JSON delimiters with double quotes
    // This handles cases like {'key': 'value'} -> {"key": "value"}
    // But preserves single quotes inside double-quoted strings

    let result = "";
    let inDoubleQuote = false;
    let inSingleQuote = false;
    let prevChar = "";

    for (let i = 0; i < jsonStr.length; i++) {
      const char = jsonStr[i];

      if (char === '"' && prevChar !== "\\") {
        inDoubleQuote = !inDoubleQuote;
        result += char;
      } else if (char === "'" && !inDoubleQuote && prevChar !== "\\") {
        // Single quote used as delimiter - replace with double quote
        inSingleQuote = !inSingleQuote;
        result += '"';
      } else {
        result += char;
      }

      prevChar = char;
    }

    return result;
  }

  private parseAbuseAnalysis(response: string): AbuseAnalysis {
    try {
      // Extract JSON from response
      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        return { riskLevel: "MEDIUM", scenarios: [] };
      }

      const parsed = JSON.parse(jsonMatch[0]) as AbuseAnalysis;
      return {
        riskLevel: parsed.riskLevel || "MEDIUM",
        scenarios: parsed.scenarios || [],
      };
    } catch {
      return { riskLevel: "MEDIUM", scenarios: [] };
    }
  }

  private getFallbackTestCases(endpoints: EndpointInfo[]): SecurityTestCase[] {
    // Generate basic test cases without AI
    const testCases: SecurityTestCase[] = [];

    for (const endpoint of endpoints.slice(0, 5)) {
      // SQL Injection test
      if (endpoint.path.includes(":id") || endpoint.path.includes("{id}")) {
        testCases.push({
          name: `SQL Injection - ${endpoint.method} ${endpoint.path}`,
          endpoint: `${endpoint.method} ${endpoint.path}`,
          category: "Injection",
          description: "Test for SQL injection via ID parameter",
          request: {
            method: endpoint.method,
            path: endpoint.path.replace(/:id|\{id\}/g, "1' OR '1'='1"),
          },
          expectedVulnerable: {
            statusCodes: [200],
            bodyContains: ["error", "sql", "syntax"],
          },
        });
      }

      // Auth bypass test
      if (endpoint.security?.length || endpoint.path.includes("admin")) {
        testCases.push({
          name: `Auth Bypass - ${endpoint.method} ${endpoint.path}`,
          endpoint: `${endpoint.method} ${endpoint.path}`,
          category: "Broken Authentication",
          description: "Test accessing protected endpoint without auth",
          request: {
            method: endpoint.method,
            path: endpoint.path.replace(/:id|\{id\}/g, "1"),
            headers: {},
          },
          expectedVulnerable: {
            statusCodes: [200, 201],
          },
        });
      }

      // XSS test for POST/PUT
      if (["POST", "PUT", "PATCH"].includes(endpoint.method)) {
        testCases.push({
          name: `XSS - ${endpoint.method} ${endpoint.path}`,
          endpoint: `${endpoint.method} ${endpoint.path}`,
          category: "XSS",
          description: "Test for reflected XSS in request body",
          request: {
            method: endpoint.method,
            path: endpoint.path.replace(/:id|\{id\}/g, "1"),
            body: {
              name: "<script>alert('xss')</script>",
              email: "test@test.com",
            },
          },
          expectedVulnerable: {
            bodyContains: ["<script>"],
          },
        });
      }
    }

    return testCases;
  }
}
