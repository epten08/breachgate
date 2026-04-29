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

    // Generate per endpoint so each prompt+response stays well within token limits.
    // A single call for all endpoints at once easily exceeds 2048 tokens and causes
    // truncated JSON that falls back to the minimal fallback set.
    const testsPerEndpoint = Math.max(2, Math.ceil(maxTests / endpoints.length));
    const systemPrompt = this.promptBuilder.buildSystemPrompt();
    const allTests: SecurityTestCase[] = [];

    for (const endpoint of endpoints) {
      if (allTests.length >= maxTests) break;
      const count = Math.min(testsPerEndpoint, maxTests - allTests.length);

      const prompt = this.promptBuilder.buildEndpointTestPrompt(endpoint, count);
      try {
        const response = await this.client.generate(prompt, systemPrompt);
        const tests = this.parseTestCases(response);
        allTests.push(...tests.slice(0, count));
        logger.debug(`Generated ${Math.min(tests.length, count)} tests for ${endpoint.method} ${endpoint.path}`);
      } catch (err) {
        logger.warn(`Failed to generate tests for ${endpoint.method} ${endpoint.path}: ${(err as Error).message}`);
        allTests.push(...this.getFallbackTestsForEndpoint(endpoint));
      }
    }

    logger.debug(`Total AI test cases generated: ${allTests.length}`);
    return allTests.slice(0, maxTests);
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
      return [];
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

  private getFallbackTestsForEndpoint(endpoint: EndpointInfo): SecurityTestCase[] {
    const tests: SecurityTestCase[] = [];
    const method = endpoint.method;
    const path = endpoint.path;
    const label = `${method} ${path}`;
    const summary = endpoint.summary?.toLowerCase() ?? "";

    // SQL / data injection — query-param and body variants
    if (summary.includes("sql") || summary.includes("injection") || summary.includes("data") || summary.includes("id")) {
      const injPayload = "1' OR '1'='1";
      tests.push({
        name: `SQL Injection - ${label}`,
        endpoint: label,
        category: "SQL Injection",
        description: "Test for SQL injection via id parameter",
        request: {
          method,
          path: `${path}?id=${encodeURIComponent(injPayload)}`,
        },
        expectedVulnerable: {
          statusCodes: [200],
          bodyContains: ["sql", "query", "select", "error"],
        },
      });
    }

    // Command injection — body endpoints that mention execute/command
    if (summary.includes("command") || summary.includes("exec") || ["POST", "PUT"].includes(method)) {
      tests.push({
        name: `Command Injection - ${label}`,
        endpoint: label,
        category: "Command Injection",
        description: "Test for OS command injection via command field",
        request: {
          method,
          path,
          body: { command: "echo hello; cat /etc/passwd" },
        },
        expectedVulnerable: {
          statusCodes: [200],
          bodyContains: ["executed", "output", "command"],
        },
      });
    }

    // Path traversal
    if (summary.includes("file") || summary.includes("path") || summary.includes("traversal")) {
      tests.push({
        name: `Path Traversal - ${label}`,
        endpoint: label,
        category: "Path Traversal",
        description: "Test for directory traversal via path parameter",
        request: {
          method,
          path: `${path}?path=../../../etc/passwd`,
        },
        expectedVulnerable: {
          statusCodes: [200],
          bodyContains: ["path", "file", "content", "traversal"],
        },
      });
    }

    // IDOR / broken access control
    if (summary.includes("user") || summary.includes("idor") || summary.includes("access")) {
      tests.push({
        name: `IDOR - ${label}`,
        endpoint: label,
        category: "Broken Access Control",
        description: "Test for insecure direct object reference via id manipulation",
        request: {
          method,
          path: `${path}?id=admin`,
        },
        expectedVulnerable: {
          statusCodes: [200],
          bodyContains: ["password", "role", "email", "user"],
        },
      });
    }

    // XSS — reflected input
    if (["POST", "PUT", "PATCH"].includes(method) || summary.includes("xss") || summary.includes("search")) {
      tests.push({
        name: `XSS - ${label}`,
        endpoint: label,
        category: "Cross-Site Scripting (XSS)",
        description: "Test for reflected XSS via user-controlled input",
        request: {
          method,
          path: ["GET"].includes(method) ? `${path}?q=<script>alert(1)</script>` : path,
          body: ["POST", "PUT", "PATCH"].includes(method)
            ? { input: "<script>alert(1)</script>" }
            : undefined,
        },
        expectedVulnerable: {
          bodyContains: ["<script>"],
        },
      });
    }

    // SSRF — endpoints accepting URLs, webhooks, or file paths (task 5)
    if (summary.includes("url") || summary.includes("webhook") || summary.includes("import") || summary.includes("fetch")) {
      tests.push({
        name: `SSRF - ${label}`,
        endpoint: label,
        category: "SSRF",
        description: "Test for server-side request forgery via attacker-controlled URL parameter",
        request: {
          method,
          path: ["GET"].includes(method) ? `${path}?url=http://169.254.169.254/latest/meta-data` : path,
          body: ["POST", "PUT", "PATCH"].includes(method)
            ? { url: "http://169.254.169.254/latest/meta-data", webhook: "http://169.254.169.254/latest/meta-data" }
            : undefined,
        },
        expectedVulnerable: {
          statusCodes: [200],
          bodyContains: ["169.254", "ami-id", "instance-id", "amazonaws"],
        },
      });
    }

    // Mass assignment — POST/PUT body endpoints (task 6)
    if (["POST", "PUT", "PATCH"].includes(method)) {
      tests.push({
        name: `Mass Assignment - ${label}`,
        endpoint: label,
        category: "Mass Assignment",
        description: "Test whether privileged fields (role, is_admin) are accepted and persisted",
        request: {
          method,
          path,
          body: { role: "admin", is_admin: true, admin: true, verified: true },
        },
        expectedVulnerable: {
          statusCodes: [200, 201],
          bodyContains: ["is_admin", "admin"],
        },
      });
    }

    // Info disclosure — always check debug-style endpoints
    tests.push({
      name: `Info Disclosure - ${label}`,
      endpoint: label,
      category: "Information Disclosure",
      description: "Test for sensitive data or debug information in response",
      request: { method, path },
      expectedVulnerable: {
        statusCodes: [200],
        bodyContains: ["password", "secret", "debug", "stack", "internal"],
      },
    });

    return tests;
  }
}
