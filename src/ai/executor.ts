import { SecurityTestCase } from "./test.generator.js";
import { ExecutionContext } from "../orchestrator/context.js";
import { logger } from "../core/logger.js";
import { buildAuthHeaders } from "../auth/auth.js";
import {
  allowsDestructiveMethod,
  isPathExcluded,
  isUrlInScope,
  requestDelayMs,
} from "../safety/safety.js";
import { sleep } from "../utils/network.js";

export interface TestResult {
  testCase: SecurityTestCase;
  response: {
    status: number;
    headers: Record<string, string>;
    body: string;
    timing: number;
  };
  isVulnerable: boolean;
  matchedCriteria: string[];
}

export class TestExecutor {
  private ctx: ExecutionContext;
  private timeout: number;
  private lastRequestAt = 0;

  constructor(ctx: ExecutionContext, timeout: number = 10000) {
    this.ctx = ctx;
    this.timeout = timeout;
  }

  async execute(testCases: SecurityTestCase[]): Promise<TestResult[]> {
    const results: TestResult[] = [];

    for (const testCase of testCases) {
      logger.debug(`Executing: ${testCase.name}`);

      try {
        const skipReason = this.getSkipReason(testCase);
        if (skipReason) {
          logger.debug(`Skipping: ${testCase.name} - ${skipReason}`);
          continue;
        }

        await this.applyThrottle();
        const result = await this.executeTest(testCase);
        results.push(result);

        if (result.isVulnerable) {
          logger.finding(
            this.inferSeverity(testCase.category),
            testCase.name
          );
        }
      } catch (err) {
        logger.debug(`Test failed: ${testCase.name} - ${(err as Error).message}`);
      }
    }

    return results;
  }

  private async executeTest(testCase: SecurityTestCase): Promise<TestResult> {
    const startTime = Date.now();

    const url = new URL(testCase.request.path, this.ctx.targetUrl);
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "User-Agent": "SecurityBot/1.0",
      ...testCase.request.headers,
      ...buildAuthHeaders(this.ctx.auth),
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url.toString(), {
        method: testCase.request.method,
        headers,
        body: testCase.request.body
          ? JSON.stringify(testCase.request.body)
          : undefined,
        signal: controller.signal,
      });
      this.lastRequestAt = Date.now();

      clearTimeout(timeoutId);

      const timing = Date.now() - startTime;
      const body = await response.text();
      const responseHeaders = this.headersToObject(response.headers);

      const { isVulnerable, matchedCriteria } = this.evaluateResponse(
        testCase,
        response.status,
        responseHeaders,
        body
      );

      return {
        testCase,
        response: {
          status: response.status,
          headers: responseHeaders,
          body,
          timing,
        },
        isVulnerable,
        matchedCriteria,
      };
    } catch (err) {
      clearTimeout(timeoutId);
      throw err;
    }
  }

  private headersToObject(headers: Headers): Record<string, string> {
    const obj: Record<string, string> = {};
    headers.forEach((value, key) => {
      obj[key.toLowerCase()] = value;
    });
    return obj;
  }

  private evaluateResponse(
    testCase: SecurityTestCase,
    status: number,
    headers: Record<string, string>,
    body: string
  ): { isVulnerable: boolean; matchedCriteria: string[] } {
    const matchedCriteria: string[] = [];
    const expected = testCase.expectedVulnerable;

    // Check status codes
    if (expected.statusCodes?.includes(status)) {
      matchedCriteria.push(`Status code ${status} matches expected`);
    }

    // Check body contains
    if (expected.bodyContains) {
      for (const needle of expected.bodyContains) {
        if (body.toLowerCase().includes(needle.toLowerCase())) {
          matchedCriteria.push(`Body contains "${needle}"`);
        }
      }
    }

    // Check missing headers
    if (expected.headerMissing) {
      for (const header of expected.headerMissing) {
        if (!headers[header.toLowerCase()]) {
          matchedCriteria.push(`Missing security header: ${header}`);
        }
      }
    }

    // Additional vulnerability indicators
    const vulnIndicators = [
      { pattern: /sql.*error|syntax.*error|mysql|postgresql|sqlite/i, name: "SQL error" },
      { pattern: /stack.*trace|exception|error.*at\s+\w+\./i, name: "Stack trace" },
      { pattern: /<script>|javascript:/i, name: "Unescaped script" },
      { pattern: /password|secret|api.?key|token/i, name: "Sensitive data" },
    ];

    for (const indicator of vulnIndicators) {
      if (indicator.pattern.test(body)) {
        matchedCriteria.push(`Response contains ${indicator.name}`);
      }
    }

    // Check for missing security headers on successful responses
    if (status >= 200 && status < 300) {
      const securityHeaders = [
        "x-content-type-options",
        "x-frame-options",
        "strict-transport-security",
      ];

      for (const header of securityHeaders) {
        if (!headers[header] && !expected.headerMissing?.includes(header)) {
          // Don't double count if already in expected
          matchedCriteria.push(`Missing security header: ${header}`);
        }
      }
    }

    return {
      isVulnerable: matchedCriteria.length > 0,
      matchedCriteria,
    };
  }

  private inferSeverity(category: string): string {
    const severityMap: Record<string, string> = {
      Injection: "CRITICAL",
      "SQL Injection": "CRITICAL",
      "Command Injection": "CRITICAL",
      XSS: "HIGH",
      "Broken Authentication": "HIGH",
      "Broken Access Control": "HIGH",
      "Security Misconfiguration": "MEDIUM",
      "Sensitive Data Exposure": "HIGH",
      CSRF: "MEDIUM",
    };

    return severityMap[category] || "MEDIUM";
  }

  private getSkipReason(testCase: SecurityTestCase): string | undefined {
    const url = new URL(testCase.request.path, this.ctx.targetUrl);
    const safety = this.ctx.config.safety;

    if (!isUrlInScope(url, this.ctx.targetUrl, safety)) {
      return `URL ${url.hostname} is outside configured scope`;
    }

    if (isPathExcluded(url.pathname, safety)) {
      return `path ${url.pathname} is excluded by safety.excludedPaths`;
    }

    if (!allowsDestructiveMethod(testCase.request.method, safety)) {
      return `method ${testCase.request.method.toUpperCase()} is blocked by safety profile`;
    }

    return undefined;
  }

  private async applyThrottle(): Promise<void> {
    const delay = requestDelayMs(this.ctx.config.safety);
    if (delay <= 0 || this.lastRequestAt === 0) {
      return;
    }

    const elapsed = Date.now() - this.lastRequestAt;
    if (elapsed < delay) {
      await sleep(delay - elapsed);
    }
  }
}
