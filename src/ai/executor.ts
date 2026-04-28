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
    const isSuccess = status >= 200 && status < 300;

    // A 404 with "route not found" means the router rejected a path-based payload — not a vulnerability.
    if (status === 404 && /route.*not.*found|could not be found/i.test(body)) {
      return { isVulnerable: false, matchedCriteria: [] };
    }

    // A 401/403 means auth/authz is working — never flag these as Broken Access Control.
    const isAuthRejection = status === 401 || status === 403;

    // Status code match only counts when the attack succeeded (2xx).
    // A 401/422 response when 200 was expected means the server correctly rejected the attempt.
    if (expected.statusCodes?.includes(status) && isSuccess) {
      matchedCriteria.push(`Status code ${status} matches expected`);
    }

    // Body-contains and header-missing checks only apply on 2xx responses.
    // Checking these on 401/404/422 generates false positives because error bodies
    // contain generic terms ("id", "success") and error responses naturally lack
    // protocol headers (WWW-Authenticate, Authorization) that are not security headers.
    if (isSuccess) {
      if (expected.bodyContains) {
        for (const needle of expected.bodyContains) {
          if (body.toLowerCase().includes(needle.toLowerCase())) {
            matchedCriteria.push(`Body contains "${needle}"`);
          }
        }
      }

      if (expected.headerMissing) {
        for (const header of expected.headerMissing) {
          if (!headers[header.toLowerCase()]) {
            matchedCriteria.push(`Missing security header: ${header}`);
          }
        }
      }

      // Auto-check core security headers on successful responses only.
      const securityHeaders = [
        "x-content-type-options",
        "x-frame-options",
        "strict-transport-security",
      ];
      for (const header of securityHeaders) {
        if (!headers[header] && !expected.headerMissing?.includes(header)) {
          matchedCriteria.push(`Missing security header: ${header}`);
        }
      }
    }

    // Definitive exploitation indicators — check on all responses.
    // These are unambiguous evidence of a real vulnerability regardless of status.
    if (!isAuthRejection) {
      const vulnIndicators = [
        { pattern: /sql.*error|syntax.*error|mysql.*error|postgresql.*error|sqlite.*error/i, name: "SQL error" },
        { pattern: /stack.*trace|exception.*at\s+\w+\./i, name: "Stack trace" },
        { pattern: /<script[\s>]|javascript:/i, name: "Unescaped script" },
        { pattern: /password\s*[:=]|api[_-]?key\s*[:=]|secret\s*[:=]/i, name: "Sensitive data" },
      ];
      for (const indicator of vulnIndicators) {
        if (indicator.pattern.test(body)) {
          matchedCriteria.push(`Response contains ${indicator.name}`);
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
