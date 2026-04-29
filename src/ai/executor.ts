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

interface BaselineResponse {
  status: number;
  body: string;
  timing: number;
}

export class TestExecutor {
  private ctx: ExecutionContext;
  private timeout: number;
  private lastRequestAt = 0;

  constructor(ctx: ExecutionContext, timeout: number = 10000) {
    this.ctx = ctx;
    this.timeout = timeout;
  }

  // Task 1: parallel execution with a concurrency cap so we don't flood the target.
  // Task 2: captures benign baseline responses before attack tests so bodyContains
  //         matches that appear in normal responses are not counted as evidence.
  async execute(testCases: SecurityTestCase[], concurrency = 5): Promise<TestResult[]> {
    const baselines = await this.captureBaselines(testCases);

    const settled: TestResult[] = [];
    const active = new Set<Promise<void>>();

    for (const testCase of testCases) {
      const skipReason = this.getSkipReason(testCase);
      if (skipReason) {
        logger.debug(`Skipping: ${testCase.name} - ${skipReason}`);
        continue;
      }

      const task = (async () => {
        try {
          await this.applyThrottle();
          const key = this.endpointKey(testCase);
          const result = await this.executeTest(testCase, baselines.get(key));
          settled.push(result);
          if (result.isVulnerable) {
            logger.finding(this.inferSeverity(testCase.category), testCase.name);
          }
        } catch (err) {
          logger.debug(`Test failed: ${testCase.name} - ${(err as Error).message}`);
        }
      })();

      active.add(task);
      task.finally(() => active.delete(task));

      if (active.size >= concurrency) {
        await Promise.race(active);
      }
    }

    await Promise.allSettled(active);
    return settled;
  }

  // Sends a benign request (no attack payload, clean path) to each unique endpoint
  // before running attack tests. Used to establish a baseline for response diffing.
  private async captureBaselines(
    testCases: SecurityTestCase[]
  ): Promise<Map<string, BaselineResponse>> {
    const baselines = new Map<string, BaselineResponse>();
    const seen = new Set<string>();

    for (const tc of testCases) {
      const key = this.endpointKey(tc);
      if (seen.has(key)) continue;
      seen.add(key);

      try {
        const cleanPath = new URL(tc.request.path, this.ctx.targetUrl).pathname;
        const url = new URL(cleanPath, this.ctx.targetUrl);
        const headers: Record<string, string> = {
          "Content-Type": "application/json",
          "User-Agent": "SecurityBot/1.0",
          ...buildAuthHeaders(this.ctx.auth),
        };
        const ctrl = new AbortController();
        const tid = setTimeout(() => ctrl.abort(), this.timeout);
        const start = Date.now();
        const resp = await fetch(url.toString(), { method: tc.request.method, headers, signal: ctrl.signal });
        clearTimeout(tid);
        baselines.set(key, { status: resp.status, body: await resp.text(), timing: Date.now() - start });
        logger.debug(`Baseline captured for ${key}: ${resp.status}`);
      } catch {
        // Baseline capture is best-effort; absence does not block attack tests.
      }
    }

    return baselines;
  }

  private endpointKey(tc: SecurityTestCase): string {
    try {
      const parsed = new URL(tc.request.path, this.ctx.targetUrl);
      return `${tc.request.method.toUpperCase()} ${parsed.pathname}`;
    } catch {
      return `${tc.request.method.toUpperCase()} ${tc.request.path}`;
    }
  }

  private async executeTest(
    testCase: SecurityTestCase,
    baseline?: BaselineResponse
  ): Promise<TestResult> {
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
        body: testCase.request.body ? JSON.stringify(testCase.request.body) : undefined,
        signal: controller.signal,
      });
      this.lastRequestAt = Date.now();
      clearTimeout(timeoutId);

      const timing = Date.now() - startTime;
      const body = await response.text();
      const responseHeaders = this.headersToObject(response.headers);

      const { isVulnerable, matchedCriteria } = this.evaluateResponse(
        testCase, response.status, responseHeaders, body, timing, baseline
      );

      return { testCase, response: { status: response.status, headers: responseHeaders, body, timing }, isVulnerable, matchedCriteria };
    } catch (err) {
      clearTimeout(timeoutId);
      throw err;
    }
  }

  private headersToObject(headers: Headers): Record<string, string> {
    const obj: Record<string, string> = {};
    headers.forEach((value, key) => { obj[key.toLowerCase()] = value; });
    return obj;
  }

  private evaluateResponse(
    testCase: SecurityTestCase,
    status: number,
    headers: Record<string, string>,
    body: string,
    timing: number,
    baseline?: BaselineResponse
  ): { isVulnerable: boolean; matchedCriteria: string[] } {
    const matchedCriteria: string[] = [];
    const expected = testCase.expectedVulnerable;
    const isSuccess = status >= 200 && status < 300;

    // A 404 "route not found" means the router rejected a path-based payload — not a vulnerability.
    if (status === 404 && /route.*not.*found|could not be found/i.test(body)) {
      return { isVulnerable: false, matchedCriteria: [] };
    }

    const isAuthRejection = status === 401 || status === 403;

    // Status code match only counts when the attack produced a 2xx that differs from the baseline.
    if (expected.statusCodes?.includes(status) && isSuccess) {
      if (!baseline || baseline.status >= 400) {
        matchedCriteria.push(`Status code ${status} matches expected`);
      }
    }

    // Body-contains and header-missing checks only apply on 2xx responses.
    if (isSuccess) {
      if (expected.bodyContains) {
        for (const needle of expected.bodyContains) {
          const inBody = body.toLowerCase().includes(needle.toLowerCase());
          // Task 2: skip the match if the same string appeared in the benign baseline response.
          // This eliminates generic words ("id", "success") that appear in every normal response.
          const inBaseline = baseline?.body.toLowerCase().includes(needle.toLowerCase()) ?? false;
          if (inBody && !inBaseline) {
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

      const securityHeaders = ["x-content-type-options", "x-frame-options", "strict-transport-security"];
      for (const header of securityHeaders) {
        if (!headers[header] && !expected.headerMissing?.includes(header)) {
          matchedCriteria.push(`Missing security header: ${header}`);
        }
      }
    }

    // Task 3: time-based blind injection — response significantly slower than baseline.
    // Threshold: >3 000 ms AND at least 3× the baseline timing.
    if (!isAuthRejection && baseline && timing > 3000 && timing > baseline.timing * 3) {
      matchedCriteria.push(
        `Response delayed ${timing}ms vs baseline ${baseline.timing}ms — possible blind injection`
      );
    }

    // Definitive exploitation indicators — check on all non-auth-rejection responses.
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

    return { isVulnerable: matchedCriteria.length > 0, matchedCriteria };
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
      SSRF: "HIGH",
      "Mass Assignment": "HIGH",
    };
    return severityMap[category] || "MEDIUM";
  }

  private getSkipReason(testCase: SecurityTestCase): string | undefined {
    const url = new URL(testCase.request.path, this.ctx.targetUrl);
    const safety = this.ctx.config.safety;

    if (!isUrlInScope(url, this.ctx.targetUrl, safety)) return `URL ${url.hostname} is outside configured scope`;
    if (isPathExcluded(url.pathname, safety)) return `path ${url.pathname} is excluded by safety.excludedPaths`;
    if (!allowsDestructiveMethod(testCase.request.method, safety)) return `method ${testCase.request.method.toUpperCase()} is blocked by safety profile`;

    return undefined;
  }

  private async applyThrottle(): Promise<void> {
    const delay = requestDelayMs(this.ctx.config.safety);
    if (delay <= 0 || this.lastRequestAt === 0) return;

    const elapsed = Date.now() - this.lastRequestAt;
    if (elapsed < delay) {
      await sleep(delay - elapsed);
    }
  }
}
