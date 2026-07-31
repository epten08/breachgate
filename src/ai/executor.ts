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
import { ExploitProof } from "../findings/finding.js";

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
  /**
   * Positive proof of exploitation observed in this response. Empty means the
   * test did not demonstrate anything, whatever else matched.
   */
  proofs: ExploitProof[];
  /** The exact response substring backing the proof. */
  proofExcerpt?: string;
  /**
   * Missing security headers seen on this response.
   *
   * Kept strictly separate from matchedCriteria. These are observations about
   * the response, not evidence that the test's attack worked, and they must
   * never influence isVulnerable. Folding them into the criteria list is what
   * caused a header miss to be reported as a confirmed SQL injection.
   */
  missingHeaders: string[];
}

export interface ExecutionOutcome {
  results: TestResult[];
  /** Tests that could not be executed at all (network errors, timeouts). */
  erroredTests: number;
  /** Tests skipped by safety policy. */
  skippedTests: number;
  attemptedTests: number;
}

interface BaselineResponse {
  status: number;
  body: string;
  timing: number;
}

/** Headers reported as observations. Never treated as exploitation evidence. */
const OBSERVED_SECURITY_HEADERS = [
  "x-content-type-options",
  "x-frame-options",
  "strict-transport-security",
];

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
  /**
   * Run the test cases and report exactly what happened.
   *
   * Errors are counted, not swallowed. Previously a network failure on every
   * test produced an empty result set that the orchestrator recorded as a
   * successful scan, so a typo in the target URL yielded a SAFE verdict. The
   * caller now sees the error count and can escalate to INCONCLUSIVE.
   */
  async execute(testCases: SecurityTestCase[], concurrency = 5): Promise<ExecutionOutcome> {
    const baselines = await this.captureBaselines(testCases);

    const settled: TestResult[] = [];
    const active = new Set<Promise<void>>();
    let erroredTests = 0;
    let skippedTests = 0;
    let attemptedTests = 0;

    for (const testCase of testCases) {
      const skipReason = this.getSkipReason(testCase);
      if (skipReason) {
        logger.debug(`Skipping: ${testCase.name} - ${skipReason}`);
        skippedTests++;
        continue;
      }

      attemptedTests++;
      const task = (async () => {
        try {
          await this.applyThrottle();
          const key = this.endpointKey(testCase);
          const result = await this.executeTest(testCase, baselines.get(key));
          settled.push(result);
          if (result.proofs.length > 0) {
            logger.finding(this.inferSeverity(testCase.category), testCase.name);
          }
        } catch (err) {
          erroredTests++;
          logger.debug(`Test errored: ${testCase.name} - ${(err as Error).message}`);
        }
      })();

      active.add(task);
      task.finally(() => active.delete(task));

      if (active.size >= concurrency) {
        await Promise.race(active);
      }
    }

    await Promise.allSettled([...active]);

    return { results: settled, erroredTests, skippedTests, attemptedTests };
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
        const resp = await fetch(url.toString(), {
          method: tc.request.method,
          headers,
          signal: ctrl.signal,
        });
        clearTimeout(tid);
        baselines.set(key, {
          status: resp.status,
          body: await resp.text(),
          timing: Date.now() - start,
        });
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

      const evaluation = this.evaluateResponse(
        testCase,
        response.status,
        responseHeaders,
        body,
        timing,
        baseline
      );

      return {
        testCase,
        response: { status: response.status, headers: responseHeaders, body, timing },
        isVulnerable: evaluation.proofs.length > 0,
        matchedCriteria: evaluation.matchedCriteria,
        proofs: evaluation.proofs,
        proofExcerpt: evaluation.proofExcerpt,
        missingHeaders: evaluation.missingHeaders,
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

  /**
   * Decide what a response actually demonstrates.
   *
   * The contract: a test is only "vulnerable" if we can point at a substring of
   * the response that no correctly behaving API would return. Everything else
   * is an observation.
   *
   * Three rules make this safe:
   *  1. Missing headers are collected separately and never enter matchedCriteria.
   *  2. Every proof must be absent from the benign baseline. If a clean request
   *     also produces the signal, the signal is not caused by our payload.
   *  3. A proof requires an excerpt. If we cannot quote the evidence, we do not
   *     claim the exploit.
   */
  private evaluateResponse(
    testCase: SecurityTestCase,
    status: number,
    headers: Record<string, string>,
    body: string,
    timing: number,
    baseline?: BaselineResponse
  ): {
    matchedCriteria: string[];
    proofs: ExploitProof[];
    proofExcerpt?: string;
    missingHeaders: string[];
  } {
    const matchedCriteria: string[] = [];
    const proofs: ExploitProof[] = [];
    const excerpts: string[] = [];
    const expected = testCase.expectedVulnerable;
    const isSuccess = status >= 200 && status < 300;
    const isAuthRejection = status === 401 || status === 403;

    // Header observations. Reported for visibility, never evidence of an attack
    // succeeding. Note there is no `isSuccess` gate and no interaction with the
    // criteria list: these are facts about the response, nothing more.
    const missingHeaders = OBSERVED_SECURITY_HEADERS.filter((h) => !headers[h]);

    // A 404 route rejection means the router refused the payload path.
    if (status === 404 && /route.*not.*found|could not be found/i.test(body)) {
      return { matchedCriteria: [], proofs: [], missingHeaders };
    }

    // An auth rejection means the control worked. Nothing here is exploitation.
    if (isAuthRejection) {
      return { matchedCriteria: [], proofs: [], missingHeaders };
    }

    const baselineBody = baseline?.body?.toLowerCase() ?? "";
    const record = (proof: ExploitProof, criterion: string, excerpt: string) => {
      proofs.push(proof);
      matchedCriteria.push(criterion);
      excerpts.push(excerpt);
    };

    // --- Proof: database error text produced by an injected payload ----------
    const sqlError = matchWithExcerpt(
      body,
      /(?:sql syntax|syntax error at or near|unterminated quoted string|mysql_fetch|ORA-\d{5}|SQLSTATE\[|sqlite3?\.OperationalError|near ".*": syntax error)/i
    );
    if (sqlError && !baselineBody.includes(sqlError.toLowerCase())) {
      record("sql-error", "Database error triggered by payload", sqlError);
    }

    // --- Proof: output of an injected shell command --------------------------
    // Deliberately narrow. An earlier version also matched "/bin/bash", which
    // appears in every /etc/passwd, so reading a file was misreported as
    // command execution. Only shapes unique to command output qualify.
    const commandOutput = matchWithExcerpt(
      body,
      /(?:uid=\d+\([\w-]+\)\s+gid=\d+\([\w-]+\)|total \d+\s*\n\s*d[rwx-]{9}|Linux \S+ \d+\.\d+\.\d+)/
    );
    if (commandOutput && !baselineBody.includes(commandOutput.toLowerCase())) {
      record("command-output", "Injected command output returned", commandOutput);
    }

    // --- Proof: cloud instance metadata reached via SSRF ---------------------
    const metadata = matchWithExcerpt(
      body,
      /(?:ami-[0-9a-f]{8,}|"AccessKeyId"|instance-identity\/document|metadata\.google\.internal|169\.254\.169\.254)/i
    );
    if (metadata && !baselineBody.includes(metadata.toLowerCase())) {
      record("cloud-metadata", "Cloud instance metadata reachable", metadata);
    }

    // --- Proof: file contents or system paths returned -----------------------
    const pathDisclosure = matchWithExcerpt(
      body,
      /(?:root:[x*]:0:0:|\[boot loader\]|\/etc\/(?:passwd|shadow)\b|C:\\Windows\\win\.ini)/i
    );
    if (pathDisclosure && !baselineBody.includes(pathDisclosure.toLowerCase())) {
      record("path-disclosure", "Server file contents returned", pathDisclosure);
    }

    // --- Proof: unhandled exception detail leaked to the caller --------------
    const stackTrace = matchWithExcerpt(
      body,
      /(?:\bat\s+[\w$.<>[\]]+\s*\([^)]*\.(?:js|mjs|ts|java|py|rb|go|php):\d+|Traceback \(most recent call last\)|Exception in thread|\bat [\w.$]+\([\w.]+\.java:\d+\))/
    );
    if (stackTrace && !baselineBody.includes(stackTrace.toLowerCase())) {
      record("stack-trace", "Unhandled exception detail returned", stackTrace);
    }

    // --- Proof: our own payload reflected back unescaped ---------------------
    // Only counts when the payload is distinctive enough to be ours, is script
    // capable, and is not already present in the benign baseline.
    if (isSuccess) {
      for (const payload of extractPayloads(testCase)) {
        if (payload.length < 8) continue;
        if (!/<script|javascript:|onerror\s*=|<img[\s>]|<svg[\s>]/i.test(payload)) continue;
        if (!body.includes(payload)) continue;
        if (baselineBody.includes(payload.toLowerCase())) continue;

        record("payload-reflected", "Attack payload reflected unescaped", payload);
        break;
      }
    }

    // --- Proof: privileged field accepted via mass assignment ---------------
    //
    // Mass assignment means WE SENT a privileged value and the server bound it.
    // Merely seeing "role":"admin" in a response is not proof: an endpoint that
    // legitimately returns a user record will contain exactly that, and reading
    // it as mass assignment reports every user-lookup endpoint as exploitable.
    if (isSuccess) {
      const sent = privilegedFieldsSent(testCase);
      for (const { field, value } of sent) {
        const echoed = matchWithExcerpt(
          body,
          new RegExp(`"${escapeRegex(field)}"\\s*:\\s*"?${escapeRegex(value)}"?`, "i")
        );
        if (echoed && !baselineBody.includes(echoed.toLowerCase())) {
          record("privileged-field", `Privileged field '${field}' was sent and accepted`, echoed);
          break;
        }
      }
    }

    // --- NOT a proof: status change between baseline and attack -------------
    //
    // A 4xx baseline turning into a 2xx attack cannot establish an auth bypass.
    // captureBaselines strips the query string, so any endpoint that requires a
    // parameter returns 4xx unparameterised and 2xx once parameters are
    // supplied. Reading that as authorization bypass fired on three unrelated
    // endpoints of the demo API, including a plain search route.
    //
    // Proving auth bypass requires comparing an authenticated request against an
    // unauthenticated one, which is what multi-role scanning does, not a
    // benign-versus-attack payload diff. Recorded as an observation only.
    if (isSuccess && baseline && baseline.status >= 400) {
      matchedCriteria.push(
        `Returned ${status} where the parameterless baseline returned ${baseline.status}`
      );
    }

    // --- Non-proof observations ---------------------------------------------
    // Expected body markers are useful signal for a human but are not proof:
    // an LLM-chosen needle can appear for entirely innocent reasons.
    if (isSuccess && expected.bodyContains) {
      for (const needle of expected.bodyContains) {
        const inBody = body.toLowerCase().includes(needle.toLowerCase());
        const inBaseline = baselineBody.includes(needle.toLowerCase());
        if (inBody && !inBaseline) {
          matchedCriteria.push(`Body contains "${needle}" (not in baseline)`);
        }
      }
    }

    // Timing signal is recorded as an observation only. A single slow response
    // is not an oracle; confirmTimingOracle promotes it to proof if it repeats.
    if (baseline && timing > 3000 && timing > baseline.timing * 3) {
      matchedCriteria.push(
        `Response delayed ${timing}ms vs baseline ${baseline.timing}ms (unconfirmed)`
      );
    }

    return {
      matchedCriteria,
      proofs,
      proofExcerpt: excerpts.length > 0 ? excerpts.join(" | ").slice(0, 500) : undefined,
      missingHeaders,
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
      SSRF: "HIGH",
      "Mass Assignment": "HIGH",
    };
    return severityMap[category] || "MEDIUM";
  }

  private getSkipReason(testCase: SecurityTestCase): string | undefined {
    const url = new URL(testCase.request.path, this.ctx.targetUrl);
    const safety = this.ctx.config.safety;

    if (!isUrlInScope(url, this.ctx.targetUrl, safety))
      return `URL ${url.hostname} is outside configured scope`;
    if (isPathExcluded(url.pathname, safety))
      return `path ${url.pathname} is excluded by safety.excludedPaths`;
    if (!allowsDestructiveMethod(testCase.request.method, safety))
      return `method ${testCase.request.method.toUpperCase()} is blocked by safety profile`;

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

/**
 * Return the matched substring so a proof can quote itself.
 * Returns undefined rather than true/false: a proof without an excerpt is not
 * a proof, because a developer cannot verify it.
 */
function matchWithExcerpt(body: string, pattern: RegExp): string | undefined {
  const match = body.match(pattern);
  if (!match) return undefined;
  const start = Math.max(0, (match.index ?? 0) - 40);
  return body.slice(start, (match.index ?? 0) + match[0].length + 40).trim();
}

const PRIVILEGED_FIELD = /^(role|is_?admin|isadmin|permissions?|scope|privilege|admin)$/i;
const PRIVILEGED_VALUE = /^(admin|superuser|root|true|1)$/i;

/**
 * Privileged fields this test case actually sent, in body or query string.
 * Mass assignment cannot be proven from a response alone; we have to know we
 * supplied the value in the first place.
 */
function privilegedFieldsSent(testCase: SecurityTestCase): Array<{ field: string; value: string }> {
  const found: Array<{ field: string; value: string }> = [];

  const consider = (field: string, value: unknown) => {
    const str = String(value);
    if (PRIVILEGED_FIELD.test(field) && PRIVILEGED_VALUE.test(str)) {
      found.push({ field, value: str });
    }
  };

  if (testCase.request.body && typeof testCase.request.body === "object") {
    for (const [field, value] of Object.entries(testCase.request.body as Record<string, unknown>)) {
      consider(field, value);
    }
  }

  const queryStart = testCase.request.path.indexOf("?");
  if (queryStart >= 0) {
    const params = new URLSearchParams(testCase.request.path.slice(queryStart + 1));
    for (const [field, value] of params.entries()) {
      consider(field, value);
    }
  }

  return found;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * The individual attack VALUES this test case sent, longest first.
 *
 * Values, not the raw query string. An earlier version returned
 * `q=<script>alert(1)</script>` including the parameter name, so the reflection
 * check compared against a string the response could never contain and every
 * reflected XSS was missed.
 */
function extractPayloads(testCase: SecurityTestCase): string[] {
  const values: string[] = [];

  if (testCase.request.body && typeof testCase.request.body === "object") {
    for (const value of Object.values(testCase.request.body as Record<string, unknown>)) {
      if (typeof value === "string") values.push(value);
    }
  }

  const queryStart = testCase.request.path.indexOf("?");
  if (queryStart >= 0) {
    const params = new URLSearchParams(testCase.request.path.slice(queryStart + 1));
    for (const value of params.values()) {
      values.push(value);
    }
  }

  return values.sort((a, b) => b.length - a.length);
}
