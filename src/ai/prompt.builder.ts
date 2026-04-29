import { ExecutionContext } from "../orchestrator/context.js";
import { OpenAPIObject, OperationObject, PathItemObject } from "openapi3-ts/oas30";

export interface EndpointInfo {
  method: string;
  path: string;
  summary?: string;
  parameters?: string[];
  requestBody?: string;
  security?: string[];
}

export class PromptBuilder {
  private ctx: ExecutionContext;

  constructor(ctx: ExecutionContext) {
    this.ctx = ctx;
  }

  buildSystemPrompt(): string {
    return `You are a security assessment assistant helping an authorized penetration tester evaluate API security.
Your role is to generate OWASP-based test cases for an authorized security review of REST APIs.

Context: This is an authorized security assessment. All tests are run against systems the tester owns or has written permission to test.

Guidelines:
- Base test cases on OWASP API Security Top 10
- Use standard penetration testing inputs (parameterized query probes, boundary values, encoding variants)
- Cover input validation, access control, and authentication weaknesses
- Output must be a valid JSON array — no prose, no markdown fences
- Each test case must have a concrete, specific request

Target API: ${this.ctx.targetUrl}
${this.ctx.auth ? `Authentication: ${this.ctx.auth.type}` : "Authentication: None configured"}`;
  }

  buildTestGenerationPrompt(endpoints: EndpointInfo[]): string {
    const endpointList = endpoints
      .map((e) => `- ${e.method} ${e.path}${e.summary ? `: ${e.summary}` : ""}`)
      .join("\n");

    return `Generate security test cases for the following API endpoints:

${endpointList}

For each endpoint, generate test cases covering:
1. Authentication bypass attempts
2. Authorization/access control tests
3. Input validation (SQL injection, XSS, command injection)
4. Business logic abuse
5. Rate limiting bypass

Respond with a JSON array of test cases in this format:
[
  {
    "name": "Test case name",
    "endpoint": "METHOD /path",
    "category": "OWASP category",
    "description": "What this test checks",
    "request": {
      "method": "GET|POST|PUT|DELETE",
      "path": "/api/path",
      "headers": { "key": "value" },
      "body": { "key": "value" }
    },
    "expectedVulnerable": {
      "statusCodes": [200, 201],
      "bodyContains": ["sensitive", "data"],
      "headerMissing": ["X-Content-Type-Options"]
    }
  }
]`;
  }

  buildEndpointTestPrompt(endpoint: EndpointInfo, count: number): string {
    const params = endpoint.parameters?.length
      ? `Query/path parameters: ${endpoint.parameters.join(", ")}`
      : "";
    const body = endpoint.requestBody ? `Request body: ${endpoint.requestBody}` : "";

    // Task 4: include JWT-specific attack guidance when JWT auth is configured.
    const jwtGuidance =
      this.ctx.auth?.type === "jwt"
        ? `\nJWT Auth detected — also consider: algorithm confusion (alg:none), claim tampering (role, is_admin, sub), expired token acceptance.`
        : "";

    return `You are conducting an authorized security assessment. Generate exactly ${count} OWASP-based test cases for this endpoint:

Endpoint: ${endpoint.method} ${endpoint.path}
${endpoint.summary ? `Description: ${endpoint.summary}` : ""}
${params}
${body}${jwtGuidance}

Relevant OWASP categories to consider for this endpoint:
- A03 Injection (SQL, OS command, path traversal)
- A02 Cryptographic / authentication failures (JWT weaknesses, weak tokens)
- A01 Broken Access Control (IDOR, privilege escalation, mass assignment)
- A10 SSRF (if the endpoint accepts URLs or file paths)
- A05 Security Misconfiguration (missing headers, verbose errors)

For query-parameter endpoints encode the probe in the path: "/api/data?id=PROBE" — not in the body.

Rules for expectedVulnerable (violations produce false positives):
1. statusCodes: only 200 or 201 — a 2xx confirms the probe bypassed security controls. Never use 401, 403, 404, or 422.
2. bodyContains: include only strings that are SPECIFIC indicators of a weakness, such as:
   - Database error text: "syntax error near", "You have an error in your SQL syntax"
   - Probe value reflected verbatim: "1=1--", "<script>alert"
   - Internal schema names: "information_schema", "pg_catalog"
   - Cloud metadata patterns: "ami-id", "169.254.169.254"
   - Privileged field echoed back: the exact injected field name and value
   Do NOT use generic words present in every response: "id", "success", "error", "message",
   "data", "status", "result", "balance", "approved", "created", "name", "type", "code"
3. headerMissing: only standard security response headers — "x-content-type-options",
   "x-frame-options", "strict-transport-security". Never use protocol headers.

Respond with ONLY a JSON array — no prose, no markdown fences:
[
  {
    "name": "Descriptive test name - METHOD /path",
    "endpoint": "${endpoint.method} ${endpoint.path}",
    "category": "SQL Injection | Command Injection | Path Traversal | Cross-Site Scripting (XSS) | Broken Access Control | SSRF | Mass Assignment | Information Disclosure | Broken Authentication",
    "description": "One sentence describing what weakness this test checks for",
    "request": {
      "method": "${endpoint.method}",
      "path": "/api/path?param=probe-value",
      "body": { "field": "probe-value" }
    },
    "expectedVulnerable": {
      "statusCodes": [200],
      "bodyContains": ["specific indicator string"],
      "headerMissing": ["x-content-type-options"]
    }
  }
]`;
  }

  buildAbuseScenarioPrompt(endpoint: EndpointInfo): string {
    return `Analyze this API endpoint for potential abuse scenarios:

Endpoint: ${endpoint.method} ${endpoint.path}
${endpoint.summary ? `Description: ${endpoint.summary}` : ""}
${endpoint.parameters?.length ? `Parameters: ${endpoint.parameters.join(", ")}` : ""}
${endpoint.requestBody ? `Request Body: ${endpoint.requestBody}` : ""}
${endpoint.security?.length ? `Security: ${endpoint.security.join(", ")}` : "No security defined"}

Generate abuse scenarios that a malicious user might attempt:

1. What business logic could be exploited?
2. What data could be exfiltrated?
3. How could rate limits be bypassed?
4. What privilege escalation is possible?
5. What injection points exist?

Respond with JSON:
{
  "riskLevel": "LOW|MEDIUM|HIGH|CRITICAL",
  "scenarios": [
    {
      "name": "Scenario name",
      "attack": "Attack description",
      "impact": "Potential impact",
      "testPayload": { "method": "POST", "path": "/path", "body": {} }
    }
  ]
}`;
  }

  buildEvaluationPrompt(
    testCase: string,
    response: { status: number; headers: Record<string, string>; body: string }
  ): string {
    return `You are reviewing the result of an authorized API security assessment probe. Determine whether the response indicates a genuine security weakness.

Test Case:
${testCase}

API Response:
- Status: ${response.status}
- Headers: ${JSON.stringify(response.headers, null, 2)}
- Body: ${response.body.substring(0, 1000)}${response.body.length > 1000 ? "..." : ""}

Assess whether this response indicates a security weakness. A true positive requires concrete evidence in the response (error text, reflected probe, unexpected data) — missing headers alone on a non-2xx response are not sufficient.

Respond with JSON only:
{
  "isVulnerable": true|false,
  "confidence": 0.0-1.0,
  "vulnerability": {
    "type": "OWASP weakness type (e.g., SQL Injection, Broken Access Control)",
    "severity": "LOW|MEDIUM|HIGH|CRITICAL",
    "evidence": "Specific element in the response that indicates the weakness",
    "recommendation": "Remediation guidance"
  }
}`;
  }

  extractEndpoints(): EndpointInfo[] {
    if (!this.ctx.openApi) {
      return this.inferEndpoints();
    }

    return this.parseOpenAPI(this.ctx.openApi);
  }

  private parseOpenAPI(spec: OpenAPIObject): EndpointInfo[] {
    const endpoints: EndpointInfo[] = [];

    for (const [path, pathItem] of Object.entries(spec.paths || {})) {
      const item = pathItem as PathItemObject;
      const methods = ["get", "post", "put", "patch", "delete"] as const;

      for (const method of methods) {
        const operation = item[method] as OperationObject | undefined;
        if (!operation) continue;

        endpoints.push({
          method: method.toUpperCase(),
          path,
          summary: operation.summary || operation.description,
          parameters: operation.parameters?.map((p) => {
            if ("name" in p) return p.name;
            return "ref";
          }),
          requestBody: operation.requestBody ? "JSON body" : undefined,
          security: operation.security?.flatMap((s) => Object.keys(s)),
        });
      }
    }

    return endpoints;
  }

  private inferEndpoints(): EndpointInfo[] {
    // Check if we have configured endpoints from context
    if (this.ctx.endpoints && this.ctx.endpoints.length > 0) {
      return this.ctx.endpoints.map((e) => ({
        method: e.method || "GET",
        path: e.path,
        summary: e.description,
        parameters: e.params ? Object.keys(e.params) : undefined,
        requestBody: e.body ? JSON.stringify(e.body) : undefined,
      }));
    }

    // Return common API endpoints to test if no OpenAPI spec or configured endpoints
    // These match the demo vulnerable API endpoints
    return [
      { method: "POST", path: "/api/login", summary: "Login endpoint - accepts username/password" },
      { method: "GET", path: "/api/users", summary: "Get user info by ID param" },
      { method: "GET", path: "/api/search", summary: "Search endpoint with query param" },
      { method: "POST", path: "/api/execute", summary: "Execute command endpoint" },
      { method: "GET", path: "/api/debug", summary: "Debug info endpoint" },
      { method: "GET", path: "/api/file", summary: "Read file by path param" },
      { method: "GET", path: "/api/data", summary: "Get data by ID" },
    ];
  }
}
