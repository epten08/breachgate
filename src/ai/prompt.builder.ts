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
    return `You are a security testing AI assistant specialized in API security testing.
Your role is to generate security test cases that identify vulnerabilities in REST APIs.

Guidelines:
- Focus on OWASP Top 10 API Security risks
- Generate realistic attack payloads
- Consider authentication bypass, injection attacks, and broken access control
- Provide specific, actionable test cases with expected outcomes
- Format responses as JSON for easy parsing

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
    const jwtGuidance = this.ctx.auth?.type === "jwt"
      ? `\nJWT Auth detected — also consider: algorithm confusion (alg:none), claim tampering (role, is_admin, sub), expired token acceptance.`
      : "";

    return `Generate exactly ${count} security test cases for this API endpoint:

Endpoint: ${endpoint.method} ${endpoint.path}
${endpoint.summary ? `Description: ${endpoint.summary}` : ""}
${params}
${body}${jwtGuidance}

Attack categories to consider (pick the most relevant for this endpoint):
- SQL Injection, Command Injection, Path Traversal, Cross-Site Scripting (XSS)
- Broken Access Control, IDOR, Mass Assignment
- SSRF (if endpoint accepts URLs, webhooks, or file paths)
- JWT attacks (if auth is JWT)
- Information Disclosure

For query-parameter endpoints use path like "/api/data?id=PAYLOAD" not body fields.

CRITICAL RULES for expectedVulnerable — violations cause false positives:
1. statusCodes: ONLY include 200 or 201. A 2xx response proves the attack succeeded.
   NEVER include 401, 403, 404, 422.
2. bodyContains: UNIQUE PROOF of exploitation ONLY:
   - SQL error: "syntax error", "You have an error in your SQL"
   - Reflected payload: "<script>alert", "1=1"
   - Leaked DB object: "information_schema", "pg_catalog"
   - SSRF hit: "169.254", "internal", "amazonaws"
   - Mass assignment accepted: the injected field name reflected back with attacker value
   FORBIDDEN (appear in every normal response — do NOT use):
   "id", "success", "error", "message", "data", "status", "result",
   "balance", "approved", "created", "updated", "name", "type", "code"
3. headerMissing: ONLY "x-content-type-options", "x-frame-options", "strict-transport-security"

Respond with ONLY a JSON array — no explanation, no markdown fences:
[
  {
    "name": "Attack name - METHOD /path",
    "endpoint": "${endpoint.method} ${endpoint.path}",
    "category": "SQL Injection | Command Injection | Path Traversal | Cross-Site Scripting (XSS) | Broken Access Control | SSRF | Mass Assignment | Information Disclosure | etc.",
    "description": "One sentence describing what this test checks",
    "request": {
      "method": "${endpoint.method}",
      "path": "/api/path?param=payload",
      "body": { "field": "payload" }
    },
    "expectedVulnerable": {
      "statusCodes": [200],
      "bodyContains": ["exact exploitation evidence string"],
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
    return `Evaluate this security test result:

Test Case:
${testCase}

API Response:
- Status: ${response.status}
- Headers: ${JSON.stringify(response.headers, null, 2)}
- Body: ${response.body.substring(0, 1000)}${response.body.length > 1000 ? "..." : ""}

Analyze if this response indicates a security vulnerability.

Respond with JSON:
{
  "isVulnerable": true|false,
  "confidence": 0.0-1.0,
  "vulnerability": {
    "type": "Vulnerability type (e.g., SQL Injection, XSS)",
    "severity": "LOW|MEDIUM|HIGH|CRITICAL",
    "evidence": "What in the response indicates the vulnerability",
    "recommendation": "How to fix this issue"
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
