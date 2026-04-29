import { Scanner } from "../scanner.js";
import { ExecutionContext } from "../../orchestrator/context.js";
import { RawFinding } from "../../findings/raw.finding.js";
import { buildAuthHeaders } from "../../auth/auth.js";
import { logger } from "../../core/logger.js";

const INTROSPECTION_QUERY = `
{
  __schema {
    types { name kind fields { name } }
    queryType { name fields { name description } }
    mutationType { name fields { name description } }
  }
}
`.trim();

// Deeply nested query used to probe for query-complexity DoS.
const DEEP_NESTING_QUERY = `
{ __type(name:"Query") { fields { type { fields { type { fields { type { name } } } } } } } }
`.trim();

interface GraphQLResponse {
  data?: unknown;
  errors?: Array<{ message: string; extensions?: Record<string, unknown> }>;
}

export class GraphQLScanner implements Scanner {
  name = "GraphQL Security Tester";
  category = "dynamic" as const;

  async run(ctx: ExecutionContext): Promise<RawFinding[]> {
    logger.scanner(this.name, "start", "Probing GraphQL endpoint");

    const findings: RawFinding[] = [];

    // Discover common GraphQL endpoint paths.
    const candidates = ["/graphql", "/api/graphql", "/query", "/gql"];
    let graphqlUrl: string | null = null;

    for (const path of candidates) {
      const url = new URL(path, ctx.targetUrl);
      try {
        const resp = await this.post(url.toString(), { query: "{ __typename }" }, ctx);
        if (resp.ok) {
          const body = await resp.json() as GraphQLResponse;
          if (body.data !== undefined || body.errors !== undefined) {
            graphqlUrl = url.toString();
            logger.debug(`GraphQL endpoint found: ${graphqlUrl}`);
            break;
          }
        }
      } catch {
        // Path not a GraphQL endpoint — continue.
      }
    }

    if (!graphqlUrl) {
      logger.debug("GraphQL: no endpoint detected, skipping");
      return [];
    }

    // 1. Introspection enabled in production
    const introResult = await this.runIntrospection(graphqlUrl, ctx, findings);

    // 2. Query complexity / deep-nesting DoS
    await this.runDepthProbe(graphqlUrl, ctx, findings);

    // 3. Field suggestion enumeration (only if introspection disabled)
    if (!introResult.enabled) {
      await this.runFieldSuggestion(graphqlUrl, ctx, findings);
    }

    // 4. Injection via query variables
    await this.runInjectionProbe(graphqlUrl, ctx, findings, introResult.queryFields);

    // 5. Broken object-level auth: query other users' data
    await this.runIdorProbe(graphqlUrl, ctx, findings, introResult.queryFields);

    logger.scanner(this.name, "done", `Found ${findings.length} GraphQL issue(s)`);
    return findings;
  }

  private async runIntrospection(
    url: string,
    ctx: ExecutionContext,
    findings: RawFinding[]
  ): Promise<{ enabled: boolean; queryFields: string[] }> {
    try {
      const resp = await this.post(url, { query: INTROSPECTION_QUERY }, ctx);
      const body = await resp.json() as GraphQLResponse;

      if (body.data && (body.data as Record<string, unknown>).__schema) {
        findings.push({
          source: this.name,
          category: "Information Disclosure",
          description: "GraphQL introspection is enabled in production, exposing full schema to attackers.",
          endpoint: `POST ${new URL(url).pathname}`,
          severityHint: "MEDIUM",
          evidence: `Introspection query returned full __schema at ${url}`,
          reference: "Disable introspection in production. Set introspection: false in your GraphQL server config.",
        });

        // Extract query field names for use in subsequent probes.
        const schema = (body.data as Record<string, unknown>).__schema as {
          queryType?: { fields?: Array<{ name: string }> };
        };
        const fields = schema.queryType?.fields?.map(f => f.name) ?? [];
        return { enabled: true, queryFields: fields };
      }
    } catch {
      // Introspection not enabled or endpoint not reachable.
    }
    return { enabled: false, queryFields: [] };
  }

  private async runDepthProbe(url: string, ctx: ExecutionContext, findings: RawFinding[]): Promise<void> {
    try {
      const start = Date.now();
      const resp = await this.post(url, { query: DEEP_NESTING_QUERY }, ctx);
      const elapsed = Date.now() - start;
      const body = await resp.json() as GraphQLResponse;

      if (elapsed > 3000 || (body.data !== undefined && !body.errors?.length)) {
        findings.push({
          source: this.name,
          category: "Security Misconfiguration",
          description: "GraphQL endpoint accepts deeply nested queries without depth limiting, enabling query complexity DoS.",
          endpoint: `POST ${new URL(url).pathname}`,
          severityHint: "MEDIUM",
          evidence: `Deep-nesting query responded in ${elapsed}ms without a depth-limit error.`,
          reference: "Implement query depth limiting (e.g., graphql-depth-limit) and query complexity analysis.",
        });
      }
    } catch {
      // Endpoint rejected or timed out — not a DoS vector here.
    }
  }

  private async runFieldSuggestion(url: string, ctx: ExecutionContext, findings: RawFinding[]): Promise<void> {
    // GraphQL servers often suggest correct field names in error messages even with introspection off.
    try {
      const resp = await this.post(url, { query: "{ usr { id } }" }, ctx);
      const body = await resp.json() as GraphQLResponse;
      const errorMsg = body.errors?.map(e => e.message).join(" ") ?? "";

      if (/did you mean/i.test(errorMsg)) {
        findings.push({
          source: this.name,
          category: "Information Disclosure",
          description: "GraphQL field suggestions are enabled — attackers can enumerate schema fields even without introspection.",
          endpoint: `POST ${new URL(url).pathname}`,
          severityHint: "LOW",
          evidence: `Error message contains field suggestion: "${errorMsg.slice(0, 200)}"`,
          reference: "Disable field suggestions. In Apollo Server set: suggestionList: () => [].",
        });
      }
    } catch {
      // Not actionable.
    }
  }

  private async runInjectionProbe(
    url: string,
    ctx: ExecutionContext,
    findings: RawFinding[],
    queryFields: string[]
  ): Promise<void> {
    const field = queryFields[0] ?? "user";
    const injectionQuery = `{ ${field}(id: "1' OR '1'='1") { id } }`;

    try {
      const resp = await this.post(url, { query: injectionQuery }, ctx);
      const body = await resp.json() as GraphQLResponse;
      const bodyStr = JSON.stringify(body);

      if (/sql.*error|syntax.*error|mysql|postgresql/i.test(bodyStr)) {
        findings.push({
          source: this.name,
          category: "SQL Injection",
          description: "GraphQL query argument is passed directly to a SQL query without sanitization.",
          endpoint: `POST ${new URL(url).pathname}`,
          severityHint: "CRITICAL",
          evidence: `SQL error in response to injection payload in ${field}(id) argument.`,
          reference: "Use parameterized queries or an ORM that prevents raw SQL. Never concatenate GraphQL arguments into SQL.",
        });
      }
    } catch {
      // Not reachable.
    }
  }

  private async runIdorProbe(
    url: string,
    ctx: ExecutionContext,
    findings: RawFinding[],
    queryFields: string[]
  ): Promise<void> {
    // Try to query user IDs 1–5 and check if different user data is returned.
    const field = queryFields.find(f => /user|account|profile/i.test(f)) ?? queryFields[0];
    if (!field) return;

    const responses = new Set<string>();
    for (let id = 1; id <= 3; id++) {
      try {
        const resp = await this.post(url, { query: `{ ${field}(id: ${id}) { id email username } }` }, ctx);
        const body = await resp.json() as GraphQLResponse;
        if (body.data && !body.errors?.length) {
          responses.add(JSON.stringify(body.data));
        }
      } catch {
        // Field doesn't accept id — skip.
      }
    }

    if (responses.size > 1) {
      findings.push({
        source: this.name,
        category: "Broken Access Control",
        description: "GraphQL query returns other users' data by varying the ID argument without authorization checks (IDOR).",
        endpoint: `POST ${new URL(url).pathname}`,
        severityHint: "HIGH",
        evidence: `${field}(id: 1..3) returned distinct user records without auth validation.`,
        reference: "Scope all GraphQL resolvers to the authenticated user. Never resolve arbitrary IDs without ownership checks.",
      });
    }
  }

  private post(url: string, body: unknown, ctx: ExecutionContext): Promise<Response> {
    return fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "SecurityBot/1.0",
        ...buildAuthHeaders(ctx.auth),
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10000),
    });
  }
}
