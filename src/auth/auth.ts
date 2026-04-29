import { AuthConfig, AuthHookConfig, AuthRoleConfig } from "../core/config.loader.js";
import { ConfigError } from "../core/errors.js";
import { runProcess } from "../core/process.runner.js";
import { AuthContext } from "../orchestrator/context.js";

export async function resolveAuthContexts(auth?: AuthConfig): Promise<AuthContext[]> {
  if (!auth) {
    return [{ type: "none", role: "anonymous" }];
  }

  if (auth.roles && auth.roles.length > 0) {
    return Promise.all(auth.roles.map((role) => resolveRole(auth, role)));
  }

  if (auth.type === "none") {
    return [{ type: "none", role: auth.role || "anonymous", headers: auth.headers }];
  }

  return [
    await resolveRole(auth, {
      name: auth.role || auth.type,
      type: auth.type,
      token: auth.token,
      apiKey: auth.apiKey,
      headerName: auth.headerName,
      cookieName: auth.cookieName,
      cookieValue: auth.cookieValue,
      headers: auth.headers,
      preScan: auth.preScan,
    }),
  ];
}

export function buildAuthHeaders(auth?: AuthContext): Record<string, string> {
  const headers: Record<string, string> = {};

  if (!auth || auth.type === "none") {
    return headers;
  }

  for (const [key, value] of Object.entries(auth.headers || {})) {
    headers[key] = value;
  }

  switch (auth.type) {
    case "jwt":
      if (auth.token) {
        headers.Authorization = `Bearer ${auth.token}`;
      }
      break;
    case "apikey":
      if (auth.apiKey) {
        headers[auth.headerName || "X-API-Key"] = auth.apiKey;
      }
      break;
    case "session":
      if (auth.cookieValue) {
        const cookie = auth.cookieName
          ? `${auth.cookieName}=${auth.cookieValue}`
          : auth.cookieValue;
        headers.Cookie = mergeCookie(headers.Cookie, cookie);
      }
      break;
  }

  return headers;
}

async function resolveRole(auth: AuthConfig, role: AuthRoleConfig): Promise<AuthContext> {
  const type = role.type || auth.type;
  const hookValues =
    role.preScan || auth.preScan ? await runAuthHook(role.preScan || auth.preScan!) : {};

  return {
    type,
    role: role.name,
    token: role.token || hookValues.token || auth.token,
    apiKey: role.apiKey || hookValues.apiKey || auth.apiKey,
    headerName: role.headerName || auth.headerName,
    cookieName: role.cookieName || auth.cookieName,
    cookieValue: role.cookieValue || hookValues.cookieValue || auth.cookieValue,
    headers: {
      ...auth.headers,
      ...role.headers,
      ...hookValues.headers,
    },
  };
}

async function runAuthHook(hook: AuthHookConfig): Promise<{
  token?: string;
  apiKey?: string;
  cookieValue?: string;
  headers?: Record<string, string>;
}> {
  const result = await runProcess(hook.command, hook.args || [], {
    timeout: hook.timeout || 30000,
  });

  if (result.exitCode !== 0) {
    throw new ConfigError(`Auth hook failed: ${result.stderr || result.stdout}`);
  }

  const output = result.stdout.trim();
  if ((hook.output || "raw") === "raw") {
    return { token: output, apiKey: output, cookieValue: output };
  }

  try {
    const parsed = JSON.parse(output) as Record<string, unknown>;
    return {
      token: readString(parsed, hook.tokenField || "token"),
      apiKey: readString(parsed, hook.apiKeyField || "apiKey"),
      cookieValue: readString(parsed, hook.cookieField || "cookie"),
      headers: readRecord(parsed, hook.headersField || "headers"),
    };
  } catch (err) {
    throw new ConfigError(`Auth hook returned invalid JSON: ${(err as Error).message}`);
  }
}

function readString(value: Record<string, unknown>, field: string): string | undefined {
  const current = value[field];
  return typeof current === "string" ? current : undefined;
}

function readRecord(
  value: Record<string, unknown>,
  field: string
): Record<string, string> | undefined {
  const current = value[field];
  if (!current || typeof current !== "object" || Array.isArray(current)) {
    return undefined;
  }

  const result: Record<string, string> = {};
  for (const [key, nested] of Object.entries(current as Record<string, unknown>)) {
    if (typeof nested === "string") {
      result[key] = nested;
    }
  }
  return result;
}

function mergeCookie(existing: string | undefined, next: string): string {
  if (!existing) {
    return next;
  }
  return `${existing}; ${next}`;
}
