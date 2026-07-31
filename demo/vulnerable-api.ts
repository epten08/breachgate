/**
 * Intentionally Vulnerable Demo API
 *
 * This API contains deliberate security vulnerabilities for testing the security scanner.
 * DO NOT use this code in production!
 */

import http from "http";
import { URL } from "url";

const PORT = process.env.PORT || 3000;

// Simulated "database" with hardcoded credentials (vulnerability: hardcoded secrets)
const users: Record<string, { password: string; role: string }> = {
  admin: { password: "admin123", role: "admin" },
  user: { password: "password", role: "user" },
};

const sessions: Record<string, string> = {};

// Simple request body parser
async function parseBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => resolve(body));
  });
}

// Route handlers
const routes: Record<string, (req: http.IncomingMessage, res: http.ServerResponse, url: URL) => Promise<void>> = {
  // Health check
  "GET /health": async (_req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok" }));
  },

  // Login endpoint (vulnerability: no rate limiting, weak auth)
  "POST /api/login": async (req, res) => {
    const body = await parseBody(req);
    let data: { username?: string; password?: string };

    try {
      data = JSON.parse(body);
    } catch {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid JSON" }));
      return;
    }

    const user = users[data.username || ""];
    if (user && user.password === data.password) {
      const token = Math.random().toString(36).substring(2);
      sessions[token] = data.username!;

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ token, role: user.role }));
    } else {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid credentials" }));
    }
  },

  // User info (vulnerability: IDOR - no authorization check)
  "GET /api/users": async (_req, res, url) => {
    const id = url.searchParams.get("id");

    if (id && users[id]) {
      // Vulnerability: exposes password hash
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        username: id,
        role: users[id].role,
        // Intentionally exposing sensitive data
        passwordHint: users[id].password.substring(0, 3) + "***"
      }));
    } else {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "User not found" }));
    }
  },

  // Search endpoint (vulnerability: reflected XSS in error message)
  "GET /api/search": async (_req, res, url) => {
    const query = url.searchParams.get("q") || "";

    if (!query) {
      // Vulnerability: reflects user input without encoding
      res.writeHead(400, { "Content-Type": "text/html" });
      res.end(`<html><body>Error: Missing search query. You searched for: ${query}</body></html>`);
      return;
    }

    // Vulnerability: reflects the query into HTML with no encoding
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(`<html><body><p>Results for: ${query}</p></body></html>`);
  },

  // Execute endpoint (vulnerability: command injection simulation)
  "POST /api/execute": async (req, res) => {
    const body = await parseBody(req);
    let data: { command?: string };

    try {
      data = JSON.parse(body);
    } catch {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid JSON" }));
      return;
    }

    // Vulnerability: accepts arbitrary command (simulated)
    const command = data.command || "";

    // Nothing is ever executed. When the input contains shell metacharacters we
    // return a canned transcript so the endpoint is detectably exploitable
    // without this process running anything.
    console.log(`[VULN] Would execute command: ${command}`);

    if (/[;&|`$]/.test(command)) {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("uid=0(root) gid=0(root) groups=0(root)\nroot\n");
      return;
    }

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      status: "executed",
      command,
      output: "Command execution simulated"
    }));
  },

  // Debug endpoint (vulnerability: information disclosure)
  "GET /api/debug": async (_req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      env: {
        NODE_ENV: process.env.NODE_ENV,
        // Vulnerability: exposing internal paths
        cwd: process.cwd(),
        platform: process.platform,
      },
      users: Object.keys(users),
      activeSessions: Object.keys(sessions).length,
      // Vulnerability: version disclosure
      nodeVersion: process.version,
    }));
  },

  // File read endpoint (vulnerability: path traversal simulation)
  "GET /api/file": async (_req, res, url) => {
    const path = url.searchParams.get("path") || "";

    // Vulnerability: no path sanitization
    if (path.includes("..")) {
      console.log(`[VULN] Path traversal attempt detected: ${path}`);
      // Canned content. No file is opened.
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/sh\n");
      return;
    }

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      path,
      content: "File read simulated",
      warning: "Path traversal vulnerabilities may exist"
    }));
  },

  // SQL-like endpoint (vulnerability: SQL injection simulation)
  "GET /api/data": async (_req, res, url) => {
    const id = url.searchParams.get("id") || "";

    // Simulated SQL query building (vulnerable pattern)
    const simulatedQuery = `SELECT * FROM data WHERE id = '${id}'`;
    console.log(`[VULN] Simulated SQL: ${simulatedQuery}`);

    if (id.includes("'") || id.includes("--") || id.toLowerCase().includes("union")) {
      console.log(`[VULN] SQL injection attempt detected: ${id}`);
      // The unescaped value reaches the engine and the driver error is returned
      // verbatim to the caller. This is a canned string: no database is used.
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        error: "Database error",
        details: `You have an error in your SQL syntax near "${id}" at line 1`,
        query: simulatedQuery,
      }));
      return;
    }

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      id,
      data: { name: "Sample Data", value: 42 },
      _debug_query: simulatedQuery
    }));
  },
};

// Main server
const server = http.createServer(async (req, res) => {
  // Missing security headers (vulnerability)
  // No CORS, CSP, X-Frame-Options, etc.

  const url = new URL(req.url || "/", `http://localhost:${PORT}`);
  const routeKey = `${req.method} ${url.pathname}`;

  const handler = routes[routeKey];

  if (handler) {
    try {
      await handler(req, res, url);
    } catch (err) {
      // Vulnerability: detailed error messages
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        error: "Internal server error",
        details: (err as Error).message,
        stack: (err as Error).stack
      }));
    }
  } else {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found", path: url.pathname }));
  }
});

server.listen(PORT, () => {
  console.log(`Vulnerable Demo API running on http://localhost:${PORT}`);
  console.log("Available endpoints:");
  console.log("  GET  /health       - Health check");
  console.log("  POST /api/login    - Login (weak auth)");
  console.log("  GET  /api/users    - Get user info (IDOR)");
  console.log("  GET  /api/search   - Search (XSS)");
  console.log("  POST /api/execute  - Execute command (injection)");
  console.log("  GET  /api/debug    - Debug info (info disclosure)");
  console.log("  GET  /api/file     - Read file (path traversal)");
  console.log("  GET  /api/data     - Get data (SQL injection)");
});
