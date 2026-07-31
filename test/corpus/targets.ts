import http from "http";
import type { AddressInfo } from "net";
import { URL } from "url";

/**
 * The precision corpus.
 *
 * Half of these endpoints are genuinely exploitable and half are clean. The
 * clean half is the important half: any tool can find bugs in a deliberately
 * broken demo app, and measuring only against vulnerable targets tells you
 * nothing about how often you will block a good deploy.
 *
 * Each case declares the ground truth (`vulnerable`) so the harness can compute
 * precision and recall rather than eyeballing output.
 */

export interface CorpusCase {
  id: string;
  /** Ground truth: is this endpoint actually exploitable as tested? */
  vulnerable: boolean;
  category: string;
  description: string;
  request: { method: string; path: string; body?: Record<string, unknown> };
  expectedVulnerable: {
    statusCodes?: number[];
    bodyContains?: string[];
    headerMissing?: string[];
  };
}

export const CORPUS: CorpusCase[] = [
  // ------------------------------------------------------------------
  // TRUE POSITIVES: genuinely exploitable
  // ------------------------------------------------------------------
  {
    id: "vuln-sqli",
    vulnerable: true,
    category: "SQL Injection",
    description: "Unsanitised query parameter reaches the database",
    request: { method: "GET", path: "/vuln/sqli?id=1'%20OR%20'1'='1" },
    expectedVulnerable: { bodyContains: ["syntax error"] },
  },
  {
    id: "vuln-cmdi",
    vulnerable: true,
    category: "Command Injection",
    description: "Shell command built from user input",
    request: { method: "POST", path: "/vuln/exec", body: { cmd: "id; whoami" } },
    expectedVulnerable: { statusCodes: [200] },
  },
  {
    id: "vuln-traversal",
    vulnerable: true,
    category: "Path Traversal",
    description: "File path taken directly from the query string",
    request: { method: "GET", path: "/vuln/file?name=../../../../etc/passwd" },
    expectedVulnerable: { statusCodes: [200] },
  },
  {
    id: "vuln-ssrf",
    vulnerable: true,
    category: "Server-Side Request Forgery (SSRF)",
    description: "Server fetches an attacker-supplied URL",
    request: { method: "GET", path: "/vuln/fetch?url=http://169.254.169.254/latest/meta-data/" },
    expectedVulnerable: { statusCodes: [200] },
  },
  {
    id: "vuln-mass-assignment",
    vulnerable: true,
    category: "Mass Assignment",
    description: "Request body bound straight onto the user model",
    request: { method: "POST", path: "/vuln/profile", body: { name: "bob", role: "admin" } },
    expectedVulnerable: { statusCodes: [200] },
  },
  {
    // Regression: extractPayloads returned the whole query string including the
    // parameter name, so the reflection check compared against something the
    // response could never contain and every reflected XSS was missed. Found by
    // running the demo API; the corpus had a clean XSS case but no vulnerable
    // one, so recall stayed at 100% while the detector was dead.
    id: "vuln-xss-reflected",
    vulnerable: true,
    category: "Cross-Site Scripting (XSS)",
    description: "Reflects the query into HTML with no encoding",
    request: { method: "GET", path: "/vuln/echo?msg=%3Cscript%3Ealert(1)%3C%2Fscript%3E" },
    expectedVulnerable: { statusCodes: [200] },
  },
  {
    id: "vuln-stacktrace",
    vulnerable: true,
    category: "Information Disclosure",
    description: "Malformed input crashes the handler and leaks a stack trace",
    request: { method: "GET", path: "/vuln/parse?input=%7Bmalformed" },
    expectedVulnerable: { statusCodes: [500] },
  },

  // ------------------------------------------------------------------
  // TRUE NEGATIVES: clean endpoints that naive detectors flag anyway
  // ------------------------------------------------------------------
  {
    id: "clean-parameterised",
    vulnerable: false,
    category: "SQL Injection",
    description: "Same shape as the SQLi endpoint but parameterised",
    request: { method: "GET", path: "/clean/query?id=1'%20OR%20'1'='1" },
    expectedVulnerable: { bodyContains: ["syntax error"] },
  },
  {
    id: "clean-no-headers",
    vulnerable: false,
    category: "SQL Injection",
    description: "Clean handler on a server that sets no security headers",
    request: { method: "GET", path: "/clean/items?q=1'%20OR%20'1'='1" },
    expectedVulnerable: { statusCodes: [200] },
  },
  {
    id: "clean-echo",
    vulnerable: false,
    category: "Cross-Site Scripting (XSS)",
    description: "Reflects input but escapes it correctly",
    request: { method: "GET", path: "/clean/echo?msg=%3Cscript%3Ealert(1)%3C/script%3E" },
    expectedVulnerable: { statusCodes: [200] },
  },
  {
    id: "clean-auth-enforced",
    vulnerable: false,
    category: "Broken Access Control",
    description: "Admin route correctly rejects an unauthenticated caller",
    request: { method: "GET", path: "/clean/admin" },
    expectedVulnerable: { statusCodes: [200] },
  },
  {
    id: "clean-error-handled",
    vulnerable: false,
    category: "Information Disclosure",
    description: "Error path returns a generic message with no internals",
    request: { method: "GET", path: "/clean/error" },
    expectedVulnerable: { statusCodes: [500] },
  },
  {
    id: "clean-word-error",
    vulnerable: false,
    category: "SQL Injection",
    description: "Legitimate response body that contains the word 'error'",
    request: { method: "GET", path: "/clean/status?id=1'%20OR%20'1'='1" },
    expectedVulnerable: { bodyContains: ["error"] },
  },
  {
    id: "clean-rejects-role",
    vulnerable: false,
    category: "Mass Assignment",
    description: "Ignores the privileged field instead of binding it",
    request: { method: "POST", path: "/clean/profile", body: { name: "bob", role: "admin" } },
    expectedVulnerable: { statusCodes: [200] },
  },
  {
    id: "clean-blocks-ssrf",
    vulnerable: false,
    category: "Server-Side Request Forgery (SSRF)",
    description: "Rejects link-local destinations",
    request: { method: "GET", path: "/clean/fetch?url=http://169.254.169.254/latest/meta-data/" },
    expectedVulnerable: { statusCodes: [200] },
  },
  {
    // Regression: found by running the demo API, not by code review.
    // captureBaselines strips the query string, so an endpoint that requires a
    // parameter returns 4xx unparameterised and 2xx once parameters are given.
    // That status change was being reported as an authorization bypass, and it
    // fired on three unrelated demo endpoints including a plain search route.
    id: "clean-requires-param",
    vulnerable: false,
    category: "Broken Access Control",
    description: "Returns 400 without its required parameter and 200 with it",
    request: { method: "GET", path: "/clean/requires-param?q=hello" },
    expectedVulnerable: { statusCodes: [200] },
  },
  {
    // Regression: an endpoint that legitimately returns a user record contains
    // "role":"admin" in its response. That is not mass assignment. Proof now
    // requires that we sent the privileged value ourselves.
    id: "clean-returns-role",
    vulnerable: false,
    category: "Mass Assignment",
    description: "Returns an existing user's role without being sent one",
    request: { method: "GET", path: "/clean/whoami?id=admin" },
    expectedVulnerable: { statusCodes: [200] },
  },
];

/**
 * Start the corpus server.
 *
 * The vulnerable handlers emit realistic exploitation signals. The clean
 * handlers are deliberately adversarial toward naive detectors: they echo
 * input safely, use the word "error" in normal output, return 500 without
 * leaking internals, and set no security headers at all.
 */
export async function startCorpusServer(): Promise<{
  baseUrl: string;
  close: () => Promise<void>;
}> {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;

    // Deliberately no security headers anywhere in this server. A correct tool
    // must still return SAFE for every /clean route.
    const json = (status: number, body: unknown) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
    };
    const text = (status: number, body: string, type = "text/plain") => {
      res.writeHead(status, { "Content-Type": type });
      res.end(body);
    };

    const readBody = (cb: (body: Record<string, unknown>) => void) => {
      let raw = "";
      req.on("data", (chunk) => (raw += chunk));
      req.on("end", () => {
        try {
          cb(JSON.parse(raw || "{}"));
        } catch {
          cb({});
        }
      });
    };

    switch (path) {
      // ---------------- vulnerable ----------------
      // Each of these behaves normally for a benign request and only produces
      // the exploitation signal when the malicious payload is present. That is
      // what a real vulnerable endpoint does, and it is what makes baseline
      // diffing a meaningful test rather than a formality.
      case "/vuln/sqli": {
        const id = url.searchParams.get("id");
        if (!id || /^\d+$/.test(id)) {
          return json(200, { id: Number(id ?? 1), name: "widget" });
        }
        return text(500, `Error: You have an error in your SQL syntax near "${id}" at line 1`);
      }

      case "/vuln/exec":
        return readBody((body) => {
          const cmd = String(body.cmd ?? "");
          if (!cmd) return json(200, { usage: "POST { cmd }" });
          if (/[;&|`$]/.test(cmd)) {
            return text(200, "uid=0(root) gid=0(root) groups=0(root)\nroot\n");
          }
          return json(200, { output: "ok" });
        });

      case "/vuln/file": {
        const name = url.searchParams.get("name");
        if (!name) return json(200, { files: ["readme.txt"] });
        if (name.includes("..")) {
          return text(
            200,
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/sh\n"
          );
        }
        return text(200, "hello world");
      }

      case "/vuln/fetch": {
        const target = url.searchParams.get("url");
        if (!target) return json(200, { fetched: null });
        if (target.includes("169.254.169.254")) {
          return json(200, {
            Code: "Success",
            AccessKeyId: "ASIAIOSFODNN7EXAMPLE",
            Token: "abc123",
          });
        }
        return json(200, { fetched: target, body: "external content" });
      }

      case "/vuln/profile":
        return readBody((body) =>
          // Binds whatever it is given, including role.
          json(200, { id: 1, name: body.name ?? "anon", role: body.role ?? "user" })
        );

      case "/vuln/echo": {
        const msg = url.searchParams.get("msg");
        if (!msg) return text(200, "<html><body><p>nothing</p></body></html>", "text/html");
        // No encoding at all.
        return text(200, `<html><body><p>${msg}</p></body></html>`, "text/html");
      }

      case "/vuln/parse": {
        const input = url.searchParams.get("input");
        if (!input) return json(200, { parsed: null });
        try {
          return json(200, { parsed: JSON.parse(input) });
        } catch {
          return text(
            500,
            "SyntaxError: Unexpected token m in JSON at position 1\n    at JSON.parse (<anonymous>)\n    at handler (/srv/app/routes/parse.js:42:11)\n    at Layer.handle (/srv/app/node_modules/express/lib/router/layer.js:95:5)"
          );
        }
      }

      // ---------------- clean ----------------
      case "/clean/query":
        // Parameterised: the payload is treated as data and matches nothing.
        return json(200, { results: [], query: "parameterised" });

      case "/clean/items":
        return json(200, { items: [{ id: 1, name: "widget" }] });

      case "/clean/echo": {
        const msg = url.searchParams.get("msg") ?? "";
        const escaped = msg
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;");
        return text(200, `<p>${escaped}</p>`, "text/html");
      }

      case "/clean/admin":
        return json(403, { error: "forbidden" });

      case "/clean/error":
        return json(500, { error: "Internal server error" });

      case "/clean/status":
        // Contains the word "error" legitimately. A detector keying on the
        // string rather than a database error pattern will false positive.
        return json(200, { status: "ok", errorCount: 0, message: "no error conditions detected" });

      case "/clean/profile":
        return readBody((body) => json(200, { id: 1, name: body.name, role: "user" }));

      case "/clean/fetch":
        return json(400, { error: "destination not allowed" });

      case "/clean/requires-param": {
        // 400 without the parameter, 200 with it. Extremely common, and not a
        // security property of any kind.
        const q = url.searchParams.get("q");
        if (!q) return json(400, { error: "q is required" });
        return json(200, { results: [], q });
      }

      case "/clean/whoami": {
        // Legitimately returns a role field. We did not send one.
        const id = url.searchParams.get("id");
        if (!id) return json(404, { error: "not found" });
        return json(200, { username: id, role: "admin", department: "platform" });
      }

      default:
        return json(404, { error: "route not found" });
    }
  });

  await new Promise<void>((resolve) => server.listen(0, resolve));
  const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  return {
    baseUrl,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
