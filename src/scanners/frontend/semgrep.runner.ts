import { tmpdir } from "os";
import { writeFileSync, unlinkSync } from "fs";
import { join } from "path";
import { RawFinding } from "../../findings/raw.finding.js";
import { runProcess, checkCommand } from "../../core/process.runner.js";
import { ScannerUnavailableError } from "../../core/errors.js";
import { logger } from "../../core/logger.js";

const SCANNER_NAME = "Semgrep Frontend";

// Custom rules covering the most impactful React/frontend security patterns
const REACT_RULES_YAML = `
rules:
  - id: react-dangerous-html
    pattern: dangerouslySetInnerHTML={{__html: $X}}
    message: "dangerouslySetInnerHTML usage detected — XSS risk if value includes unsanitized user input"
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: CWE-79

  - id: localstorage-auth-token
    patterns:
      - pattern: localStorage.setItem($KEY, ...)
      - metavariable-regex:
          metavariable: $KEY
          regex: '"(token|auth|jwt|session|credential|access_token|auth_token|id_token)"'
    message: "Auth token stored in localStorage — tokens are accessible via XSS; use httpOnly cookies"
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: CWE-922

  - id: sessionstorage-auth-token
    patterns:
      - pattern: sessionStorage.setItem($KEY, ...)
      - metavariable-regex:
          metavariable: $KEY
          regex: '"(token|auth|jwt|session|credential|access_token|auth_token|id_token)"'
    message: "Auth token stored in sessionStorage — accessible via XSS; use httpOnly cookies"
    languages: [javascript, typescript]
    severity: MEDIUM
    metadata:
      cwe: CWE-922

  - id: insecure-http-fetch
    patterns:
      - pattern: fetch("http://$HOST/...")
      - pattern-not: fetch("http://localhost/...")
      - pattern-not: fetch("http://localhost:$PORT/...")
      - pattern-not: fetch("http://127.0.0.1/...")
    message: "Insecure HTTP endpoint in fetch() — use HTTPS to prevent man-in-the-middle attacks"
    languages: [javascript, typescript]
    severity: WARNING
    metadata:
      cwe: CWE-319

  - id: insecure-http-axios
    patterns:
      - pattern: axios.$METHOD("http://$HOST/...")
      - pattern-not: axios.$METHOD("http://localhost/...")
      - pattern-not: axios.$METHOD("http://localhost:$PORT/...")
      - pattern-not: axios.$METHOD("http://127.0.0.1/...")
    message: "Insecure HTTP endpoint in axios — use HTTPS to prevent man-in-the-middle attacks"
    languages: [javascript, typescript]
    severity: WARNING
    metadata:
      cwe: CWE-319

  - id: eval-usage
    pattern: eval($X)
    message: "eval() usage is dangerous and can enable code injection — avoid eval entirely"
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: CWE-95

  - id: innerhtml-assignment
    patterns:
      - pattern: $EL.innerHTML = $X
      - pattern-not: $EL.innerHTML = ""
    message: "innerHTML assignment can enable XSS if value includes user-controlled content"
    languages: [javascript, typescript]
    severity: WARNING
    metadata:
      cwe: CWE-79

  - id: document-write
    pattern: document.write($X)
    message: "document.write() can enable XSS if called with user-controlled input"
    languages: [javascript, typescript]
    severity: WARNING
    metadata:
      cwe: CWE-79

  - id: client-side-role-check
    patterns:
      - pattern: |
          if ($OBJ.role === $ROLE) { ... }
    message: "Client-side role check — authorization must be enforced server-side; client checks are bypassable"
    languages: [javascript, typescript]
    severity: WARNING
    metadata:
      cwe: CWE-602

  - id: hardcoded-secret-var
    patterns:
      - pattern: const $VAR = "$VALUE"
      - metavariable-regex:
          metavariable: $VAR
          regex: (apiKey|api_key|secretKey|secret_key|accessKey|access_key|privateKey|private_key|clientSecret|client_secret|stripeKey|firebaseKey)
      - metavariable-regex:
          metavariable: $VALUE
          regex: .{8,}
    message: "Potential hardcoded secret — rotate the credential and store in environment variables"
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: CWE-798

  - id: postmessage-wildcard-origin
    pattern: $WINDOW.postMessage($MSG, "*")
    message: "postMessage with wildcard origin '*' can leak data to malicious sites — specify the exact target origin"
    languages: [javascript, typescript]
    severity: WARNING
    metadata:
      cwe: CWE-346

  - id: missing-message-origin-check
    patterns:
      - pattern: |
          window.addEventListener("message", function($EVENT) {
            ...
          })
      - pattern-not: |
          window.addEventListener("message", function($EVENT) {
            ...
            if ($EVENT.origin ...) { ... }
            ...
          })
    message: "message event listener missing origin check — validate event.origin before processing postMessage data"
    languages: [javascript, typescript]
    severity: WARNING
    metadata:
      cwe: CWE-346
`.trim();

interface SemgrepResult {
  results: SemgrepFinding[];
  errors: unknown[];
}

interface SemgrepFinding {
  check_id: string;
  path: string;
  start: { line: number };
  extra: {
    message: string;
    severity: string;
    lines?: string;
    metadata?: { cwe?: string };
  };
}

export async function runSemgrepScan(targetDir: string): Promise<RawFinding[]> {
  const hasSemgrep = await checkCommand("semgrep");
  if (!hasSemgrep) {
    throw new ScannerUnavailableError(
      "Semgrep is not installed — static frontend analysis skipped",
      SCANNER_NAME,
      undefined,
      "Install semgrep: pip install semgrep  |  brew install semgrep  |  https://semgrep.dev/docs/getting-started"
    );
  }

  const rulesPath = join(tmpdir(), `breachgate-semgrep-${Date.now()}.yml`);
  writeFileSync(rulesPath, REACT_RULES_YAML, "utf-8");

  try {
    logger.debug(`Running semgrep on ${targetDir}`);
    const result = await runProcess(
      "semgrep",
      ["--config", rulesPath, "--json", "--quiet", "--no-rewrite-rule-ids", targetDir],
      { timeout: 120000 }
    );

    return parseSemgrepOutput(result.stdout);
  } finally {
    try {
      unlinkSync(rulesPath);
    } catch {
      // temp file cleanup failure is non-fatal
    }
  }
}

function parseSemgrepOutput(stdout: string): RawFinding[] {
  if (!stdout.trim()) return [];

  let data: SemgrepResult;
  try {
    data = JSON.parse(stdout) as SemgrepResult;
  } catch {
    logger.warn("Failed to parse Semgrep JSON output");
    return [];
  }

  return data.results.map((r) => ({
    source: SCANNER_NAME,
    category: mapSemgrepCategory(r.check_id),
    description: r.extra.message,
    endpoint: `${r.path}:${r.start.line}`,
    severityHint: mapSemgrepSeverity(r.extra.severity),
    evidence: r.extra.lines?.trim(),
    cwe: r.extra.metadata?.cwe,
    reference: "https://owasp.org/www-project-top-ten/",
  }));
}

function mapSemgrepSeverity(severity: string): string {
  switch (severity.toUpperCase()) {
    case "ERROR":
      return "HIGH";
    case "WARNING":
      return "MEDIUM";
    case "MEDIUM":
      return "MEDIUM";
    default:
      return "LOW";
  }
}

function mapSemgrepCategory(checkId: string): string {
  if (
    checkId.includes("dangerous-html") ||
    checkId.includes("innerhtml") ||
    checkId.includes("document-write")
  ) {
    return "Cross-Site Scripting (XSS)";
  }
  if (checkId.includes("localstorage") || checkId.includes("sessionstorage")) {
    return "Insecure Token Storage";
  }
  if (checkId.includes("http")) {
    return "Insecure Communication";
  }
  if (checkId.includes("eval")) {
    return "Code Injection";
  }
  if (checkId.includes("role")) {
    return "Broken Access Control";
  }
  if (checkId.includes("postmessage") || checkId.includes("message-origin")) {
    return "Cross-Origin Communication";
  }
  if (checkId.includes("secret") || checkId.includes("hardcoded")) {
    return "Hardcoded Secret";
  }
  return "Security Misconfiguration";
}
