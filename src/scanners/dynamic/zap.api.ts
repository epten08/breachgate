import { Scanner } from "../scanner.js";
import { ExecutionContext } from "../../orchestrator/context.js";
import { RawFinding } from "../../findings/raw.finding.js";
import { runProcess, checkCommand } from "../../core/process.runner.js";
import { ScannerError, ScannerUnavailableError } from "../../core/errors.js";
import { logger } from "../../core/logger.js";
import { sleep } from "../../utils/network.js";
import { buildAuthHeaders } from "../../auth/auth.js";
import {
  allowsDestructiveMethod,
  isPathExcluded,
  shouldRunZapActiveScan,
} from "../../safety/safety.js";

interface ZapAlert {
  pluginid: string;
  alertRef: string;
  alert: string;
  name: string;
  riskcode: string;
  confidence: string;
  riskdesc: string;
  desc: string;
  solution: string;
  reference: string;
  cweid: string;
  wascid: string;
  uri: string;
  method: string;
  evidence?: string;
  attack?: string;
  param?: string;
}

const RISK_MAP: Record<string, string> = {
  "0": "INFO",
  "1": "LOW",
  "2": "MEDIUM",
  "3": "HIGH",
};

export class ZapApiScanner implements Scanner {
  name = "OWASP ZAP API";
  category = "dynamic" as const;

  private zapPort = 8080;
  private zapApiKey: string | undefined;
  private zapProcess: boolean = false;
  private useDocker: boolean = false;
  private dockerContainerId: string | undefined;

  constructor() {
    // Read ZAP API key from environment variable
    this.zapApiKey = process.env.ZAP_API_KEY;
  }

  async run(ctx: ExecutionContext): Promise<RawFinding[]> {
    logger.scanner(this.name, "start", `Scanning ${ctx.targetUrl}`);

    const zapMode = await this.checkZapAvailable();
    if (zapMode === "none") {
      throw new ScannerUnavailableError(
        "OWASP ZAP is not running and no ZAP Docker image or CLI command is available",
        this.name
      );
    }

    this.useDocker = zapMode === "docker";

    try {
      if (this.useDocker) {
        await this.startZapDocker(ctx);
      } else {
        await this.ensureZapRunning();
      }

      const findings = await this.runApiScan(ctx);
      logger.scanner(this.name, "done", `Found ${findings.length} issues`);
      return findings;
    } catch (err) {
      logger.scanner(this.name, "error", (err as Error).message);
      throw new ScannerError(
        `ZAP scan failed: ${(err as Error).message}`,
        this.name,
        err as Error
      );
    } finally {
      await this.cleanup();
    }
  }

  private async checkZapAvailable(): Promise<"api" | "docker" | "none"> {
    // First check if ZAP is already running on the expected port
    const hasApiKey = !!this.zapApiKey;
    logger.info(`Checking ZAP on port ${this.zapPort} (API key: ${hasApiKey ? "configured" : "not set"})`);

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      // Include API key if configured
      const url = this.buildZapUrl("/JSON/core/view/version/");

      const response = await fetch(url, {
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        const data = await response.json();
        logger.info(`ZAP API detected: version ${JSON.stringify(data)}`);
        return "api";
      } else if (response.status === 403) {
        logger.warn("ZAP API returned 403 - API key required. Set ZAP_API_KEY environment variable.");
      } else {
        logger.debug(`ZAP API responded with status ${response.status}`);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown error";
      logger.debug(`ZAP API connection failed: ${message}`);
    }

    // Check for ZAP Docker image
    const hasDocker = await checkCommand("docker");
    if (hasDocker) {
      const imageCheck = await runProcess("docker", ["images", "-q", "ghcr.io/zaproxy/zaproxy"], { timeout: 10000 });
      if (imageCheck.stdout.trim()) {
        logger.info("ZAP Docker image available, will use Docker mode");
        return "docker";
      }
      // Also check for older image name
      const oldImageCheck = await runProcess("docker", ["images", "-q", "owasp/zap2docker-stable"], { timeout: 10000 });
      if (oldImageCheck.stdout.trim()) {
        logger.info("ZAP Docker image (owasp/zap2docker-stable) available");
        return "docker";
      }
    }

    // Check for CLI commands to start ZAP
    const zapCommands = ["zap.sh", "zap-cli", "zap.bat"];
    for (const cmd of zapCommands) {
      if (await checkCommand(cmd)) {
        logger.info(`Found ZAP CLI command: ${cmd}`);
        return "api";
      }
    }

    return "none";
  }

  private async startZapDocker(ctx: ExecutionContext): Promise<void> {
    logger.info("Starting ZAP via Docker");

    // Determine which image to use
    let zapImage = "ghcr.io/zaproxy/zaproxy:stable";
    const imageCheck = await runProcess("docker", ["images", "-q", "ghcr.io/zaproxy/zaproxy"], { timeout: 10000 });
    if (!imageCheck.stdout.trim()) {
      zapImage = "owasp/zap2docker-stable";
    }

    // Start ZAP in daemon mode with API enabled
    // Use host.docker.internal to allow ZAP to reach the target on localhost
    const targetUrl = ctx.targetUrl.replace("localhost", "host.docker.internal");

    const result = await runProcess(
      "docker",
      [
        "run", "-d", "--rm",
        "-p", `${this.zapPort}:${this.zapPort}`,
        "--add-host=host.docker.internal:host-gateway",
        zapImage,
        "zap.sh", "-daemon",
        "-port", String(this.zapPort),
        "-host", "0.0.0.0",
        "-config", "api.disablekey=true",
        "-config", "api.addrs.addr.name=.*",
        "-config", "api.addrs.addr.regex=true"
      ],
      { timeout: 30000 }
    );

    if (result.exitCode !== 0) {
      throw new ScannerError(`Failed to start ZAP Docker: ${result.stderr}`, this.name);
    }

    this.dockerContainerId = result.stdout.trim();
    logger.info(`ZAP Docker container started: ${this.dockerContainerId.substring(0, 12)}`);

    // Wait for ZAP to be ready
    for (let i = 0; i < 30; i++) {
      await sleep(2000);
      try {
        const url = this.buildZapUrl("/JSON/core/view/version/");
        const response = await fetch(url);
        if (response.ok) {
          logger.info("ZAP Docker is ready");
          return;
        }
      } catch {
        // Keep waiting
      }
    }

    throw new ScannerError("ZAP Docker failed to start within timeout", this.name);
  }

  private buildZapUrl(path: string, params?: Record<string, string>): string {
    // Use 127.0.0.1 instead of localhost - ZAP binds to 127.0.0.1 by default
    const url = new URL(path, `http://127.0.0.1:${this.zapPort}`);

    // Add API key if configured
    if (this.zapApiKey) {
      url.searchParams.set("apikey", this.zapApiKey);
    }

    // Add other params
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        url.searchParams.set(key, value);
      }
    }

    return url.toString();
  }

  private async ensureZapRunning(): Promise<void> {
    try {
      const url = this.buildZapUrl("/JSON/core/view/version/");
      const response = await fetch(url);
      if (response.ok) {
        logger.debug("ZAP already running");
        return;
      }
    } catch {
      // ZAP not running, start it
    }

    logger.debug("Starting ZAP in daemon mode");

    const zapCmd = process.platform === "win32" ? "zap.bat" : "zap.sh";

    try {
      runProcess(
        zapCmd,
        ["-daemon", "-port", String(this.zapPort), "-config", "api.disablekey=true"],
        { timeout: 10000, shell: process.platform === "win32" }
      ).catch(() => {});

      this.zapProcess = true;

      for (let i = 0; i < 30; i++) {
        await sleep(2000);
        try {
          const url = this.buildZapUrl("/JSON/core/view/version/");
          const response = await fetch(url);
          if (response.ok) {
            logger.debug("ZAP started successfully");
            return;
          }
        } catch {
          // Keep waiting
        }
      }

      throw new Error("ZAP failed to start within timeout");
    } catch (err) {
      throw new ScannerError(
        `Failed to start ZAP: ${(err as Error).message}`,
        this.name
      );
    }
  }

  private async runApiScan(ctx: ExecutionContext): Promise<RawFinding[]> {
    // When running ZAP in Docker, replace localhost with host.docker.internal
    // so ZAP container can reach the target on the host machine
    let targetUrl = ctx.targetUrl;
    if (this.useDocker) {
      targetUrl = targetUrl.replace(/localhost|127\.0\.0\.1/g, "host.docker.internal");
      logger.info(`ZAP Docker scanning: ${targetUrl}`);
    }

    const authHeaders = buildAuthHeaders(ctx.auth);

    // Access the base URL first, carrying configured auth where possible.
    await this.sendRequestViaZap("GET", targetUrl, authHeaders);

    const scopedEndpoints = (ctx.endpoints && ctx.endpoints.length > 0
      ? ctx.endpoints
      : this.extractOpenApiEndpoints(ctx))
      .filter((endpoint) => {
        if (isPathExcluded(endpoint.path, ctx.config.safety)) {
          logger.debug(`Skipping ZAP endpoint ${endpoint.path}: excluded by safety profile`);
          return false;
        }
        if (endpoint.method && !allowsDestructiveMethod(endpoint.method, ctx.config.safety)) {
          logger.debug(`Skipping ZAP endpoint ${endpoint.method} ${endpoint.path}: method blocked by safety profile`);
          return false;
        }
        return true;
      });

    // If we have configured or OpenAPI endpoints, add them to ZAP for scanning
    if (scopedEndpoints.length > 0) {
      logger.info(`Adding ${scopedEndpoints.length} scoped endpoints to ZAP`);
      for (const endpoint of scopedEndpoints) {
        const endpointUrl = `${targetUrl}${endpoint.path}`;

        // Add query parameters if any
        const urlWithParams = new URL(endpointUrl);
        if (endpoint.params) {
          for (const [key, value] of Object.entries(endpoint.params)) {
            urlWithParams.searchParams.set(key, value);
          }
        }

        const bodyStr = endpoint.body ? JSON.stringify(endpoint.body) : "";
        await this.sendRequestViaZap(
          endpoint.method || "GET",
          urlWithParams.toString(),
          authHeaders,
          bodyStr
        );
      }
    }

    // Spider to discover more endpoints
    logger.info("Spidering target...");
    const spiderResponse = await this.zapRequest("/JSON/spider/action/scan/", {
      url: targetUrl,
      maxChildren: "10",
      recurse: "true",
    });

    const spiderId = spiderResponse?.scan as string;
    if (spiderId) {
      await this.waitForScan("spider", spiderId);
    }

    if (shouldRunZapActiveScan(ctx.config.safety)) {
      // Run active scan on all discovered URLs only for the full-active profile.
      logger.info("Running active scan...");
      const scanResponse = await this.zapRequest("/JSON/ascan/action/scan/", {
        url: targetUrl,
        recurse: "true",
        scanPolicyName: "Default Policy",
      });

      const scanId = scanResponse?.scan as string;
      if (scanId) {
        await this.waitForScan("ascan", scanId, 300000);
      }
    } else {
      logger.info("Skipping ZAP active scan; set safety.profile: full-active to enable it");
    }

    const alertsResponse = await this.zapRequest("/JSON/core/view/alerts/", {
      baseurl: targetUrl,
    });

    const alerts = ((alertsResponse?.alerts || []) as ZapAlert[])
      .filter((alert) => !this.isAlertExcluded(alert, ctx));
    logger.info(`ZAP found ${alerts.length} alerts`);

    return this.parseAlerts(alerts, ctx.auth?.role);
  }

  private async zapRequest(path: string, params?: Record<string, string>): Promise<Record<string, unknown>> {
    const url = this.buildZapUrl(path, params);

    try {
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`ZAP API error: ${response.status}`);
      }
      return await response.json() as Record<string, unknown>;
    } catch (err) {
      logger.debug(`ZAP request failed: ${(err as Error).message}`);
      return {};
    }
  }

  private async sendRequestViaZap(
    method: string,
    url: string,
    headers: Record<string, string>,
    body = ""
  ): Promise<void> {
    await this.zapRequest("/JSON/core/action/sendRequest/", {
      request: this.buildRawHttpRequest(method, url, headers, body),
      followRedirects: "true",
    });
  }

  private buildRawHttpRequest(
    method: string,
    url: string,
    headers: Record<string, string>,
    body: string
  ): string {
    const parsed = new URL(url);
    const requestHeaders: Record<string, string> = {
      Host: parsed.host,
      "User-Agent": "SecurityBot/1.0",
      ...headers,
    };

    if (body) {
      requestHeaders["Content-Type"] = requestHeaders["Content-Type"] || "application/json";
      requestHeaders["Content-Length"] = Buffer.byteLength(body).toString();
    }

    const headerLines = Object.entries(requestHeaders)
      .map(([key, value]) => `${key}: ${value}`)
      .join("\n");

    return `${method.toUpperCase()} ${parsed.pathname}${parsed.search} HTTP/1.1\n${headerLines}\n\n${body}`;
  }

  private async waitForScan(
    scanType: "spider" | "ascan",
    scanId: string,
    timeout = 60000
  ): Promise<void> {
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      const response = await this.zapRequest(`/JSON/${scanType}/view/status/`, { scanId });
      const status = parseInt(String(response?.status || "0"), 10);

      if (status >= 100) {
        return;
      }

      logger.debug(`${scanType} progress: ${status}%`);
      await sleep(2000);
    }

    logger.warn(`${scanType} timed out`);
  }

  private parseAlerts(alerts: ZapAlert[], role?: string): RawFinding[] {
    return alerts.map((alert) => ({
      source: this.name,
      category: this.mapCategory(alert.name),
      description: alert.desc?.replace(/<[^>]*>/g, "") || alert.name,
      endpoint: `${alert.method} ${alert.uri}`,
      role,
      severityHint: RISK_MAP[alert.riskcode] || "LOW",
      evidence: alert.evidence || alert.attack,
      cwe: alert.cweid ? `CWE-${alert.cweid}` : undefined,
      reference: alert.reference,
    }));
  }

  private isAlertExcluded(alert: ZapAlert, ctx: ExecutionContext): boolean {
    try {
      const url = new URL(alert.uri);
      return isPathExcluded(url.pathname, ctx.config.safety);
    } catch {
      return false;
    }
  }

  private extractOpenApiEndpoints(ctx: ExecutionContext): Array<{
    path: string;
    method?: string;
    params?: Record<string, string>;
    body?: Record<string, unknown>;
  }> {
    if (!ctx.openApi?.paths) {
      return [];
    }

    const methods = new Set(["get", "post", "put", "patch", "delete"]);
    const endpoints: Array<{
      path: string;
      method?: string;
      params?: Record<string, string>;
      body?: Record<string, unknown>;
    }> = [];

    for (const [path, pathItem] of Object.entries(ctx.openApi.paths)) {
      if (!pathItem || typeof pathItem !== "object") {
        continue;
      }

      for (const [method] of Object.entries(pathItem)) {
        if (!methods.has(method)) {
          continue;
        }

        endpoints.push({
          path,
          method: method.toUpperCase(),
        });
      }
    }

    return endpoints;
  }

  private mapCategory(alertName: string): string {
    const name = alertName.toLowerCase();

    if (name.includes("injection") || name.includes("sqli")) return "Injection";
    if (name.includes("xss") || name.includes("cross-site scripting")) return "XSS";
    if (name.includes("csrf")) return "CSRF";
    if (name.includes("auth")) return "Broken Authentication";
    if (name.includes("access")) return "Broken Access Control";
    if (name.includes("exposure") || name.includes("disclosure")) return "Sensitive Data Exposure";
    if (name.includes("header")) return "Security Misconfiguration";
    if (name.includes("ssl") || name.includes("tls") || name.includes("certificate")) return "TLS/SSL Issue";

    return "Security Vulnerability";
  }

  private async cleanup(): Promise<void> {
    if (this.dockerContainerId) {
      logger.debug("Stopping ZAP Docker container");
      try {
        await runProcess("docker", ["stop", this.dockerContainerId], { timeout: 30000 });
      } catch {
        // Ignore stop errors
      }
    } else if (this.zapProcess) {
      try {
        await this.zapRequest("/JSON/core/action/shutdown/");
      } catch {
        // Ignore shutdown errors
      }
    }
  }
}
