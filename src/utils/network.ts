import { logger } from "../core/logger.js";

export interface HealthCheckOptions {
  url: string;
  healthEndpoint?: string;
  timeout?: number;
  interval?: number;
  maxAttempts?: number;
  expectedStatus?: number[];
}

export async function waitForHealthy(options: HealthCheckOptions): Promise<boolean> {
  const {
    url,
    healthEndpoint,
    timeout = 60000,
    interval = 2000,
    maxAttempts = 30,
    expectedStatus = [200, 201, 204],
  } = options;

  // Build the health check URL - try configured endpoint, /health, or root
  const healthPaths = healthEndpoint ? [healthEndpoint] : ["/health", "/", "/api/health"];

  const startTime = Date.now();
  let attempts = 0;

  logger.debug(`Waiting for ${url} to become healthy`, { maxAttempts, timeout, healthPaths });

  while (attempts < maxAttempts && Date.now() - startTime < timeout) {
    attempts++;

    // Try each health path
    for (const path of healthPaths) {
      try {
        const checkUrl = new URL(path, url).toString();
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

        const response = await fetch(checkUrl, {
          method: "GET",
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (expectedStatus.includes(response.status)) {
          logger.debug(`Health check passed at ${checkUrl} after ${attempts} attempts`);
          return true;
        }

        logger.debug(`Health check attempt ${attempts} (${path}): status ${response.status}`);
      } catch (err) {
        const message = err instanceof Error ? err.message : "Unknown error";
        logger.debug(`Health check attempt ${attempts} (${path}) failed: ${message}`);
      }
    }

    await sleep(interval);
  }

  logger.warn(`Health check failed after ${attempts} attempts`);
  return false;
}

export async function detectApiUrl(
  baseUrl: string,
  paths: string[] = ["/", "/health", "/api", "/api/health"]
): Promise<string | null> {
  for (const path of paths) {
    const url = new URL(path, baseUrl).toString();
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);

      const response = await fetch(url, {
        method: "GET",
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (response.ok || response.status === 401 || response.status === 403) {
        logger.debug(`API detected at ${url}`);
        return baseUrl;
      }
    } catch {
      // Continue to next path
    }
  }

  return null;
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function parsePortFromUrl(url: string): number | null {
  try {
    const parsed = new URL(url);
    if (parsed.port) {
      return parseInt(parsed.port, 10);
    }
    return parsed.protocol === "https:" ? 443 : 80;
  } catch {
    return null;
  }
}
