import { runProcess, checkCommand } from "../core/process.runner.js";
import { EnvironmentError } from "../core/errors.js";
import { logger } from "../core/logger.js";
import { SecurityBotConfig } from "../core/config.loader.js";
import { waitForHealthy, detectApiUrl } from "../utils/network.js";
import { fileExists, readYaml } from "../utils/fs.js";

export interface EnvironmentInfo {
  baseUrl: string;
  images: string[];
  services: string[];
  managedByUs: boolean;
}

interface DockerComposeConfig {
  services?: Record<string, DockerComposeService>;
}

interface DockerComposeService {
  image?: string;
  build?: string | { context?: string; dockerfile?: string };
  ports?: string[];
  healthcheck?: {
    test?: string | string[];
    interval?: string;
    timeout?: string;
    retries?: number;
  };
}

export class EnvironmentManager {
  private config: SecurityBotConfig;
  private composeFile: string | null = null;
  private managedByUs = false;

  constructor(config: SecurityBotConfig) {
    this.config = config;
  }

  async setup(): Promise<EnvironmentInfo> {
    if (this.config.target.baseUrl && !this.config.target.dockerCompose) {
      return this.setupExternalTarget();
    }

    if (this.config.target.dockerCompose) {
      return this.setupDockerCompose();
    }

    throw new EnvironmentError(
      "No target specified. Provide either baseUrl or dockerCompose in config."
    );
  }

  async teardown(): Promise<void> {
    if (!this.managedByUs || !this.composeFile) {
      logger.debug("Environment not managed by us, skipping teardown");
      return;
    }

    logger.info("Tearing down environment");

    try {
      await runProcess("docker", ["compose", "-f", this.composeFile, "down", "-v"], {
        timeout: 60000,
      });
      logger.info("Environment teardown complete");
    } catch (err) {
      logger.warn(`Failed to teardown environment: ${(err as Error).message}`);
    }
  }

  private async setupExternalTarget(): Promise<EnvironmentInfo> {
    const baseUrl = this.config.target.baseUrl!;
    const healthEndpoint = this.config.target.healthEndpoint;
    const healthTimeout = this.config.target.healthTimeout || 30000;

    logger.info(`Using external target: ${baseUrl}`);

    // Only check health if dynamic scanning is enabled
    if (this.config.scanners.dynamic.enabled) {
      const isHealthy = await waitForHealthy({
        url: baseUrl,
        healthEndpoint,
        timeout: healthTimeout,
        maxAttempts: 5,
      });

      if (!isHealthy) {
        const detected = await detectApiUrl(baseUrl);
        if (!detected) {
          throw new EnvironmentError(`Target not reachable: ${baseUrl}`);
        }
        logger.info("Target reachable (health endpoint not available)");
      }
    } else {
      logger.debug("Skipping health check (dynamic scanning disabled)");
    }

    // Use configured images for container scanning if specified
    const configuredImages = this.config.scanners.container?.images || [];

    return {
      baseUrl,
      images: configuredImages,
      services: [],
      managedByUs: false,
    };
  }

  private async setupDockerCompose(): Promise<EnvironmentInfo> {
    const composePath = this.config.target.dockerCompose!;

    if (!fileExists(composePath)) {
      throw new EnvironmentError(`Docker compose file not found: ${composePath}`);
    }

    await this.verifyDockerAvailable();

    this.composeFile = composePath;

    const composeConfig = readYaml<DockerComposeConfig>(composePath);
    const services = Object.keys(composeConfig.services || {});
    const images = this.extractImages(composeConfig, composePath);

    logger.info(`Found ${services.length} services in docker-compose`, { services });

    const isRunning = await this.isComposeRunning(composePath);

    if (isRunning) {
      logger.info("Docker compose environment already running");
      this.managedByUs = false;
    } else {
      logger.info("Starting docker compose environment");
      await this.startCompose(composePath);
      this.managedByUs = true;
    }

    const baseUrl = await this.detectBaseUrl(composeConfig);
    const healthEndpoint = this.config.target.healthEndpoint;
    const healthTimeout = this.config.target.healthTimeout || 120000;

    logger.info(`Waiting for API at ${baseUrl}`);
    const isHealthy = await waitForHealthy({
      url: baseUrl,
      healthEndpoint,
      timeout: healthTimeout,
      maxAttempts: 60,
      interval: 2000,
    });

    if (!isHealthy) {
      if (this.managedByUs) {
        await this.teardown();
      }
      throw new EnvironmentError(`API failed to become healthy: ${baseUrl}`);
    }

    logger.info("Environment ready", { baseUrl });

    return {
      baseUrl,
      images,
      services,
      managedByUs: this.managedByUs,
    };
  }

  private async verifyDockerAvailable(): Promise<void> {
    const hasDocker = await checkCommand("docker");
    if (!hasDocker) {
      throw new EnvironmentError("Docker is not installed or not in PATH");
    }

    const result = await runProcess("docker", ["info"], { timeout: 10000 });
    if (result.exitCode !== 0) {
      throw new EnvironmentError("Docker daemon is not running");
    }
  }

  private async isComposeRunning(composePath: string): Promise<boolean> {
    try {
      const result = await runProcess(
        "docker",
        ["compose", "-f", composePath, "ps", "--format", "json"],
        { timeout: 10000 }
      );

      if (result.exitCode !== 0) {
        return false;
      }

      const lines = result.stdout.trim().split("\n").filter(Boolean);
      return lines.length > 0;
    } catch {
      return false;
    }
  }

  private async startCompose(composePath: string): Promise<void> {
    logger.scanner("Docker Compose", "start", "Building and starting services");

    const result = await runProcess(
      "docker",
      ["compose", "-f", composePath, "up", "-d", "--build", "--wait"],
      { timeout: 300000 }
    );

    if (result.exitCode !== 0) {
      throw new EnvironmentError(
        `Failed to start docker-compose: ${result.stderr || result.stdout}`
      );
    }

    logger.scanner("Docker Compose", "done", "Services started");
  }

  private extractImages(config: DockerComposeConfig, composePath: string): string[] {
    const images: string[] = [];

    if (this.config.scanners.container.images?.length) {
      return this.config.scanners.container.images;
    }

    for (const [name, service] of Object.entries(config.services || {})) {
      if (service.image) {
        images.push(service.image);
      } else if (service.build) {
        const projectName = this.getProjectName(composePath);
        images.push(`${projectName}-${name}`);
      }
    }

    return images;
  }

  private getProjectName(composePath: string): string {
    const parts = composePath.replace(/\\/g, "/").split("/");
    const dir = parts[parts.length - 2] || "project";
    return dir.toLowerCase().replace(/[^a-z0-9]/g, "");
  }

  private async detectBaseUrl(config: DockerComposeConfig): Promise<string> {
    if (this.config.target.baseUrl) {
      return this.config.target.baseUrl;
    }

    for (const service of Object.values(config.services || {})) {
      if (service.ports?.length) {
        for (const portMapping of service.ports) {
          const hostPort = this.parseHostPort(portMapping);
          if (hostPort) {
            return `http://localhost:${hostPort}`;
          }
        }
      }
    }

    return "http://localhost:3000";
  }

  private parseHostPort(portMapping: string): number | null {
    const parts = portMapping.toString().split(":");

    if (parts.length === 1) {
      return parseInt(parts[0], 10);
    }

    if (parts.length === 2) {
      return parseInt(parts[0], 10);
    }

    if (parts.length === 3) {
      return parseInt(parts[1], 10);
    }

    return null;
  }
}
