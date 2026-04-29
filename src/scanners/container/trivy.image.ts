import { Scanner } from "../scanner.js";
import { ExecutionContext } from "../../orchestrator/context.js";
import { RawFinding } from "../../findings/raw.finding.js";
import { runProcess, checkCommand } from "../../core/process.runner.js";
import { ScannerError, ScannerUnavailableError } from "../../core/errors.js";
import { logger } from "../../core/logger.js";

interface TrivyImageResult {
  SchemaVersion: number;
  Results?: TrivyImageTarget[];
}

interface TrivyImageTarget {
  Target: string;
  Class: string;
  Type: string;
  Vulnerabilities?: TrivyImageVulnerability[];
}

interface TrivyImageVulnerability {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion: string;
  FixedVersion?: string;
  Severity: string;
  Title?: string;
  Description?: string;
  PrimaryURL?: string;
  CweIDs?: string[];
  Layer?: {
    Digest?: string;
    DiffID?: string;
  };
}

export class TrivyImageScanner implements Scanner {
  name = "Trivy Image";
  category = "container" as const;

  private useDocker = false;

  async run(ctx: ExecutionContext): Promise<RawFinding[]> {
    const images = ctx.environment.images;

    if (!images || images.length === 0) {
      throw new ScannerUnavailableError("No container images configured or detected", this.name);
    }

    // Check for native trivy first, then Docker
    const hasTrivy = await checkCommand("trivy");
    const hasDocker = await checkCommand("docker");

    if (!hasTrivy && !hasDocker) {
      throw new ScannerUnavailableError(
        "Neither Trivy nor Docker is available for container scanning",
        this.name,
        undefined,
        "Install Trivy: brew install trivy (macOS) | apt install trivy (Linux) | scoop install trivy (Windows). Or install Docker to use the container image."
      );
    }

    if (!hasTrivy && hasDocker) {
      // Check if trivy image is available
      const imageCheck = await runProcess("docker", ["images", "-q", "aquasec/trivy"], {
        timeout: 10000,
      });
      if (!imageCheck.stdout.trim()) {
        throw new ScannerUnavailableError(
          "Trivy Docker image not found. Pull with: docker pull aquasec/trivy",
          this.name,
          undefined,
          "Run: docker pull aquasec/trivy"
        );
      }
      this.useDocker = true;
      logger.info("Using Trivy via Docker for container scanning");
    }

    const allFindings: RawFinding[] = [];
    const failures: string[] = [];

    for (const image of images) {
      logger.scanner(this.name, "start", `Scanning image: ${image}`);

      try {
        const findings = await this.scanImage(image);
        allFindings.push(...findings);
        logger.scanner(this.name, "done", `${image}: ${findings.length} issues`);
      } catch (err) {
        const message = `${image}: ${(err as Error).message}`;
        failures.push(message);
        logger.scanner(this.name, "error", message);
      }
    }

    if (failures.length === images.length) {
      throw new ScannerError(`All image scans failed: ${failures.join("; ")}`, this.name);
    }

    return allFindings;
  }

  private async scanImage(image: string): Promise<RawFinding[]> {
    let result;

    if (this.useDocker) {
      // Run Trivy via Docker to scan another Docker image
      // Mount docker socket to allow scanning local images
      result = await runProcess(
        "docker",
        [
          "run",
          "--rm",
          "-v",
          "/var/run/docker.sock:/var/run/docker.sock",
          "aquasec/trivy",
          "image",
          image,
          "--format",
          "json",
          "--scanners",
          "vuln",
        ],
        { timeout: 600000 }
      );
    } else {
      result = await runProcess(
        "trivy",
        ["image", image, "--format", "json", "--scanners", "vuln"],
        { timeout: 600000 } // 10 minutes for large images
      );
    }

    if (result.exitCode !== 0 && !result.stdout) {
      throw new ScannerError(`Image scan failed: ${result.stderr}`, this.name);
    }

    return this.parseResults(result.stdout, image);
  }

  private parseResults(output: string, image: string): RawFinding[] {
    const findings: RawFinding[] = [];

    if (!output.trim()) {
      return findings;
    }

    let data: TrivyImageResult;
    try {
      data = JSON.parse(output);
    } catch {
      logger.warn(`Failed to parse Trivy output for ${image}`);
      return findings;
    }

    for (const target of data.Results || []) {
      for (const vuln of target.Vulnerabilities || []) {
        findings.push({
          source: this.name,
          category: this.mapCategory(target.Type),
          description:
            vuln.Title || vuln.Description || `${vuln.VulnerabilityID} in ${vuln.PkgName}`,
          severityHint: vuln.Severity,
          evidence: `${vuln.PkgName}@${vuln.InstalledVersion} in ${image} (${target.Target})`,
          cve: vuln.VulnerabilityID,
          cwe: vuln.CweIDs?.[0],
          package: vuln.PkgName,
          version: vuln.InstalledVersion,
          fixedVersion: vuln.FixedVersion,
          reference: vuln.PrimaryURL,
        });
      }
    }

    return findings;
  }

  private mapCategory(targetType: string): string {
    switch (targetType) {
      case "alpine":
      case "debian":
      case "ubuntu":
      case "redhat":
      case "centos":
      case "rocky":
      case "alma":
        return "OS Package Vulnerability";
      case "npm":
      case "yarn":
      case "pip":
      case "poetry":
      case "go":
      case "cargo":
        return "Application Dependency Vulnerability";
      default:
        return "Container Vulnerability";
    }
  }
}
