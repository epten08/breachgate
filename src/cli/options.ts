import { Severity } from "../findings/finding.js";
import { ReportFormat } from "../core/config.loader.js";

export interface ScanOptions {
  config?: string;
  configs?: string[];
  workdir?: string;
  target?: string;
  output?: string;
  format?: ReportFormat[];
  failOn?: Severity;
  profile?: string;
  baseline?: string;
  differential?: boolean;
  verbose?: boolean;
  quiet?: boolean;
  ci?: boolean;  // Deterministic CI mode - minimal output
  skipStatic?: boolean;
  skipContainer?: boolean;
  skipDynamic?: boolean;
  skipAi?: boolean;
}

export interface GlobalOptions {
  verbose?: boolean;
  quiet?: boolean;
  noColor?: boolean;
}

export function parseSeverity(value: string): Severity {
  const upper = value.toUpperCase();
  if (["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(upper)) {
    return upper as Severity;
  }
  throw new Error(`Invalid severity: ${value}. Must be LOW, MEDIUM, HIGH, or CRITICAL`);
}

export function parseFormats(value: string, previous: string[] = []): string[] {
  const formats = value.split(",").map((f) => f.trim().toLowerCase());
  for (const format of formats) {
    if (!["markdown", "json", "sarif"].includes(format)) {
      throw new Error(`Invalid format: ${format}. Must be markdown, json, or sarif`);
    }
  }
  return [...previous, ...formats];
}

export function parseConfigPaths(value: string, previous: string[] = []): string[] {
  const paths = value
    .split(",")
    .map((path) => path.trim())
    .filter(Boolean);

  if (paths.length === 0) {
    throw new Error("At least one config path must be provided");
  }

  return [...previous, ...paths];
}
