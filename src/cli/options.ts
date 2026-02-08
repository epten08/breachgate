import { Severity } from "../findings/finding";

export interface ScanOptions {
  config?: string;
  target?: string;
  output?: string;
  format?: ("markdown" | "json")[];
  failOn?: Severity;
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
    if (!["markdown", "json"].includes(format)) {
      throw new Error(`Invalid format: ${format}. Must be markdown or json`);
    }
  }
  return [...previous, ...formats];
}
