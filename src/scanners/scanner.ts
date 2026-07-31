import { ExecutionContext } from "../orchestrator/context.js";
import { RawFinding } from "../findings/raw.finding.js";

/**
 * Breach Gate scans running APIs. Three scanner categories, no more.
 *
 * static  - dependency and IaC analysis of the repository (Trivy)
 * dynamic - active HTTP testing of the running target (ZAP)
 * ai      - LLM-generated, endpoint-aware behavioural tests
 */
export type ScannerCategory = "static" | "dynamic" | "ai";

export const SCANNER_CATEGORIES: ScannerCategory[] = ["static", "dynamic", "ai"];

export interface Scanner {
  name: string;
  category: ScannerCategory;

  run(ctx: ExecutionContext): Promise<RawFinding[]>;
}
