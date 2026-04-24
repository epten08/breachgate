import { ExecutionContext } from "../orchestrator/context.js";
import { RawFinding } from "../findings/raw.finding.js";

export type ScannerCategory =
  | "static"
  | "container"
  | "dynamic"
  | "ai";

export interface Scanner {
  name: string;
  category: ScannerCategory;

  run(ctx: ExecutionContext): Promise<RawFinding[]>;
}
