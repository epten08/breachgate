export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

export interface EndpointContext {
  method?: string;
  path?: string;
  acceptsUserInput: boolean;
  requiresAuth: boolean;
  handlesData: boolean;
}

export interface Finding {
  id: string;
  title: string;
  category: string;
  severity: Severity;

  endpoint?: string;
  endpointContext?: EndpointContext;
  role?: string;
  evidence: string;

  // Risk metrics
  exploitability: number; // 0.0 – 1.0
  confidence: number; // 0.0 – 1.0
  riskScore: number; // Calculated composite score

  // Tracking
  sources: string[];
  deduplicated: boolean;
  duplicateCount: number;

  // Vulnerability details
  cve?: string;
  cwe?: string;
  package?: string;
  version?: string;
  fixedVersion?: string;
  reference?: string;
}

export interface FindingGroup {
  primary: Finding;
  duplicates: Finding[];
}
