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

  /** Positive exploitation proof observed in a response. Empty means detected only. */
  proofs: ExploitProof[];
  /** The exact response substring backing the proof, for ten-second verification. */
  proofExcerpt?: string;

  /**
   * Confidence that the detector correctly identified what it reports, 0.0 to 1.0.
   *
   * This is the ONLY score stored on a Finding. Exploitability, impact,
   * reachability, and the composite feasibility score are all derived on demand
   * by AttackAnalyzer. Two engines previously each wrote their own number named
   * "risk" onto this object and disagreed, so reports and verdicts cited
   * different figures for the same finding.
   */
  confidence: number;

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

  // Exploit intelligence, populated by ExploitIntel when the finding has a CVE.
  /** EPSS probability of exploitation in the next 30 days, 0.0 to 1.0 */
  epssScore?: number;
  /** EPSS percentile relative to all scored CVEs, 0.0 to 1.0 */
  epssPercentile?: number;
  /** True when listed in the CISA Known Exploited Vulnerabilities catalog */
  knownExploited?: boolean;
}

/**
 * Positive proof that exploitation actually succeeded.
 *
 * A finding is only ever "confirmed" when a scanner observed one of these in a
 * response. Scanner identity is never proof: a passive alert from an active
 * scanner is still a passive alert.
 */
export type ExploitProof =
  | "sql-error" // Database error text surfaced by an injected payload
  | "command-output" // Output of an injected shell command
  | "payload-reflected" // Attack payload echoed back verbatim and unescaped
  | "path-disclosure" // File contents or system paths returned
  | "cloud-metadata" // Cloud instance metadata reached via SSRF
  | "privileged-field" // Privileged field accepted via mass assignment
  | "auth-bypass" // 2xx where the unauthenticated baseline was 4xx
  | "timing-oracle" // Reproducible response delay indicating blind injection
  | "stack-trace"; // Unhandled exception detail returned to the caller

export const EXPLOIT_PROOFS: ExploitProof[] = [
  "sql-error",
  "command-output",
  "payload-reflected",
  "path-disclosure",
  "cloud-metadata",
  "privileged-field",
  "auth-bypass",
  "timing-oracle",
  "stack-trace",
];

export interface FindingGroup {
  primary: Finding;
  duplicates: Finding[];
}
