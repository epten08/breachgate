import { ExploitProof } from "./finding.js";

export interface RawFinding {
  source: string;
  category: string;
  description: string;
  endpoint?: string;
  role?: string;
  severityHint?: string;
  evidence?: string;
  cve?: string;
  cwe?: string;
  package?: string;
  version?: string;
  fixedVersion?: string;
  reference?: string;

  /**
   * Positive proof that exploitation succeeded, observed in the response.
   *
   * Scanners must only set this when they saw an actual exploitation signal.
   * An empty or absent list means "detected, not confirmed", which is the
   * correct default for every passive check and every static finding.
   */
  proofs?: ExploitProof[];

  /**
   * The exact substring from the response that establishes the proof.
   * This is what a developer reads to verify the claim in ten seconds.
   */
  proofExcerpt?: string;
}
