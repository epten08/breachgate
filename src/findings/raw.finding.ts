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
}
