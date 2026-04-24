import { Finding, Severity } from "../findings/finding.js";
import { SecurityVerdict } from "../findings/attack.analyzer.js";
import { PolicyEvaluation, fingerprintFinding } from "../policy/policy.js";

export interface SarifReporterOptions {
  targetUrl: string;
  verdict?: SecurityVerdict;
  policyEvaluation?: PolicyEvaluation;
}

interface SarifReport {
  version: "2.1.0";
  $schema: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        informationUri: string;
        rules: Array<{
          id: string;
          name: string;
          shortDescription: { text: string };
          help: { text: string };
          properties: {
            securitySeverity: string;
            tags: string[];
          };
        }>;
      };
    };
    invocations: Array<{
      executionSuccessful: boolean;
      properties: Record<string, unknown>;
    }>;
    results: Array<{
      ruleId: string;
      level: "error" | "warning" | "note";
      message: { text: string };
      locations: Array<{
        physicalLocation: {
          artifactLocation: { uri: string };
          region: { startLine: number };
        };
      }>;
      partialFingerprints: {
        breachGateFingerprint: string;
      };
      properties: Record<string, unknown>;
    }>;
  }>;
}

export class SarifReporter {
  generate(findings: Finding[], options: SarifReporterOptions): string {
    const includedFindings = this.filterFindings(findings, options.policyEvaluation);
    const categories = [...new Set(includedFindings.map((f) => f.category))].sort();
    const rules = categories.map((category) => {
      const representative = includedFindings.find((f) => f.category === category);
      const severity = representative?.severity || "LOW";

      return {
        id: this.ruleId(category),
        name: category,
        shortDescription: {
          text: category,
        },
        help: {
          text: `Breach Gate identified ${category}. Review the finding evidence and remediation guidance in the generated JSON or Markdown report.`,
        },
        properties: {
          securitySeverity: this.securitySeverity(severity),
          tags: ["security", "breach-gate", category.toLowerCase().replace(/\s+/g, "-")],
        },
      };
    });

    const report: SarifReport = {
      version: "2.1.0",
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      runs: [
        {
          tool: {
            driver: {
              name: "Breach Gate",
              informationUri: "https://github.com/OWNER/breach-gate",
              rules,
            },
          },
          invocations: [
            {
              executionSuccessful: options.verdict?.verdict !== "INCONCLUSIVE",
              properties: {
                targetUrl: options.targetUrl,
                verdict: options.verdict?.verdict,
                policyStatus: options.policyEvaluation?.status,
                policyProfile: options.policyEvaluation?.profile,
              },
            },
          ],
          results: includedFindings.map((finding) => ({
            ruleId: this.ruleId(finding.category),
            level: this.level(finding.severity),
            message: {
              text: `${finding.title}${finding.endpoint ? ` (${finding.endpoint})` : ""}`,
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: "security.config.yml",
                  },
                  region: {
                    startLine: 1,
                  },
                },
              },
            ],
            partialFingerprints: {
              breachGateFingerprint: fingerprintFinding(finding),
            },
            properties: {
              category: finding.category,
              severity: finding.severity,
              riskScore: finding.riskScore,
              confidence: finding.confidence,
              exploitability: finding.exploitability,
              endpoint: finding.endpoint,
              role: finding.role,
              cve: finding.cve,
              cwe: finding.cwe,
              sources: finding.sources,
            },
          })),
        },
      ],
    };

    return JSON.stringify(report, null, 2);
  }

  private ruleId(category: string): string {
    return `BREACH-GATE-${category.toUpperCase().replace(/[^A-Z0-9]+/g, "-").replace(/^-|-$/g, "")}`;
  }

  private filterFindings(findings: Finding[], policyEvaluation?: PolicyEvaluation): Finding[] {
    if (!policyEvaluation?.differentialOnly) {
      return findings;
    }

    const effective = new Set(policyEvaluation.effectiveFindingFingerprints);
    return findings.filter((finding) => effective.has(fingerprintFinding(finding)));
  }

  private level(severity: Severity): "error" | "warning" | "note" {
    if (severity === "CRITICAL" || severity === "HIGH") {
      return "error";
    }
    if (severity === "MEDIUM") {
      return "warning";
    }
    return "note";
  }

  private securitySeverity(severity: Severity): string {
    switch (severity) {
      case "CRITICAL":
        return "9.5";
      case "HIGH":
        return "8.0";
      case "MEDIUM":
        return "5.0";
      case "LOW":
        return "2.0";
    }
  }
}

