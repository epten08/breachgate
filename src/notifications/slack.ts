import { SlackNotificationConfig } from "../core/config.loader.js";
import { SecurityVerdict } from "../findings/attack.analyzer.js";
import { Finding } from "../findings/finding.js";

export async function sendSlackNotification(
  config: SlackNotificationConfig,
  verdict: SecurityVerdict,
  findings: Finding[],
  targetUrl: string
): Promise<void> {
  if (config.onlyOnFailure && verdict.verdict === "SAFE") {
    return;
  }

  const emoji =
    {
      SAFE: ":white_check_mark:",
      UNSAFE: ":no_entry:",
      REVIEW_REQUIRED: ":warning:",
      INCONCLUSIVE: ":question:",
    }[verdict.verdict] ?? ":question:";
  const color =
    { SAFE: "#16a34a", UNSAFE: "#dc2626", REVIEW_REQUIRED: "#d97706", INCONCLUSIVE: "#7c3aed" }[
      verdict.verdict
    ] ?? "#64748b";

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  }

  const summaryParts: string[] = [];
  if (counts.CRITICAL > 0) summaryParts.push(`${counts.CRITICAL} critical`);
  if (counts.HIGH > 0) summaryParts.push(`${counts.HIGH} high`);
  if (counts.MEDIUM > 0) summaryParts.push(`${counts.MEDIUM} medium`);
  if (counts.LOW > 0) summaryParts.push(`${counts.LOW} low`);
  const summary = summaryParts.length > 0 ? summaryParts.join(", ") : "no findings";

  const payload: Record<string, unknown> = {
    text: `${emoji} Breach Gate — *${verdict.verdict}* for \`${targetUrl}\``,
    attachments: [
      {
        color,
        fields: [
          { title: "Verdict", value: verdict.verdict, short: true },
          { title: "Findings", value: summary, short: true },
          { title: "Reason", value: verdict.reason, short: false },
        ],
      },
    ],
  };

  if (config.channel) {
    payload.channel = config.channel;
  }

  const response = await fetch(config.webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(`Slack webhook returned ${response.status}: ${await response.text()}`);
  }
}
