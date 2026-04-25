import { createHmac } from "crypto";
import { WebhookNotificationConfig } from "../core/config.loader.js";
import { SecurityVerdict } from "../findings/attack.analyzer.js";
import { Finding } from "../findings/finding.js";

export async function sendWebhookNotification(
  config: WebhookNotificationConfig,
  verdict: SecurityVerdict,
  findings: Finding[],
  targetUrl: string
): Promise<void> {
  if (config.onlyOnFailure && verdict.verdict === "SAFE") {
    return;
  }

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  }

  const payload = {
    event: "scan_complete",
    timestamp: new Date().toISOString(),
    targetUrl,
    verdict: verdict.verdict,
    reason: verdict.reason,
    confirmedExploits: verdict.confirmedExploits.length,
    findings: {
      total: findings.length,
      critical: counts.CRITICAL,
      high: counts.HIGH,
      medium: counts.MEDIUM,
      low: counts.LOW,
    },
  };

  const body = JSON.stringify(payload);
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (config.secret) {
    const sig = createHmac("sha256", config.secret).update(body).digest("hex");
    headers["X-Breach-Gate-Signature"] = `sha256=${sig}`;
  }

  const response = await fetch(config.url, { method: "POST", headers, body });
  if (!response.ok) {
    throw new Error(`Webhook POST to ${config.url} returned ${response.status}: ${await response.text()}`);
  }
}
