import { NotificationConfig } from "../core/config.loader.js";
import { SecurityVerdict } from "../findings/attack.analyzer.js";
import { Finding } from "../findings/finding.js";
import { logger } from "../core/logger.js";
import { sendSlackNotification } from "./slack.js";
import { sendGitHubNotification } from "./github.js";
import { sendWebhookNotification } from "./webhook.js";

export async function sendNotifications(
  config: NotificationConfig | undefined,
  verdict: SecurityVerdict,
  findings: Finding[],
  targetUrl: string
): Promise<void> {
  if (!config) return;

  const tasks: Array<Promise<void>> = [];

  if (config.slack) {
    tasks.push(
      sendSlackNotification(config.slack, verdict, findings, targetUrl).catch(err =>
        logger.warn(`Slack notification failed: ${(err as Error).message}`)
      )
    );
  }

  if (config.github) {
    tasks.push(
      sendGitHubNotification(config.github, verdict, findings, targetUrl).catch(err =>
        logger.warn(`GitHub notification failed: ${(err as Error).message}`)
      )
    );
  }

  if (config.webhook) {
    tasks.push(
      sendWebhookNotification(config.webhook, verdict, findings, targetUrl).catch(err =>
        logger.warn(`Webhook notification failed: ${(err as Error).message}`)
      )
    );
  }

  await Promise.all(tasks);
}
