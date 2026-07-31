import { Scanner } from "../scanner.js";
import { ExecutionContext } from "../../orchestrator/context.js";
import { RawFinding } from "../../findings/raw.finding.js";
import { SecurityTestCase, TestGenerator } from "../../ai/test.generator.js";
import { TestExecutor } from "../../ai/executor.js";
import { TestEvaluator } from "../../ai/evaluator.js";
import { AIConfig } from "../../ai/adversary.js";
import { logger } from "../../core/logger.js";
import { ScannerError, ScannerUnavailableError } from "../../core/errors.js";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { dirname, resolve } from "path";

export interface AIScannnerConfig {
  provider: "ollama" | "openai" | "anthropic";
  model: string;
  baseUrl?: string;
  apiKey?: string;
  maxTests?: number;
  deterministic?: boolean;
  temperature?: number;
  maxTokens?: number;
  replayTests?: string;
  saveTests?: string;
}

export class AIScanner implements Scanner {
  name = "AI Security Tester";
  category = "ai" as const;

  private config: AIScannnerConfig;

  constructor(config: AIScannnerConfig) {
    this.config = config;
  }

  async run(ctx: ExecutionContext): Promise<RawFinding[]> {
    logger.scanner(this.name, "start", "Generating and executing security tests");

    const aiConfig: AIConfig = {
      provider: this.config.provider,
      model: this.config.model,
      baseUrl: this.config.baseUrl,
      apiKey: this.config.apiKey,
      temperature: this.config.deterministic ? 0 : this.config.temperature,
      maxTokens: this.config.maxTokens,
    };

    try {
      let isAvailable = false;
      let testCases: SecurityTestCase[];

      if (this.config.replayTests) {
        testCases = this.loadReplayTests(ctx);
        logger.debug(`Loaded ${testCases.length} replayed AI test cases`);
      } else {
        // Check if AI is available before generating test cases.
        const generator = new TestGenerator(ctx, aiConfig);
        isAvailable = await generator.isAvailable();

        if (!isAvailable) {
          const hints: Record<string, string> = {
            ollama:
              "Start Ollama: ollama serve. Then pull a model: ollama pull llama3:8b. See https://ollama.ai",
            openai:
              "Set the OPENAI_API_KEY environment variable. Get a key at https://platform.openai.com/api-keys",
            anthropic:
              "Set the ANTHROPIC_API_KEY environment variable. Get a key at https://console.anthropic.com",
          };
          throw new ScannerUnavailableError(
            `AI provider ${this.config.provider} is not available`,
            this.name,
            undefined,
            hints[this.config.provider]
          );
        }

        const maxTests = this.config.maxTests || 10;
        testCases = await generator.generateTestCases(maxTests);
        this.saveReplayTests(ctx, testCases);
      }

      logger.debug(`Generated ${testCases.length} test cases`);

      if (testCases.length === 0) {
        logger.warn("No test cases generated");
        return [];
      }

      // Execute tests
      const executor = new TestExecutor(ctx);
      const outcome = await executor.execute(testCases);

      // A scan that could not reach the target is a failed scan, not a clean
      // one. Without this the orchestrator records success on an empty result
      // set and the verdict comes back SAFE for an unreachable target.
      if (outcome.attemptedTests > 0 && outcome.results.length === 0) {
        throw new ScannerError(
          `All ${outcome.attemptedTests} AI test request(s) failed to reach ${ctx.targetUrl}`,
          this.name,
          undefined,
          "Check that the target URL is correct and reachable from this machine."
        );
      }

      const errorRate =
        outcome.attemptedTests > 0 ? outcome.erroredTests / outcome.attemptedTests : 0;
      if (errorRate > 0.5) {
        throw new ScannerError(
          `${outcome.erroredTests} of ${outcome.attemptedTests} AI test requests failed. Results are not trustworthy.`,
          this.name,
          undefined,
          "The target may be rate limiting, unstable, or partially unreachable."
        );
      }

      if (outcome.erroredTests > 0) {
        logger.warn(
          `${outcome.erroredTests} of ${outcome.attemptedTests} AI test(s) errored and were not evaluated`
        );
      }

      logger.debug(
        `Executed ${outcome.results.length} tests, ${outcome.results.filter((r) => r.proofs.length > 0).length} with confirmed exploitation`
      );

      // Evaluate results
      const evaluator = new TestEvaluator(ctx, isAvailable ? aiConfig : undefined);
      const findings = await evaluator.evaluate(outcome.results);

      logger.scanner(this.name, "done", `Found ${findings.length} issues`);
      return findings;
    } catch (err) {
      if (err instanceof ScannerUnavailableError || err instanceof ScannerError) {
        throw err;
      }
      logger.scanner(this.name, "error", (err as Error).message);
      throw new ScannerError((err as Error).message, this.name, err as Error);
    }
  }

  private loadReplayTests(ctx: ExecutionContext): SecurityTestCase[] {
    const path = this.resolveReplayPath(ctx, this.config.replayTests!);
    if (!existsSync(path)) {
      // Report the absolute path and the directory it was resolved against.
      // A bare "./ai-tests.json" tells you nothing about where we looked, which
      // turned a one-line .gitignore mistake into a CI investigation.
      throw new ScannerUnavailableError(
        `AI replay artifact not found: ${path} (resolved to ${resolve(path)} from working directory ${process.cwd()})`,
        this.name,
        undefined,
        "Check that the file exists and is committed. Note that .gitignore has an 'ai-tests*.json' rule, so a replay fixture must be explicitly un-ignored to reach CI."
      );
    }

    const parsed = JSON.parse(readFileSync(path, "utf-8")) as
      | SecurityTestCase[]
      | {
          tests?: SecurityTestCase[];
        };
    const tests = Array.isArray(parsed) ? parsed : parsed.tests;

    if (!Array.isArray(tests)) {
      throw new ScannerUnavailableError(
        `AI replay artifact does not contain a tests array: ${path}`,
        this.name
      );
    }

    return tests.filter(
      (testCase) =>
        testCase.name && testCase.endpoint && testCase.request?.method && testCase.request?.path
    );
  }

  private saveReplayTests(ctx: ExecutionContext, tests: SecurityTestCase[]): void {
    if (!this.config.saveTests) {
      return;
    }

    const path = this.resolveReplayPath(ctx, this.config.saveTests);
    const dir = dirname(path);
    if (dir && dir !== ".") {
      mkdirSync(dir, { recursive: true });
    }

    writeFileSync(
      path,
      JSON.stringify(
        {
          schemaVersion: "1.0",
          generatedAt: new Date().toISOString(),
          targetUrl: ctx.targetUrl,
          role: ctx.auth?.role,
          deterministic: this.config.deterministic === true,
          tests,
        },
        null,
        2
      ),
      "utf-8"
    );
    logger.info(`Saved AI replay artifact: ${path}`);
  }

  private resolveReplayPath(ctx: ExecutionContext, path: string): string {
    const role = sanitizeRole(ctx.auth?.role || "anonymous");
    return path.replace(/\{role\}/g, role);
  }
}

function sanitizeRole(role: string): string {
  return (
    role
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, "-")
      .replace(/^-|-$/g, "") || "role"
  );
}
