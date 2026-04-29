import { Scanner } from "../scanner.js";
import { ExecutionContext } from "../../orchestrator/context.js";
import { RawFinding } from "../../findings/raw.finding.js";
import { SecurityTestCase, TestGenerator } from "../../ai/test.generator.js";
import { TestExecutor } from "../../ai/executor.js";
import { TestEvaluator } from "../../ai/evaluator.js";
import { AIConfig } from "../../ai/adversary.js";
import { logger } from "../../core/logger.js";
import { ScannerUnavailableError } from "../../core/errors.js";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { dirname } from "path";

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
      const results = await executor.execute(testCases);
      logger.debug(
        `Executed ${results.length} tests, ${results.filter((r) => r.isVulnerable).length} potential vulnerabilities`
      );

      // Evaluate results
      const evaluator = new TestEvaluator(ctx, isAvailable ? aiConfig : undefined);
      const findings = await evaluator.evaluate(results);

      logger.scanner(this.name, "done", `Found ${findings.length} issues`);
      return findings;
    } catch (err) {
      if (err instanceof ScannerUnavailableError) {
        throw err;
      }
      logger.scanner(this.name, "error", (err as Error).message);
      return [];
    }
  }

  private loadReplayTests(ctx: ExecutionContext): SecurityTestCase[] {
    const path = this.resolveReplayPath(ctx, this.config.replayTests!);
    if (!existsSync(path)) {
      throw new ScannerUnavailableError(`AI replay artifact not found: ${path}`, this.name);
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
