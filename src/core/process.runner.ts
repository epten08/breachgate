import { spawn, SpawnOptions } from "child_process";
import { ProcessError } from "./errors.js";
import { logger } from "./logger.js";

export interface ProcessResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export interface RunOptions {
  cwd?: string;
  env?: Record<string, string>;
  timeout?: number;
  shell?: boolean;
}

export async function runProcess(
  command: string,
  args: string[],
  options: RunOptions = {}
): Promise<ProcessResult> {
  const { cwd, env, timeout = 300000, shell = false } = options;

  logger.debug(`Running: ${command} ${args.join(" ")}`, { cwd });

  return new Promise((resolve, reject) => {
    const spawnOptions: SpawnOptions = {
      cwd,
      env: { ...process.env, ...env },
      shell,
      stdio: ["pipe", "pipe", "pipe"],
    };

    const proc = spawn(command, args, spawnOptions);

    let stdout = "";
    let stderr = "";
    let killed = false;

    const timer = setTimeout(() => {
      killed = true;
      proc.kill("SIGTERM");
      reject(
        new ProcessError(
          `Process timed out after ${timeout}ms`,
          `${command} ${args.join(" ")}`,
          null,
          stderr
        )
      );
    }, timeout);

    proc.stdout?.on("data", (data) => {
      stdout += data.toString();
    });

    proc.stderr?.on("data", (data) => {
      stderr += data.toString();
    });

    proc.on("error", (err) => {
      clearTimeout(timer);
      reject(
        new ProcessError(
          `Failed to start process: ${err.message}`,
          `${command} ${args.join(" ")}`,
          null,
          stderr,
          err
        )
      );
    });

    proc.on("close", (code) => {
      clearTimeout(timer);
      if (killed) return;

      const exitCode = code ?? 0;
      resolve({ stdout, stderr, exitCode });
    });
  });
}

export async function runProcessJson<T>(
  command: string,
  args: string[],
  options: RunOptions = {}
): Promise<T> {
  const result = await runProcess(command, args, options);

  if (result.exitCode !== 0) {
    throw new ProcessError(
      `Process exited with code ${result.exitCode}`,
      `${command} ${args.join(" ")}`,
      result.exitCode,
      result.stderr
    );
  }

  try {
    return JSON.parse(result.stdout) as T;
  } catch (err) {
    throw new ProcessError(
      `Failed to parse JSON output: ${(err as Error).message}`,
      `${command} ${args.join(" ")}`,
      result.exitCode,
      result.stdout
    );
  }
}

export async function checkCommand(command: string): Promise<boolean> {
  try {
    const isWindows = process.platform === "win32";
    const checkCmd = isWindows ? "where" : "which";
    const result = await runProcess(checkCmd, [command], { timeout: 5000 });
    return result.exitCode === 0;
  } catch {
    return false;
  }
}
