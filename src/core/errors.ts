export class SecBotError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly cause?: Error
  ) {
    super(message);
    this.name = "SecBotError";
  }
}

export class ConfigError extends SecBotError {
  constructor(message: string, cause?: Error) {
    super(message, "CONFIG_ERROR", cause);
    this.name = "ConfigError";
  }
}

export class ScannerError extends SecBotError {
  constructor(
    message: string,
    public readonly scanner: string,
    cause?: Error
  ) {
    super(message, "SCANNER_ERROR", cause);
    this.name = "ScannerError";
  }
}

export class ScannerUnavailableError extends ScannerError {
  constructor(message: string, scanner: string, cause?: Error) {
    super(message, scanner, cause);
    this.name = "ScannerUnavailableError";
  }
}

export class EnvironmentError extends SecBotError {
  constructor(message: string, cause?: Error) {
    super(message, "ENVIRONMENT_ERROR", cause);
    this.name = "EnvironmentError";
  }
}

export class ProcessError extends SecBotError {
  constructor(
    message: string,
    public readonly command: string,
    public readonly exitCode: number | null,
    public readonly stderr: string,
    cause?: Error
  ) {
    super(message, "PROCESS_ERROR", cause);
    this.name = "ProcessError";
  }
}

export class AIError extends SecBotError {
  constructor(message: string, cause?: Error) {
    super(message, "AI_ERROR", cause);
    this.name = "AIError";
  }
}
