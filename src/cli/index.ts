#!/usr/bin/env node

import { config } from "dotenv";
import { Command } from "commander";
import { createRunCommand } from "./commands/run.js";
import { createInitCommand } from "./commands/init.js";
import { createDoctorCommand } from "./commands/doctor.js";
import { logger } from "../core/logger.js";

// Load environment variables from .env file without adding noise to CI logs.
config({ quiet: true });

const VERSION = "1.0.0";

async function main(): Promise<void> {
  const program = new Command();

  program
    .name("breach-gate")
    .description("CLI-based automated security analysis tool")
    .version(VERSION)
    .option("--no-color", "Disable colored output")
    .hook("preAction", (thisCommand) => {
      const opts = thisCommand.opts();
      if (opts.color === false) {
        // Chalk respects NO_COLOR env var
        process.env.NO_COLOR = "1";
      }
    });

  // Add commands
  program.addCommand(createRunCommand());
  program.addCommand(createInitCommand());
  program.addCommand(createDoctorCommand());

  // Default action (no command specified)
  program.action(() => {
    program.help();
  });

  // Error handling
  program.exitOverride((err) => {
    if (err.code === "commander.help" || err.code === "commander.version") {
      process.exit(0);
    }
    process.exit(1);
  });

  try {
    await program.parseAsync(process.argv);
  } catch (err) {
    logger.error(`Fatal error: ${(err as Error).message}`);
    process.exit(1);
  }
}

main();

