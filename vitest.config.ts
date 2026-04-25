import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    reporter: "verbose",
    // CLI tests spawn subprocesses; integration tests do I/O — give them room
    testTimeout: 60000,
    hookTimeout: 30000,
    // Suppress logger output unless a test fails
    onConsoleLog: (log) => {
      // Only suppress internal scanner/logger output, keep test output
      if (log.includes("[ERR]") || log.includes("[WARN]") || log.includes("[INFO]") || log.includes("[DBG]")) {
        return false;
      }
      return true;
    },
  },
});
