# Code Scanning And PR Feedback

Breach Gate can emit SARIF with `--format sarif`. SARIF is intended for CI systems that can surface security findings in pull requests or code scanning dashboards.

## GitHub Code Scanning

```yaml
name: Breach Gate Code Scanning

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  breach-gate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Run Breach Gate
        uses: OWNER/breach-gate@v1
        with:
          config: security.config.yml
          target: ${{ vars.SECURITY_BOT_API_URL }}
          output: security-reports
          format: json,markdown,sarif
          scan-args: --profile pull-request --differential

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: security-reports/security-report.sarif

      - name: Upload security reports
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-reports
          path: security-reports/
```

## GitHub PR Summary

For lightweight PR feedback, use the JSON report to append a summary to the workflow step summary.

```yaml
- name: Add Breach Gate summary
  if: always()
  shell: bash
  run: |
    node <<'NODE' >> "$GITHUB_STEP_SUMMARY"
    const fs = require('fs');
    const report = JSON.parse(fs.readFileSync('security-reports/security-report.json', 'utf8'));
    console.log('## Breach Gate');
    console.log('');
    console.log(`Verdict: **${report.verdict?.status || 'UNKNOWN'}**`);
    console.log(`Policy: **${report.policyEvaluation?.status || 'not applied'}**`);
    console.log(`Findings: **${report.summary.total}**`);
    if (report.policyEvaluation?.reasons?.length) {
      console.log('');
      console.log('### Policy Reasons');
      for (const reason of report.policyEvaluation.reasons) console.log(`- ${reason}`);
    }
    NODE
```

## Notes

- In differential mode, SARIF results include only findings that are not suppressed by the active baseline.
- Dynamic API findings do not always map to source files. Breach Gate anchors SARIF results to `security.config.yml` and includes endpoint, category, risk, and fingerprint metadata in each result.
- Use `permissions.security-events: write` when uploading SARIF to GitHub code scanning.

