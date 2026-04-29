# GitHub Actions

Use these examples when Breach Gate is published as either:

- a composite action, for example `epten08/breach-gate@v1`
- an npm package, for example `npx breach-gate@1.0.0`
- a container image, for example `ghcr.io/epten08/breach-gate:1.0.0`

Replace `epten08/breach-gate` and image names with the release location used by this project.

## Pull Request Quick Scan

Run a fast gate on pull requests. This example skips active dynamic and AI checks so developers get quick feedback.

```yaml
name: Breach Gate PR

on:
  pull_request:
    branches: [main]

jobs:
  breach-gate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Run Breach Gate
        uses: epten08/breach-gate@v1
        with:
          config: security.config.yml
          target: ${{ vars.SECURITY_BOT_API_URL }}
          output: security-reports
          format: json,markdown,sarif
          scan-args: --profile pull-request --differential --skip-dynamic --skip-ai

      - name: Upload security reports
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-reports
          path: security-reports/
```

## Protected Branch Full Scan

Run a deeper deployment gate on `main`. This job should target a staging or preview environment, not production.

```yaml
name: Breach Gate Release Gate

on:
  push:
    branches: [main]

jobs:
  breach-gate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    env:
      JWT_TOKEN: ${{ secrets.SECURITY_BOT_JWT_TOKEN }}
      API_KEY: ${{ secrets.SECURITY_BOT_API_KEY }}
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    steps:
      - uses: actions/checkout@v4

      - name: Run Breach Gate
        uses: epten08/breach-gate@v1
        with:
          config: security.config.yml
          target: ${{ vars.STAGING_API_URL }}
          output: security-reports
          format: json,markdown,sarif
          scan-args: --profile main

      - name: Upload security reports
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-reports
          path: security-reports/
```

For protected APIs, configure short-lived auth hooks or role-specific credentials in `security.config.yml`. See [auth-and-safety.md](auth-and-safety.md) for multi-role scans, session cookies, replay artifacts, and production-host guardrails.

## Scheduled Deep Scan

Run active and AI-assisted scans on a schedule, usually against a disposable staging environment.

```yaml
name: Breach Gate Nightly

on:
  schedule:
    - cron: "17 2 * * *"
  workflow_dispatch:

jobs:
  breach-gate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    env:
      JWT_TOKEN: ${{ secrets.SECURITY_BOT_JWT_TOKEN }}
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    steps:
      - uses: actions/checkout@v4

      - name: Run Breach Gate
        uses: epten08/breach-gate@v1
        with:
          config: security.config.yml
          target: ${{ vars.NIGHTLY_API_URL }}
          output: security-reports
          format: json,markdown,sarif
          scan-args: --profile nightly -v

      - name: Upload security reports
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-reports
          path: security-reports/
```

## Docker Image Usage

The container image is useful when a CI environment should not install Node or Trivy directly.

```yaml
- name: Run Breach Gate in Docker
  run: |
    docker run --rm \
      -v "$PWD:/workspace" \
      -w /workspace \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -e JWT_TOKEN="${{ secrets.SECURITY_BOT_JWT_TOKEN }}" \
      ghcr.io/epten08/breach-gate:1.0.0 \
      scan --ci --config security.config.yml --profile main --format json,markdown,sarif --output security-reports
```

## NPM Usage

Use this style when the package is published to npm or a private registry.

```yaml
- uses: actions/setup-node@v4
  with:
    node-version: "20"
    cache: npm

- run: npx breach-gate@1.0.0 scan --ci --profile main --config security.config.yml --format json,markdown,sarif --output security-reports
```

## Template File

A combined workflow template is available at [templates/github-actions-security.yml](templates/github-actions-security.yml).

For SARIF upload and PR summary examples, see [code-scanning.md](code-scanning.md).

