# Releasing Breach Gate

The release workflow lives at `.github/workflows/release.yml`.

## Release Inputs

The workflow can be run in two ways:

- Push a semantic version tag such as `v1.2.3`.
- Run `workflow_dispatch` manually and set `publish` to `true`.

Manual runs with `publish=false` execute verification only.

## Required Secrets

- `NPM_TOKEN`: npm automation token with permission to publish `breach-gate`.
- `GITHUB_TOKEN`: provided by GitHub Actions and used to publish the GHCR image.

## What The Workflow Publishes

- npm package: `breach-gate`
- container image: `ghcr.io/<owner>/breach-gate`
- CycloneDX SBOM artifact: `sbom.cdx.json`
- npm provenance with `npm publish --provenance`
- container provenance and SBOM attestations from Docker Buildx

The workflow runs these checks before publishing:

```bash
npm ci
npm run typecheck
npm test
npm run test:cli
npm run build
npm audit --omit=dev
npm run sbom -- sbom.cdx.json
npm pack --dry-run
```

## Tagging A Release

```bash
git tag v1.2.3
git push origin v1.2.3
```

## Package Contents

The npm package includes:

- `dist/`
- `README.md`
- `security.config.yml`
- `.env.example`

The Docker image includes:

- Node.js runtime
- Built Breach Gate CLI
- Trivy
- Docker CLI for image-scan workflows that mount a Docker socket

OWASP ZAP and Ollama remain external services or separate containers.

