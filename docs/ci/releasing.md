# Releasing Breach Gate

Two separate pipelines. They are often confused, so be precise about which one
you want.

| Workflow | Trigger | Publishes |
|---|---|---|
| `auto-release.yml` | push to `main` | Git tag, GitHub Release, floating major tag. This is what updates the **GitHub Marketplace** listing for the Action. |
| `release.yml` | version tag push, or manual dispatch | **npm package** and the GHCR container image. |

## Merging to main does not publish to npm

`auto-release.yml` pushes its tag using the default `GITHUB_TOKEN`, and GitHub
deliberately does not trigger workflows from events created with that token.
So the tag it creates does **not** start `release.yml`, and nothing reaches npm
until you ask for it.

For a security tool this is a reasonable default: a human decides when a build
reaches the registry.

## Publishing to npm

Run the release workflow against the tag that `auto-release` already created:

```bash
gh workflow run release.yml --ref v2.0.0 -f publish=true
```

Using `--ref <tag>` matters. Without it the workflow runs against the default
branch, so you would publish whatever `main` currently contains under the
version in `package.json`, which is not necessarily what was tagged.

Dry run first, which runs every verification step and publishes nothing:

```bash
gh workflow run release.yml --ref v2.0.0 -f publish=false
```

## Marketplace releases

Handled entirely by `auto-release.yml` on merge to `main`. It reads the version
from `package.json`, creates `v<version>`, cuts a GitHub Release, and moves the
floating major tag (`v2`) so that `uses: epten08/breachgate@v2` resolves.

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
# tag must match package.json version (tag-triggered runs only)
npm run typecheck
npm run test:controls   # clean targets must stay SAFE
npm run precision       # precision gated at exactly 1.0
npm test
npm run test:cli
npm run build
npm audit --omit=dev
npm run sbom -- sbom.cdx.json
npm pack --dry-run
```

The two accuracy gates were missing from this list until v2.0.0, which meant a
build whose precision had never been measured could be published. A single
false positive now blocks the release.

## Tagging a release manually

Normally `auto-release.yml` does this for you on merge to `main`. If you are
tagging by hand, push from a local clone so the event triggers `release.yml`:

```bash
git tag v2.0.0
git push origin v2.0.0
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

