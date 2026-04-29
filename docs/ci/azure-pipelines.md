# Azure Pipelines

Use this template when Breach Gate is published as an npm package or a container image. Replace package, image, and service connection names before use.

## NPM-Based Security Gate

```yaml
trigger:
  branches:
    include:
      - main

pr:
  branches:
    include:
      - main

schedules:
  - cron: "17 2 * * *"
    displayName: Nightly security scan
    branches:
      include:
        - main
    always: true

pool:
  vmImage: ubuntu-latest

variables:
  SEC_BOT_OUTPUT: security-reports

steps:
  - checkout: self

  - task: NodeTool@0
    inputs:
      versionSpec: "20.x"

  - script: |
      npx breach-gate@1.0.0 scan --ci --profile main --config security.config.yml --format json,markdown,sarif --output "$(SEC_BOT_OUTPUT)" $(SEC_BOT_ARGS)
    displayName: Run Breach Gate
    env:
      JWT_TOKEN: $(SECURITY_BOT_JWT_TOKEN)
      API_KEY: $(SECURITY_BOT_API_KEY)
      OPENAI_API_KEY: $(OPENAI_API_KEY)

  - publish: $(SEC_BOT_OUTPUT)
    artifact: security-reports
    condition: always()
```

## Container-Based Security Gate

```yaml
steps:
  - checkout: self

  - script: |
      docker run --rm \
        -v "$(System.DefaultWorkingDirectory):/workspace" \
        -w /workspace \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -e JWT_TOKEN="$(SECURITY_BOT_JWT_TOKEN)" \
        ghcr.io/epten08/breach-gate:1.0.0 \
        scan --ci --profile main --config security.config.yml --format json,markdown,sarif --output security-reports
    displayName: Run Breach Gate in Docker

  - publish: security-reports
    artifact: security-reports
    condition: always()
```

## Template File

A copyable template is available at [templates/azure-pipelines-security.yml](templates/azure-pipelines-security.yml).

