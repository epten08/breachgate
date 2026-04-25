# GitLab CI

Use this template when Breach Gate is published as a container image. Replace `ghcr.io/OWNER/breach-gate:1.0.0` with the image location used by this project.

## Security Gate

```yaml
stages:
  - security

security_bot:
  stage: security
  image: ghcr.io/OWNER/breach-gate:1.0.0
  variables:
    SEC_BOT_OUTPUT: security-reports
  script:
    - breach-gate scan --ci --config security.config.yml --format json,markdown,sarif --output "$SEC_BOT_OUTPUT" ${SEC_BOT_ARGS:-}
  artifacts:
    when: always
    expire_in: 14 days
    paths:
      - security-reports/
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      variables:
        SEC_BOT_ARGS: "--profile pull-request --differential --skip-dynamic --skip-ai"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
      variables:
        SEC_BOT_ARGS: "--profile main"
    - if: $CI_PIPELINE_SOURCE == "schedule"
      variables:
        SEC_BOT_ARGS: "--profile nightly -v"
```

## Docker Socket For Container Scans

If container image scanning needs access to locally built images, use Docker-in-Docker or a runner with Docker socket access. The simplest runner-level setup is to mount `/var/run/docker.sock` into jobs and use the Breach Gate image as the job image.

For Docker-in-Docker:

```yaml
security_bot:
  stage: security
  image: ghcr.io/OWNER/breach-gate:1.0.0
  services:
    - name: docker:26-dind
      command: ["--tls=false"]
  variables:
    DOCKER_HOST: tcp://docker:2375
    DOCKER_TLS_CERTDIR: ""
  script:
    - docker build -t "$CI_REGISTRY_IMAGE:test" .
    - breach-gate scan --ci --profile main --config security.config.yml --format json,markdown,sarif --output security-reports
  artifacts:
    when: always
    paths:
      - security-reports/
```

## Secrets

Store values such as `JWT_TOKEN`, `API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, and `ZAP_API_KEY` as masked GitLab CI/CD variables. Reference them in `security.config.yml` with `${JWT_TOKEN}` style interpolation.

## Template File

A copyable template is available at [templates/gitlab-security.yml](templates/gitlab-security.yml).

