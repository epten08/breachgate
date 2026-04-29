# syntax=docker/dockerfile:1

FROM node:20-bookworm-slim AS build

WORKDIR /opt/breach-gate

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

RUN npm prune --omit=dev

FROM node:20-bookworm-slim AS runtime

LABEL org.opencontainers.image.title="Breach Gate"
LABEL org.opencontainers.image.description="CLI-based automated security analysis tool for CI/CD pipelines"
LABEL org.opencontainers.image.source="https://github.com/epten08/breach-gate"
LABEL org.opencontainers.image.licenses="MIT"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg docker.io \
    && mkdir -p /usr/share/keyrings \
    && curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key \
      | gpg --dearmor -o /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
      > /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends trivy \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/breach-gate

COPY package.json package-lock.json README.md security.config.yml .env.example ./
COPY --from=build /opt/breach-gate/node_modules ./node_modules
COPY --from=build /opt/breach-gate/dist ./dist

RUN npm install -g --omit=dev .

WORKDIR /workspace

ENTRYPOINT ["breach-gate"]
CMD ["--help"]

