# Breach Gate – Requirements Specification (MVP)

## 1. Purpose

The purpose of this project is to build a CLI-based automated security analysis tool that performs continuous security checks against a Dockerised REST API and integrates seamlessly into local development and CI pipelines.

The system must identify high-risk, exploitable security issues early in the development lifecycle and present findings in a developer-friendly, actionable format.

---

## 2. Scope

### 2.1 In Scope (MVP)

- REST API security testing
- Docker / docker-compose–based targets
- Automated execution via CLI and CI
- Static, container, dynamic, and AI-assisted security checks
- Markdown and JSON reporting
- Fail-fast behavior based on severity thresholds

### 2.2 Out of Scope (MVP)

- Web UI or dashboard
- Multi-tenant SaaS deployment
- Auto-remediation or code modification
- Cloud infrastructure scanning (AWS/GCP/Azure)
- Network-level attacks (DoS, port scanning)
- Zero-day vulnerability discovery
- Manual rule authoring by users

---

## 3. Functional Requirements

### 3.1 CLI Interface

| ID | Requirement |
| --- | --- |
| FR-CLI-1 | The system shall provide a CLI command to execute security scans. |
| FR-CLI-2 | The CLI shall support execution in both local development environments and CI/CD pipelines. |
| FR-CLI-3 | The CLI shall return a non-zero exit code when configured severity thresholds are exceeded. |

### 3.2 Target Environment Handling

| ID | Requirement |
| --- | --- |
| FR-ENV-1 | The system shall support targets defined via `docker-compose.yml`. |
| FR-ENV-2 | The system shall automatically start the target environment, detect API readiness, and determine the base API URL. |
| FR-ENV-3 | The system shall cleanly tear down the environment after execution. |

### 3.3 Security Scanning Capabilities

#### 3.3.1 Static & Dependency Scanning

| ID | Requirement |
| --- | --- |
| FR-STAT-1 | The system shall scan application code and dependencies for known vulnerabilities. |
| FR-STAT-2 | The system shall detect vulnerable dependencies and hardcoded secrets (where supported by tooling). |

#### 3.3.2 Container Image Scanning

| ID | Requirement |
| --- | --- |
| FR-CONT-1 | The system shall scan Docker images for OS-level vulnerabilities. |
| FR-CONT-2 | The system shall identify critical CVEs and insecure base images. |

#### 3.3.3 Dynamic API Scanning

| ID | Requirement |
| --- | --- |
| FR-DYN-1 | The system shall perform dynamic security scans against running API endpoints. |
| FR-DYN-2 | The system shall support authenticated and unauthenticated scans. |
| FR-DYN-3 | The system shall limit scans to documented API endpoints when an OpenAPI specification is provided. |

#### 3.3.4 AI-Assisted Abuse Testing

| ID | Requirement |
| --- | --- |
| FR-AI-1 | The system shall use a language model to generate targeted abuse and edge-case test scenarios. |
| FR-AI-2 | AI-generated tests shall focus on authentication and authorization bypass, parameter tampering, and business logic violations. |
| FR-AI-3 | AI-generated tests shall produce deterministic, reproducible findings. |

### 3.4 Findings Processing

| ID | Requirement |
| --- | --- |
| FR-FIND-1 | The system shall normalize outputs from all scanners into a unified finding schema. |
| FR-FIND-2 | The system shall deduplicate equivalent findings across multiple sources. |
| FR-FIND-3 | Each finding shall include: severity, category, evidence, confidence level, exploitability estimate, and source attribution. |

### 3.5 Reporting

| ID | Requirement |
| --- | --- |
| FR-REP-1 | The system shall generate a Markdown security report. |
| FR-REP-2 | The system shall generate a machine-readable JSON report. |
| FR-REP-3 | Reports shall include: executive summary, list of critical and high-risk findings, and recommended remediation guidance. |

---

## 4. Non-Functional Requirements

### 4.1 Performance

| ID | Requirement |
| --- | --- |
| NFR-PERF-1 | A full MVP scan shall complete within 10 minutes on a developer workstation. |

### 4.2 Usability

| ID | Requirement |
| --- | --- |
| NFR-USAB-1 | Reports must be understandable by developers without formal security training. |
| NFR-USAB-2 | False positives must be minimized through normalization and confidence scoring. |

### 4.3 Extensibility

| ID | Requirement |
| --- | --- |
| NFR-EXT-1 | Security scanners shall be implemented as pluggable adapters. |
| NFR-EXT-2 | The AI engine shall support both local and remote models. |

### 4.4 Security

| ID | Requirement |
| --- | --- |
| NFR-SEC-1 | The system shall not transmit application code or secrets unless explicitly configured. |
| NFR-SEC-2 | The system shall operate in a read-only manner against target systems. |

---

## 5. Configuration Requirements

| ID | Requirement |
| --- | --- |
| CR-1 | The system shall be configurable via a YAML configuration file. |
| CR-2 | Configuration shall include: enabled scans, severity thresholds, AI model selection, and target definition. |

---

## 6. Supported Technologies (MVP)

| Component | Technology |
| --- | --- |
| Language | TypeScript (Node.js) |
| Container Runtime | Docker |
| Static & Container Scanning | Trivy |
| Dynamic Scanning | OWASP ZAP (API mode) |
| AI Models | Local (Ollama) or API-based LLM |
| Output Formats | Markdown, JSON |

---

## 7. Success Criteria

The MVP shall be considered successful if:

- It runs locally and in CI without modification
- It detects at least one real security issue in a demo API
- It fails CI builds on critical findings
- Developers can act on findings without external security expertise

---

## 8. Future Considerations (Non-MVP)

- HTML reports
- GitHub/GitLab PR annotations
- Policy-as-code
- Multi-project scanning
- SaaS deployment model
