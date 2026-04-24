#!/usr/bin/env node

import { createHash } from "crypto";
import { mkdirSync, readFileSync, writeFileSync } from "fs";
import { dirname, resolve } from "path";

const outputPath = process.argv[2] || "sbom.cdx.json";
const packageJson = JSON.parse(readFileSync("package.json", "utf-8"));
const packageLock = JSON.parse(readFileSync("package-lock.json", "utf-8"));

const components = [];
const seen = new Set();

for (const [path, entry] of Object.entries(packageLock.packages || {})) {
  if (!path.startsWith("node_modules/") || !entry.version) {
    continue;
  }

  const name = path.replace(/^node_modules\//, "");
  const bomRef = `pkg:npm/${encodeURIComponent(name)}@${entry.version}`;
  if (seen.has(bomRef)) {
    continue;
  }
  seen.add(bomRef);

  const component = {
    type: "library",
    "bom-ref": bomRef,
    name,
    version: entry.version,
    purl: bomRef,
    scope: entry.dev ? "optional" : "required",
  };

  if (entry.license) {
    component.licenses = [
      {
        license: {
          id: entry.license,
        },
      },
    ];
  }

  components.push(component);
}

components.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));

const bom = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  serialNumber: `urn:uuid:${stableUuid(`${packageJson.name}@${packageJson.version}`)}`,
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    tools: [
      {
        vendor: "Breach Gate",
        name: "generate-sbom",
        version: packageJson.version,
      },
    ],
    component: {
      type: "application",
      "bom-ref": `pkg:npm/${packageJson.name}@${packageJson.version}`,
      name: packageJson.name,
      version: packageJson.version,
      purl: `pkg:npm/${packageJson.name}@${packageJson.version}`,
    },
  },
  components,
};

const resolvedOutput = resolve(outputPath);
mkdirSync(dirname(resolvedOutput), { recursive: true });
writeFileSync(resolvedOutput, `${JSON.stringify(bom, null, 2)}\n`, "utf-8");
console.log(`Generated ${outputPath} with ${components.length} component(s)`);

function stableUuid(value) {
  const hash = createHash("sha256").update(value).digest("hex");
  return [
    hash.slice(0, 8),
    hash.slice(8, 12),
    `5${hash.slice(13, 16)}`,
    `8${hash.slice(17, 20)}`,
    hash.slice(20, 32),
  ].join("-");
}

