import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import type { BotConfig } from "./config.js";

/**
 * Generates a Software Bill of Materials (SBOM) snapshot for the bot image.
 *
 * This is a lightweight, deterministic SBOM that captures:
 * - The package.json metadata (name, version, dependencies)
 * - The SHA-256 hash of the current source tree (src/)
 * - The current configuration state (excluding secrets)
 *
 * This SBOM is used by the Mimir notifier to verify image integrity and
 * ensure that the running bot matches the expected deployment artifact.
 *
 * It does NOT include:
 * - Private keys or tokens
 * - Unbounded remote payloads
 * - Sensitive environment variables
 */

export interface SbomSnapshot {
  /** ISO timestamp of generation */
  generatedAt: string;
  /** Package name from package.json */
  packageName: string;
  /** Package version from package.json */
  packageVersion: string;
  /** SHA-256 hash of the src/ directory contents */
  sourceHash: string;
  /** Configuration summary (non-sensitive) */
  configSummary: {
    network: string;
    marketContractId: string;
    squadContractId: string;
    pollIntervalMs: number;
    maxNotificationsPerCycle: number;
  };
  /** List of production dependencies */
  dependencies: string[];
}

/**
 * Reads package.json and extracts metadata.
 */
async function readPackageJson(): Promise<{ name: string; version: string; dependencies: string[] }> {
  try {
    const pkgRaw = await readFile("package.json", "utf8");
    const pkg = JSON.parse(pkgRaw) as {
      name: string;
      version: string;
      dependencies?: Record<string, string>;
    };
    const deps = pkg.dependencies ? Object.keys(pkg.dependencies).sort() : [];
    return {
      name: pkg.name || "unknown",
      version: pkg.version || "0.0.0",
      dependencies: deps,
    };
  } catch {
    // Fallback if package.json is missing or invalid
    return {
      name: "unknown",
      version: "0.0.0",
      dependencies: [],
    };
  }
}

/**
 * Computes a deterministic hash of the src/ directory.
 * Reads all .ts files in src/ and hashes their concatenated content.
 */
async function computeSourceHash(): Promise<string> {
  const { readdir, readFile } = await import("node:fs/promises");
  const { join } = await import("node:path");
  const { createHash } = await import("node:crypto");

  try {
    const srcDir = join(process.cwd(), "src");
    const files = await readdir(srcDir);
    const tsFiles = files.filter((f) => f.endsWith(".ts")).sort();

    const hash = createHash("sha256");
    for (const file of tsFiles) {
      const content = await readFile(join(srcDir, file), "utf8");
      hash.update(content);
    }
    return hash.digest("hex");
  } catch {
    // If src/ is not readable, return a placeholder
    return "0000000000000000000000000000000000000000000000000000000000000000";
  }
}

/**
 * Generates a full SBOM snapshot.
 */
export async function generateSbom(config: BotConfig): Promise<SbomSnapshot> {
  const pkg = await readPackageJson();
  const sourceHash = await computeSourceHash();

  return {
    generatedAt: new Date().toISOString(),
    packageName: pkg.name,
    packageVersion: pkg.version,
    sourceHash,
    configSummary: {
      network: config.networkPassphrase === "Test SDF Network ; September 2015" ? "testnet" : "custom",
      marketContractId: config.marketContractId,
      squadContractId: config.squadContractId,
      pollIntervalMs: config.pollIntervalMs,
      maxNotificationsPerCycle: config.maxNotificationsPerCycle,
    },
    dependencies: pkg.dependencies,
  };
}

/**
 * Formats the SBOM as a human-readable string for logging.
 */
export function formatSbom(sbom: SbomSnapshot): string {
  const lines = [
    "SBOM Snapshot:",
    `  Generated: ${sbom.generatedAt}`,
    `  Package: ${sbom.packageName}@${sbom.packageVersion}`,
    `  Source Hash: ${sbom.sourceHash}`,
    `  Network: ${sbom.configSummary.network}`,
    `  Market Contract: ${sbom.configSummary.marketContractId}`,
    `  Squad Contract: ${sbom.configSummary.squadContractId}`,
    `  Poll Interval: ${sbom.configSummary.pollIntervalMs}ms`,
    `  Max Notifications/Cycle: ${sbom.configSummary.maxNotificationsPerCycle}`,
    `  Dependencies: ${sbom.dependencies.join(", ") || "none"}`,
  ];
  return lines.join("\n");
}