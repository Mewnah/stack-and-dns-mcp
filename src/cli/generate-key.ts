#!/usr/bin/env node
/**
 * Generates customer API keys.
 *
 *   npm run keys:generate -- --plan pro --label "Acme Corp"
 *   npm run keys:generate -- --plan enterprise --count 3 --json
 *
 * Prints the raw key once (give it to the customer) and the SHA-256 hash to
 * store server-side in STACKDNS_API_KEYS_FILE. STACKDNS_API_KEYS accepts the
 * raw key inline for small deployments.
 */

import { apiKeyId, apiKeyPrefix, generateApiKey, hashApiKey } from "../middleware/auth.js";

interface CliOptions {
  plan: "free" | "pro" | "enterprise";
  label: string;
  count: number;
  json: boolean;
}

function parse(argv: string[]): CliOptions {
  const options: CliOptions = { plan: "pro", label: "", count: 1, json: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--plan" && argv[i + 1]) {
      const plan = String(argv[++i]).toLowerCase();
      if (plan !== "free" && plan !== "pro" && plan !== "enterprise") {
        throw new Error(`Invalid plan "${plan}". Use free, pro or enterprise.`);
      }
      options.plan = plan;
    } else if (arg === "--label" && argv[i + 1]) {
      options.label = String(argv[++i]);
    } else if (arg === "--count" && argv[i + 1]) {
      const count = Number(argv[++i]);
      if (!Number.isInteger(count) || count < 1 || count > 100) throw new Error("--count must be an integer between 1 and 100.");
      options.count = count;
    } else if (arg === "--json") {
      options.json = true;
    } else if (arg === "--help" || arg === "-h") {
      process.stdout.write("Usage: generate-key [--plan free|pro|enterprise] [--label <text>] [--count <n>] [--json]\n");
      process.exit(0);
    } else {
      throw new Error(`Unknown argument "${arg}". Run with --help.`);
    }
  }
  return options;
}

function main(): void {
  const options = parse(process.argv.slice(2));
  const records = Array.from({ length: options.count }, (_, index) => {
    const key = generateApiKey();
    const keyHash = hashApiKey(key);
    return {
      id: apiKeyId(keyHash),
      key,
      keyHash,
      prefix: apiKeyPrefix(key),
      plan: options.plan,
      label: options.label || `${options.plan} key ${index + 1}`,
      active: true,
      createdAt: new Date().toISOString()
    };
  });

  if (options.json) {
    process.stdout.write(JSON.stringify(records, null, 2) + "\n");
    return;
  }

  for (const record of records) {
    process.stdout.write("\n");
    process.stdout.write(`API key (give to customer, shown once):\n  ${record.key}\n`);
    process.stdout.write(`Key id:      ${record.id}\n`);
    process.stdout.write(`SHA-256:     ${record.keyHash}\n`);
    process.stdout.write(`Plan:        ${record.plan}\n`);
    process.stdout.write(`Label:       ${record.label}\n`);
  }
  process.stdout.write("\nInline env format (STACKDNS_API_KEYS):\n");
  process.stdout.write(`  ${records.map((r) => `${r.key}:${r.plan}:${r.label.replace(/[:,]/g, " ")}`).join(",")}\n`);
  process.stdout.write("\nKey-file format (STACKDNS_API_KEYS_FILE, hashes only):\n");
  process.stdout.write(
    JSON.stringify(
      records.map((r) => ({ id: r.id, keyHash: r.keyHash, prefix: r.prefix, plan: r.plan, label: r.label, active: true })),
      null,
      2
    ) + "\n"
  );
}

try {
  main();
} catch (err) {
  process.stderr.write(`${(err as Error).message}\n`);
  process.exit(1);
}
