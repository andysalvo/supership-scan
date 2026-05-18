#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { readFileSync, readdirSync, statSync, existsSync } from "fs";
import { join, relative, extname } from "path";

const SUPERSHIP_URL = process.env.SUPERSHIP_URL || "https://supership.crestsystems.ai";
const SCAN_EXTENSIONS = new Set([
  ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
  ".json", ".env", ".yaml", ".yml", ".toml",
  ".sql", ".py", ".rb", ".go", ".rs",
  ".html", ".svelte", ".vue",
]);
const SKIP_DIRS = new Set([
  "node_modules", ".git", ".next", "dist", "build",
  "__pycache__", ".venv", "vendor", ".cache",
]);

function walkDir(dir, base, max = 50) {
  const files = {};
  let count = 0;
  function walk(d) {
    if (count >= max) return;
    let entries;
    try { entries = readdirSync(d); } catch { return; }
    for (const entry of entries) {
      if (count >= max) return;
      const full = join(d, entry);
      if (SKIP_DIRS.has(entry)) continue;
      let stat;
      try { stat = statSync(full); } catch { continue; }
      if (stat.isDirectory()) {
        walk(full);
      } else if (stat.isFile()) {
        const ext = extname(entry).toLowerCase();
        if (!SCAN_EXTENSIONS.has(ext) && !entry.startsWith(".env")) continue;
        if (stat.size > 100_000) continue;
        try {
          files[relative(base, full)] = readFileSync(full, "utf8");
          count++;
        } catch {}
      }
    }
  }
  walk(dir);
  return files;
}

const server = new Server(
  { name: "supership", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "scan_directory",
      description: "Scan a local directory for security vulnerabilities. Checks for exposed secrets, auth holes, injection flaws, config issues, Supabase misconfigurations, and logging leaks. Code is sent to supership.crestsystems.ai for analysis (free tier: score + grade only, no source code stored).",
      inputSchema: {
        type: "object",
        properties: {
          path: { type: "string", description: "Absolute path to the directory to scan" },
          tier: { type: "string", enum: ["free", "quick", "full"], default: "free", description: "Scan tier: free (score only), quick ($1, secrets+config), full ($5, all categories)" },
        },
        required: ["path"],
      },
    },
    {
      name: "scan_code",
      description: "Scan code snippets for security vulnerabilities. Pass file contents directly instead of reading from disk.",
      inputSchema: {
        type: "object",
        properties: {
          files: { type: "object", description: "Map of filepath to file content, e.g. {\"app.js\": \"const key = ...\"}" },
          tier: { type: "string", enum: ["free", "quick", "full"], default: "free" },
        },
        required: ["files"],
      },
    },
    {
      name: "attest",
      description: "Get a witnessed attestation for scan results. Returns a signed, timestamped, chain-anchored proof that a scan occurred with specific results. The attestation is the product -- the scan is free, the proof costs $0.01.",
      inputSchema: {
        type: "object",
        properties: {
          input_hash: { type: "string", description: "SHA-256 hash of the scanned input" },
          score: { type: "number", description: "Scan score (0-100)" },
          grade: { type: "string", description: "Scan grade (A-F)" },
          summary: { type: "object", description: "Finding counts by severity" },
        },
        required: ["input_hash", "score", "grade"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  if (name === "scan_directory") {
    const dir = args.path;
    if (!existsSync(dir)) {
      return { content: [{ type: "text", text: `Directory not found: ${dir}` }] };
    }
    const files = walkDir(dir, dir);
    const fileCount = Object.keys(files).length;
    if (fileCount === 0) {
      return { content: [{ type: "text", text: "No scannable files found in directory." }] };
    }

    const tier = args.tier || "free";
    const res = await fetch(`${SUPERSHIP_URL}/scan/${tier}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ files }),
      signal: AbortSignal.timeout(30000),
    });
    const data = await res.json();
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }

  if (name === "scan_code") {
    const tier = args.tier || "free";
    const res = await fetch(`${SUPERSHIP_URL}/scan/${tier}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ files: args.files }),
      signal: AbortSignal.timeout(30000),
    });
    const data = await res.json();
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }

  if (name === "attest") {
    const res = await fetch(`${SUPERSHIP_URL}/attest`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        input_hash: args.input_hash,
        score: args.score,
        grade: args.grade,
        summary: args.summary || {},
      }),
      signal: AbortSignal.timeout(10000),
    });
    const data = await res.json();
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }

  return { content: [{ type: "text", text: `Unknown tool: ${name}` }] };
});

const transport = new StdioServerTransport();
await server.connect(transport);
