#!/usr/bin/env node

import { readFileSync, readdirSync, statSync, existsSync } from 'fs';
import { join, relative, extname } from 'path';
import { createHash } from 'crypto';

const SUPERSHIP_URL = process.env.SUPERSHIP_URL || 'https://supership.crestsystems.ai';
const MAX_FILES = 100;
const MAX_FILE_SIZE = 100_000;
const SCAN_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx',
  '.json', '.env', '.yaml', '.yml', '.toml',
  '.sql', '.py', '.rb', '.go', '.rs',
  '.html', '.svelte', '.vue',
]);
const SKIP_DIRS = new Set([
  'node_modules', '.git', '.next', 'dist', 'build',
  '__pycache__', '.venv', 'vendor', '.cache',
]);

const args = process.argv.slice(2);
const flags = {};
const positional = [];
for (const a of args) {
  if (a === '--attest') flags.attest = true;
  else if (a === '--json') flags.json = true;
  else if (a === '--help' || a === '-h') flags.help = true;
  else if (a.startsWith('--tier=')) flags.tier = a.split('=')[1];
  else positional.push(a);
}

if (flags.help || positional.length === 0) {
  console.log(`
  supership-scan <directory> [options]

  Scan a directory for security vulnerabilities. Code never leaves your machine.

  Options:
    --attest     Send results to supership for witnessed attestation ($0.01)
    --tier=free  Tier: free (default), quick, full, deep
    --json       Output raw JSON
    --help       Show this help

  Examples:
    supership-scan .                    # scan current directory
    supership-scan ./src --attest       # scan and get witnessed proof
    supership-scan . --tier=full --json # full scan, JSON output
  `);
  process.exit(0);
}

const targetDir = positional[0];
if (!existsSync(targetDir)) {
  console.error(`Directory not found: ${targetDir}`);
  process.exit(1);
}

function walkDir(dir, base) {
  const files = {};
  let count = 0;

  function walk(d) {
    if (count >= MAX_FILES) return;
    let entries;
    try { entries = readdirSync(d); } catch { return; }

    for (const entry of entries) {
      if (count >= MAX_FILES) return;
      const full = join(d, entry);
      if (SKIP_DIRS.has(entry)) continue;

      let stat;
      try { stat = statSync(full); } catch { continue; }

      if (stat.isDirectory()) {
        walk(full);
      } else if (stat.isFile()) {
        const ext = extname(entry).toLowerCase();
        if (!SCAN_EXTENSIONS.has(ext) && !entry.startsWith('.env')) continue;
        if (stat.size > MAX_FILE_SIZE) continue;

        try {
          const content = readFileSync(full, 'utf8');
          const rel = relative(base, full);
          files[rel] = content;
          count++;
        } catch {}
      }
    }
  }

  walk(dir);
  return files;
}

async function main() {
  const tier = flags.tier || 'free';
  console.log(`scanning ${targetDir}...`);

  const files = walkDir(targetDir, targetDir);
  const fileCount = Object.keys(files).length;

  if (fileCount === 0) {
    console.log('no scannable files found.');
    process.exit(0);
  }

  console.log(`found ${fileCount} files`);

  const endpoint = `${SUPERSHIP_URL}/scan/${tier}`;
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ files }),
    signal: AbortSignal.timeout(30000),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    console.error(`scan failed: ${res.status} ${err.error || ''}`);
    process.exit(1);
  }

  const result = await res.json();

  if (flags.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    const g = result.grade;
    const gradeColor = g === 'A' ? '\x1b[32m' : g === 'F' ? '\x1b[31m' : '\x1b[33m';
    console.log(`\n  score: ${result.score}/100  grade: ${gradeColor}${g}\x1b[0m`);
    console.log(`  files: ${result.files_scanned}  skipped: ${(result.files_skipped || []).length}`);

    const s = result.summary || {};
    if (s.critical) console.log(`  \x1b[31m${s.critical} critical\x1b[0m`);
    if (s.high) console.log(`  \x1b[33m${s.high} high\x1b[0m`);
    if (s.medium) console.log(`  ${s.medium} medium`);
    if (s.low) console.log(`  ${s.low} low`);

    if (result.findings && result.findings.length > 0) {
      console.log('\n  findings:');
      for (const f of result.findings.slice(0, 20)) {
        const sev = f.severity === 'critical' ? '\x1b[31m' : f.severity === 'high' ? '\x1b[33m' : '';
        console.log(`    ${sev}${f.severity}\x1b[0m  ${f.file}:${f.line}  ${f.message}`);
      }
      if (result.findings.length > 20) {
        console.log(`    ... and ${result.findings.length - 20} more`);
      }
    }

    if (result.envelope) {
      console.log(`\n  input hash: ${result.envelope.input_hash}`);
      console.log(`  language:   ${result.envelope.language}`);
    }

    if (result.message) {
      console.log(`\n  ${result.message}`);
    }
  }

  if (flags.attest && result.envelope) {
    console.log('\n  requesting attestation...');
    try {
      const attestRes = await fetch(`${SUPERSHIP_URL}/attest`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          input_hash: result.envelope.input_hash,
          rule_pack_hash: result.envelope.rule_pack_hash,
          engine_version: result.envelope.engine_version,
          score: result.score,
          grade: result.grade,
          summary: result.summary,
          findings_count: (result.findings || []).length,
        }),
        signal: AbortSignal.timeout(10000),
      });

      if (attestRes.ok) {
        const att = await attestRes.json();
        if (flags.json) {
          console.log(JSON.stringify(att, null, 2));
        } else {
          console.log(`  \x1b[32mattestation signed\x1b[0m`);
          console.log(`  timestamp: ${att.attestation.timestamp}`);
          console.log(`  language:  ${att.attestation.language}`);
          console.log(`  signed:    ${att.attestation.signed}`);
          console.log(`\n  ${att.disclaimer}`);
        }
      } else {
        console.log('  attestation failed:', attestRes.status);
      }
    } catch (e) {
      console.log('  attestation unavailable:', e.message);
    }
  }

  console.log('');
}

main().catch((e) => {
  console.error('error:', e.message);
  process.exit(1);
});
