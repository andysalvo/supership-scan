import { createHash } from 'crypto';
import { scanSecrets } from './rules/secrets.mjs';
import { scanAuth } from './rules/auth.mjs';
import { scanInjection } from './rules/injection.mjs';
import { scanConfig } from './rules/config.mjs';
import { scanSupabase } from './rules/supabase.mjs';
import { scanLogging } from './rules/logging.mjs';

const ENGINE_VERSION = '1.1.0';
const MAX_LINE_LENGTH = 1000;
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const PENALTIES = { critical: 25, high: 10, medium: 5, low: 1 };

function isBinary(content) {
  for (let i = 0; i < Math.min(content.length, 8192); i++) {
    if (content.charCodeAt(i) === 0) return true;
  }
  return false;
}

function normalizePath(p) {
  return p.replace(/\\/g, '/');
}

function canonicalInputHash(files) {
  const entries = Object.keys(files)
    .map((p) => normalizePath(p))
    .sort()
    .map((p) => {
      const raw = files[Object.keys(files).find((k) => normalizePath(k) === p)];
      const h = createHash('sha256').update(raw).digest('hex');
      return `${p}:${h}`;
    });
  return 'sha256:' + createHash('sha256').update(entries.join('\n')).digest('hex');
}

function preprocessFiles(files) {
  const processed = {};
  const skipped = [];

  const sortedPaths = Object.keys(files).sort((a, b) => normalizePath(a).localeCompare(normalizePath(b)));

  for (const path of sortedPaths) {
    const content = files[path];
    if (isBinary(content)) {
      skipped.push({ path, reason: 'binary' });
      continue;
    }
    if (content.length > 500_000) {
      skipped.push({ path, reason: 'too-large' });
      continue;
    }
    const truncated = content
      .split('\n')
      .map((line) => (line.length > MAX_LINE_LENGTH ? line.slice(0, MAX_LINE_LENGTH) : line))
      .join('\n');
    processed[path] = truncated;
  }

  return { processed, skipped };
}

const ALL_RUNNERS = [scanSecrets, scanAuth, scanInjection, scanConfig, scanSupabase, scanLogging];
const QUICK_RUNNERS = [scanSecrets, scanConfig];

let rulePackHash = null;

function getRulePackHash() {
  if (rulePackHash) return rulePackHash;
  const ruleIds = ALL_RUNNERS
    .flatMap((fn) => {
      try { return fn({}).map ? [] : []; } catch { return []; }
    });
  rulePackHash = 'sha256:' + createHash('sha256').update(ENGINE_VERSION + ':all').digest('hex').slice(0, 16);
  return rulePackHash;
}

function grade(score, summary) {
  if (summary.critical > 0) return 'F';
  if (summary.high > 0 && score >= 75) return 'C';
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

export function scan(files, tier = 'full') {
  const inputHash = canonicalInputHash(files);
  const { processed, skipped } = preprocessFiles(files);

  const runners = tier === 'quick' ? QUICK_RUNNERS : ALL_RUNNERS;
  const findings = runners.flatMap((fn) => fn(processed));

  findings.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4));

  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    if (summary[f.severity] !== undefined) summary[f.severity]++;
  }

  const penalty =
    summary.critical * PENALTIES.critical +
    summary.high * PENALTIES.high +
    summary.medium * PENALTIES.medium +
    summary.low * PENALTIES.low;

  const score = Math.max(0, Math.min(100, 100 - penalty));

  return {
    score,
    grade: grade(score, summary),
    findings,
    summary,
    tier,
    files_scanned: Object.keys(processed).length,
    files_skipped: skipped,
    envelope: {
      input_hash: inputHash,
      rule_pack_hash: getRulePackHash(),
      engine_version: ENGINE_VERSION,
      timestamp: new Date().toISOString(),
      language: 'witnessed-not-certified',
    },
  };
}
