import { scan } from '../src/scanner.mjs';

const STRIPE_FIXTURE = ['sk', 'live', 'FAKEFAKEFAKEFAKEFAKEFAKE'].join('_');

const vulnCode = {
  'api-keys.js': [
    "const OPENAI_KEY = 'sk-proj-abc123def456ghi789jkl012mno345pqr678';",
    "const ANTHROPIC = 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345678901234567890';",
    "const AWS = 'AKIAIOSFODNN7EXAMPLE';",
    `const STRIPE = '${STRIPE_FIXTURE}';`,
    "const DB = 'postgres://admin:s3cret@prod-db.internal:5432/myapp';",
  ].join('\n'),

  'injection.js': [
    "const express = require('express');",
    "const app = express();",
    "app.get('/user', (req, res) => {",
    "  db.query('SELECT * FROM users WHERE id = ' + req.query.id);",
    "});",
    "app.get('/search', (req, res) => {",
    "  db.query(`SELECT * FROM products WHERE name LIKE '${req.query.q}'`);",
    "});",
    "app.post('/run', (req, res) => {",
    "  eval(req.body.code);",
    "});",
    "const { exec } = require('child_process');",
    "exec(`ls ${req.query.dir}`);",
  ].join('\n'),

  'auth.js': [
    "const express = require('express');",
    "const app = express();",
    "app.get('/api/admin/users', (req, res) => {",
    "  res.json(allUsers);",
    "});",
    "app.post('/api/delete', (req, res) => {",
    "  db.delete(req.body.id);",
    "});",
  ].join('\n'),

  'config.js': [
    "const cors = require('cors');",
    "app.use(cors({ origin: '*' }));",
    "app.use(express.static('src', { dotfiles: 'allow' }));",
    "res.cookie('session', token, { httpOnly: false });",
  ].join('\n'),

  'xss.jsx': [
    "function render(html) {",
    "  return <div dangerouslySetInnerHTML={{ __html: html }} />;",
    "}",
    "document.getElementById('out').innerHTML = userInput;",
    "document.write(data);",
  ].join('\n'),

  '.env': [
    "DATABASE_URL=postgres://root:password@db.prod.internal:5432/app",
    `STRIPE_SECRET_KEY=${STRIPE_FIXTURE}`,
    "OPENAI_API_KEY=sk-proj-ABCDEFGHIJKLMNOPQRST1234567890abcdefghij",
    'JWT_SECRET="mysupersecretjwttoken123"',
  ].join('\n'),

  'supabase-client.js': [
    "import { createClient } from '@supabase/supabase-js';",
    "const service_role = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRlc3QiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjIwMDAwMDAwMDB9.abc123';",
    "const supabase = createClient(url, service_role);",
  ].join('\n'),

  'logging.js': [
    "app.post('/login', (req, res) => {",
    "  console.log(req.body);",
    "  console.log('Password:', req.body.password);",
    "});",
  ].join('\n'),
};

const EXPECTED = [
  { file: 'api-keys.js', id: 'SEC-003', desc: 'OpenAI key' },
  { file: 'api-keys.js', id: 'SEC-005', desc: 'Anthropic key' },
  { file: 'api-keys.js', id: 'SEC-001', desc: 'AWS key' },
  { file: 'api-keys.js', id: 'SEC-006', desc: 'Stripe live key' },
  { file: 'api-keys.js', id: 'SEC-009', desc: 'DB URL with creds' },
  { file: 'injection.js', id: 'INJ-002', desc: 'SQL concat' },
  { file: 'injection.js', id: 'INJ-001', desc: 'SQL template literal' },
  { file: 'injection.js', id: 'INJ-005', desc: 'eval()' },
  { file: 'injection.js', id: 'INJ-007', desc: 'command injection exec' },
  { file: 'xss.jsx', id: 'INJ-003', desc: 'dangerouslySetInnerHTML' },
  { file: 'xss.jsx', id: 'INJ-009', desc: 'innerHTML assignment' },
  { file: 'xss.jsx', id: 'INJ-010', desc: 'document.write' },
  { file: '.env', id: 'SEC-009', desc: 'DB URL in .env' },
  { file: '.env', id: 'SEC-006', desc: 'Stripe key in .env' },
  { file: '.env', id: 'SEC-003', desc: 'OpenAI key in .env' },
  { file: '.env', id: 'SEC-010', desc: 'JWT secret in .env' },
  { file: 'config.js', id: 'CFG-001', desc: 'CORS wildcard' },
  { file: 'supabase-client.js', id: 'SEC-008', desc: 'Supabase service_role' },
  { file: 'logging.js', id: 'LOG-001', desc: 'Logging req.body' },
  { file: 'auth.js', id: 'AUTH-001', desc: 'Unprotected API route' },
];

const result = scan(vulnCode, 'full');
const foundIds = new Set(result.findings.map(f => f.file + ':' + f.id));

let tp = 0, fn = 0, missed = [];
for (const exp of EXPECTED) {
  if (foundIds.has(exp.file + ':' + exp.id)) {
    tp++;
  } else {
    fn++;
    missed.push(exp);
  }
}

const expectedSet = new Set(EXPECTED.map(e => e.file + ':' + e.id));
const fp = result.findings.filter(f => !expectedSet.has(f.file + ':' + f.id));

console.log('=== SUPERSHIP DETECTION BENCHMARK ===');
console.log(`Score: ${result.score}/100 Grade: ${result.grade}`);
console.log(`Total findings: ${result.findings.length}`);
console.log(`\nGround truth: ${EXPECTED.length} expected vulnerabilities`);
console.log(`True Positives:  ${tp}/${EXPECTED.length} (${(tp/EXPECTED.length*100).toFixed(0)}%)`);
console.log(`False Negatives: ${fn}/${EXPECTED.length} (${(fn/EXPECTED.length*100).toFixed(0)}%)`);
console.log(`False Positives: ${fp.length}`);
console.log(`\nMISSED:`);
for (const m of missed) console.log(`  ${m.file}: ${m.id} (${m.desc})`);
console.log(`\nEXTRA (not in ground truth):`);
for (const f of fp) console.log(`  ${f.file}: ${f.id} (${f.message.slice(0,80)})`);
console.log(`\nFINDINGS BY CATEGORY:`);
const byCat = {};
for (const f of result.findings) { byCat[f.category] = (byCat[f.category]||0)+1; }
for (const [k,v] of Object.entries(byCat)) console.log(`  ${k}: ${v}`);
