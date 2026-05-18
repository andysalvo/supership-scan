/**
 * secrets.mjs — Detects exposed credentials and secret material in source code.
 *
 * Export: scanSecrets(files) → Finding[]
 * files: Map or object of { filepath: content }
 */

const SKIP_FILES = [
  /\.env\.example$/i,
  /\.env\.sample$/i,
  /\.env\.template$/i,
  /package-lock\.json$/,
  /pnpm-lock\.yaml$/,
  /yarn\.lock$/,
];

const TEST_PATH = /\/(test|tests|__tests__|mock|mocks|fixture|fixtures|spec|specs)\//i;

const RULES = [
  {
    id: 'SEC-001',
    rule: 'aws_access_key',
    severity: 'critical',
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    message: 'AWS access key ID detected',
    fix: 'Remove the key from source and rotate it immediately. Use environment variables or AWS Secrets Manager.',
  },
  {
    id: 'SEC-002',
    rule: 'aws_secret_key',
    severity: 'critical',
    // 40-char base64-ish string that commonly follows aws_secret or AWS_SECRET
    pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?([A-Za-z0-9/+]{40})["']?/i,
    message: 'AWS secret access key detected',
    fix: 'Remove the secret and rotate it. Store in AWS Secrets Manager or as an environment variable.',
  },
  {
    id: 'SEC-003',
    rule: 'openai_key',
    severity: 'critical',
    pattern: /\bsk-proj-[A-Za-z0-9_\-]{20,}/,
    message: 'OpenAI project API key detected (sk-proj-...)',
    fix: 'Revoke the key at platform.openai.com and store it in an environment variable.',
  },
  {
    id: 'SEC-004',
    rule: 'openai_key_legacy',
    severity: 'critical',
    pattern: /\bsk-[A-Za-z0-9]{48}\b/,
    message: 'OpenAI API key detected (sk-...)',
    fix: 'Revoke the key at platform.openai.com and store it in an environment variable.',
  },
  {
    id: 'SEC-005',
    rule: 'anthropic_key',
    severity: 'critical',
    pattern: /\bsk-ant-[A-Za-z0-9_\-]{20,}/,
    message: 'Anthropic API key detected (sk-ant-...)',
    fix: 'Revoke the key at console.anthropic.com and store it in an environment variable.',
  },
  {
    id: 'SEC-006',
    rule: 'stripe_secret_key',
    severity: 'critical',
    pattern: /\bsk_live_[A-Za-z0-9]{24,}/,
    message: 'Stripe live secret key detected',
    fix: 'Revoke the key in the Stripe dashboard immediately. Store as an environment variable.',
  },
  {
    id: 'SEC-007',
    rule: 'stripe_test_key',
    severity: 'medium',
    pattern: /\bsk_test_[A-Za-z0-9]{24,}/,
    message: 'Stripe test secret key detected',
    fix: 'Move to an environment variable. Test keys can still expose business logic if leaked.',
  },
  {
    id: 'SEC-008',
    rule: 'supabase_service_role_jwt',
    severity: 'critical',
    // Supabase service_role JWTs start with "eyJ" and "role":"service_role" when decoded.
    // We detect the pattern of a long JWT assigned to a variable associated with service_role.
    pattern: /service_role[^;\n]*eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}/,
    message: 'Supabase service_role JWT found in client-accessible code',
    fix: 'The service_role key bypasses RLS. Only use it in server-side code and store in environment variables.',
  },
  {
    id: 'SEC-009',
    rule: 'database_url_with_creds',
    severity: 'critical',
    pattern: /(?:postgres|postgresql|mysql|mongodb|redis):\/\/[^:@\s]+:[^@\s]+@[^\s"'`]+/i,
    message: 'Database connection URL with embedded credentials detected',
    fix: 'Remove credentials from the URL. Use environment variables or a secrets manager.',
  },
  {
    id: 'SEC-010',
    rule: 'hardcoded_jwt_secret',
    severity: 'high',
    pattern: /(?:jwt[_\-]?secret|JWT[_\-]?SECRET)\s*[=:]\s*["']([^"']{8,})["']/i,
    message: 'Hardcoded JWT secret detected',
    fix: 'Generate a cryptographically random secret and store it in an environment variable.',
  },
  {
    id: 'SEC-011',
    rule: 'hardcoded_password',
    severity: 'high',
    pattern: /(?:password|passwd|PASSWORD)\s*[=:]\s*["']([^"']{4,})["']/,
    message: 'Hardcoded password detected',
    fix: 'Remove the password from source code and use environment variables or a secrets manager.',
  },
  {
    id: 'SEC-012',
    rule: 'private_key_block',
    severity: 'critical',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
    message: 'Private key block detected in source code',
    fix: 'Remove the private key from source code immediately. Store in a secrets manager or environment variable.',
  },
  {
    id: 'SEC-013',
    rule: 'google_api_key',
    severity: 'high',
    pattern: /\bAIza[0-9A-Za-z_\-]{35}\b/,
    message: 'Google API key detected (AIza...)',
    fix: 'Restrict the key in Google Cloud Console and move it to an environment variable.',
  },
  {
    id: 'SEC-014',
    rule: 'github_token',
    severity: 'critical',
    pattern: /\b(?:ghp_|github_pat_)[A-Za-z0-9_]{36,}/,
    message: 'GitHub personal access token detected',
    fix: 'Revoke the token at github.com/settings/tokens and store as an environment variable.',
  },
  {
    id: 'SEC-015',
    rule: 'slack_token',
    severity: 'high',
    pattern: /\bxox[bpsa]-[0-9A-Za-z\-]{16,}/,
    message: 'Slack token detected (xox...)',
    fix: 'Revoke the token at api.slack.com and store as an environment variable.',
  },
  {
    id: 'SEC-016',
    rule: 'sendgrid_key',
    severity: 'high',
    pattern: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/,
    message: 'SendGrid API key detected (SG....)',
    fix: 'Revoke the key in SendGrid and store as an environment variable.',
  },
  {
    id: 'SEC-017',
    rule: 'twilio_key',
    severity: 'high',
    pattern: /\bSK[0-9a-f]{32}\b/,
    message: 'Twilio API key SID detected (SK...)',
    fix: 'Revoke the key in the Twilio console and store as an environment variable.',
  },
  {
    id: 'SEC-018',
    rule: 'cdp_api_secret',
    severity: 'critical',
    pattern: /(?:cdp[_\-]?api[_\-]?key[_\-]?secret|CDP_API_KEY_SECRET)\s*[=:]\s*["']([^"']{10,})["']/i,
    message: 'Coinbase CDP API secret detected',
    fix: 'Remove the secret and rotate it in the Coinbase Developer Platform. Store as an environment variable.',
  },
  {
    id: 'SEC-019',
    rule: 'generic_api_key',
    severity: 'medium',
    pattern: /\bapi[_\-]?key\s*[=:]\s*["']([A-Za-z0-9_\-]{20,})["']/i,
    message: 'Generic API key assignment detected',
    fix: 'Verify this is not a real secret. If so, move to an environment variable.',
  },
  {
    id: 'SEC-020',
    rule: 'generic_secret',
    severity: 'medium',
    pattern: /\bsecret\s*[=:]\s*["']([A-Za-z0-9_\-!@#$%^&*]{16,})["']/i,
    message: 'Hardcoded secret value detected',
    fix: 'Verify this is not a real secret. If so, move to an environment variable.',
  },
  {
    id: 'SEC-021',
    rule: 'hardcoded_admin_credentials',
    severity: 'critical',
    pattern: /(?:admin[_\-]?password|ADMIN[_\-]?PASSWORD|root[_\-]?password)\s*[=:]\s*["']([^"']{4,})["']/i,
    message: 'Hardcoded admin/root credentials detected',
    fix: 'Remove immediately. Admin credentials in source are a critical security risk.',
  },
  {
    id: 'SEC-022',
    rule: 'bearer_token_hardcoded',
    severity: 'high',
    pattern: /Authorization['":\s]+["']Bearer\s+[A-Za-z0-9_\-\.]{20,}["']/i,
    message: 'Hardcoded Bearer token detected in Authorization header',
    fix: 'Remove the token from source code and inject it at runtime via environment variables.',
  },
  {
    id: 'SEC-023',
    rule: 'heroku_api_key',
    severity: 'high',
    pattern: /heroku[_\-]?api[_\-]?key\s*[=:]\s*["']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["']?/i,
    message: 'Heroku API key detected',
    fix: 'Revoke the key in Heroku account settings and store as an environment variable.',
  },
  {
    id: 'SEC-024',
    rule: 'mailgun_key',
    severity: 'high',
    pattern: /\bkey-[0-9a-f]{32}\b/,
    message: 'Mailgun API key detected',
    fix: 'Revoke the key in Mailgun and store as an environment variable.',
  },
  {
    id: 'SEC-025',
    rule: 'basic_auth_url',
    severity: 'high',
    pattern: /https?:\/\/[^:@\s]+:[^@\s]+@[^\s"'`]+/,
    message: 'URL with embedded Basic Auth credentials detected',
    fix: 'Remove credentials from the URL and pass them via headers or environment variables.',
  },
];

/**
 * scanSecrets(files) → Finding[]
 * @param {Record<string, string>} files - filepath → content map
 * @returns {Array<object>} findings
 */
export function scanSecrets(files) {
  const findings = [];

  for (const [filepath, content] of Object.entries(files)) {
    // Skip lock files and env templates
    if (SKIP_FILES.some((rx) => rx.test(filepath))) continue;

    const isTestFile = TEST_PATH.test(filepath);
    const lines = content.split('\n');

    for (const rule of RULES) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (rule.pattern.test(line)) {
          let severity = rule.severity;
          // Downgrade severity for test/mock/fixture directories
          if (isTestFile && severity !== 'critical') {
            severity = 'low';
          } else if (isTestFile) {
            severity = 'low';
          }

          findings.push({
            id: rule.id,
            severity,
            category: 'secrets',
            file: filepath,
            line: i + 1,
            rule: rule.rule,
            message: rule.message,
            fix: rule.fix,
          });
          // Only report first match per rule per file to avoid noise
          break;
        }
      }
    }
  }

  return findings;
}
