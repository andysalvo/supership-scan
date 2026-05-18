/**
 * logging.mjs — Detects dangerous logging patterns that leak sensitive data.
 *
 * Export: scanLogging(files) → Finding[]
 * files: object of { filepath: content }
 */

const RULES = [
  {
    id: 'LOG-001',
    rule: 'log_request_body',
    severity: 'high',
    pattern: /console\.(?:log|info|debug|warn|error)\s*\([^)]*req\.body/,
    message: 'console.log(req.body) — logs entire request body including credentials and PII',
    fix: 'Log only specific safe fields: console.log({ method: req.method, path: req.path }) instead of req.body.',
  },
  {
    id: 'LOG-002',
    rule: 'log_sensitive_variable',
    severity: 'high',
    // Logging variables named password, secret, token, key, credential
    pattern: /console\.(?:log|info|debug|warn|error)\s*\([^)]*\b(?:password|passwd|secret|private[_\-]?key|api[_\-]?key|auth[_\-]?token|access[_\-]?token|credential)\b/i,
    message: 'Logging a variable with a sensitive name (password/secret/token/key)',
    fix: 'Never log credentials or secrets. Redact or omit sensitive fields before logging.',
  },
  {
    id: 'LOG-003',
    rule: 'env_file_in_public_dir',
    severity: 'critical',
    // Detected by filepath, not content — .env file in a public-serving directory
    // Matches: public/.env, public/.env.local, dist/.env.production, etc.
    pathPattern: /(?:^|\/)(public|static|dist|build|out|\.next(?:\/static)?)\//i,
    envFilePattern: /\.env[^/]*$/i,
    message: '.env file found in a public-serving directory — credentials will be served to any client',
    fix: 'Move the .env file to the project root. It must never be inside public/, static/, dist/, or build/ directories.',
  },
  {
    id: 'LOG-004',
    rule: 'error_stack_in_response',
    severity: 'high',
    // Sending error.stack in a response
    pattern: /res\.(?:json|send|status\([^)]+\)\.json|status\([^)]+\)\.send)\s*\([^)]*(?:err(?:or)?\.stack|stack\s*:\s*err(?:or)?\.stack|stack\s*:\s*e\.stack)/,
    message: 'Error stack trace included in HTTP response — leaks internal implementation details',
    fix: 'Log errors server-side and return a generic error message to clients. Never expose stack traces in responses.',
  },
  {
    id: 'LOG-005',
    rule: 'internal_error_in_response',
    severity: 'medium',
    // res.json({ error: err.message }) or similar — may expose internal details
    pattern: /res\.(?:json|send)\s*\(\s*\{[^}]*(?:message|error)\s*:\s*(?:err(?:or)?|e)\.message/,
    message: 'Internal error message sent directly to client — may expose implementation details',
    fix: 'Log the full error server-side and return a generic user-facing message: res.json({ error: \'Something went wrong\' })',
  },
  {
    id: 'LOG-006',
    rule: 'log_authorization_header',
    severity: 'high',
    pattern: /console\.(?:log|info|debug|warn|error)\s*\([^)]*(?:req\.headers(?:\[['"]authorization['"]|\s*\.\s*authorization)|authorization\s*:\s*req\.headers)/i,
    message: 'Logging authorization header — exposes Bearer tokens and API keys',
    fix: 'Never log authorization headers. If you need to debug auth, log only a hash or redacted version.',
  },
  {
    id: 'LOG-007',
    rule: 'console_log_in_production_code',
    severity: 'low',
    // Flag console.log (not warn/error) in non-test files as a low severity reminder
    pattern: /console\.log\s*\(/,
    message: 'console.log() in production code — may leak data and creates noise',
    fix: 'Use a structured logger (pino, winston) that respects log levels and can be disabled in production.',
  },
];

/**
 * scanLogging(files) → Finding[]
 * @param {Record<string, string>} files
 * @returns {Array<object>}
 */
export function scanLogging(files) {
  const findings = [];

  for (const [filepath, content] of Object.entries(files)) {
    // LOG-003: path-based check for .env in public dirs
    const envInPublic = RULES.find((r) => r.pathPattern);
    if (envInPublic && envInPublic.pathPattern.test(filepath) && envInPublic.envFilePattern.test(filepath)) {
      findings.push({
        id: 'LOG-003',
        severity: 'critical',
        category: 'logging',
        file: filepath,
        line: 1,
        rule: 'env_file_in_public_dir',
        message: envInPublic.message,
        fix: envInPublic.fix,
      });
      // Skip content scanning for env files
      continue;
    }

    const lines = content.split('\n');

    for (const rule of RULES) {
      // Skip path-based rules during content scan
      if (rule.pathPattern) continue;
      // LOG-007 is very noisy — only flag once per file
      let foundConsoleLog = false;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/^\s*(?:\/\/|\/\*|\*|#)/.test(line)) continue;

        if (rule.id === 'LOG-007') {
          if (!foundConsoleLog && rule.pattern.test(line)) {
            // Only flag console.log if not already caught by a more specific rule
            const alreadyCaught =
              /console\.(?:log|info|debug|warn|error)\s*\([^)]*req\.body/.test(line) ||
              /console\.(?:log|info|debug|warn|error)\s*\([^)]*\b(?:password|passwd|secret|private[_\-]?key|api[_\-]?key|auth[_\-]?token|access[_\-]?token|credential)\b/i.test(line) ||
              /console\.(?:log|info|debug|warn|error)\s*\([^)]*(?:req\.headers(?:\[['"]authorization['"]|\s*\.\s*authorization)|authorization\s*:\s*req\.headers)/i.test(line);

            if (!alreadyCaught) {
              foundConsoleLog = true;
              findings.push({
                id: rule.id,
                severity: rule.severity,
                category: 'logging',
                file: filepath,
                line: i + 1,
                rule: rule.rule,
                message: rule.message,
                fix: rule.fix,
              });
            }
          }
        } else if (rule.pattern.test(line)) {
          findings.push({
            id: rule.id,
            severity: rule.severity,
            category: 'logging',
            file: filepath,
            line: i + 1,
            rule: rule.rule,
            message: rule.message,
            fix: rule.fix,
          });
          break;
        }
      }
    }
  }

  return findings;
}
