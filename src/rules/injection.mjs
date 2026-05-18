/**
 * injection.mjs — Detects code injection vulnerabilities.
 *
 * Export: scanInjection(files) → Finding[]
 * files: object of { filepath: content }
 */

const RULES = [
  {
    id: 'INJ-001',
    rule: 'sql_interpolation',
    severity: 'critical',
    // Template literal passed to query/execute/db functions containing ${}
    pattern: /(?:query|execute|db\.run|db\.all|db\.get|pool\.query|connection\.query|client\.query)\s*\(\s*`[^`]*\$\{/,
    message: 'SQL query built with template literal string interpolation — SQL injection risk',
    fix: 'Use parameterized queries with placeholders (?, $1, etc.) instead of string interpolation.',
  },
  {
    id: 'INJ-002',
    rule: 'sql_concatenation',
    severity: 'critical',
    // String concatenation passed to query functions
    pattern: /(?:query|execute|db\.run|db\.all|db\.get|pool\.query|connection\.query|client\.query)\s*\(\s*["'][^"']*["']\s*\+/,
    message: 'SQL query built with string concatenation — SQL injection risk',
    fix: 'Use parameterized queries with placeholders instead of string concatenation.',
  },
  {
    id: 'INJ-003',
    rule: 'dangerous_inner_html',
    severity: 'high',
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{/,
    message: 'dangerouslySetInnerHTML usage detected — potential XSS vulnerability',
    fix: 'Sanitize HTML with DOMPurify before passing to dangerouslySetInnerHTML, or restructure to avoid it.',
  },
  {
    id: 'INJ-004',
    rule: 'vue_v_html',
    severity: 'high',
    pattern: /v-html\s*=/,
    message: 'Vue v-html directive detected — potential XSS vulnerability',
    fix: 'Sanitize content with DOMPurify before using v-html, or use v-text for plain text.',
  },
  {
    id: 'INJ-005',
    rule: 'eval_usage',
    severity: 'critical',
    // eval() but not variable named eval or commented out
    pattern: /(?<![.\w])eval\s*\(/,
    message: 'eval() detected — arbitrary code execution risk',
    fix: 'Replace eval() with safer alternatives: JSON.parse for data, or restructure the logic to avoid dynamic evaluation.',
  },
  {
    id: 'INJ-006',
    rule: 'new_function',
    severity: 'critical',
    pattern: /new\s+Function\s*\(/,
    message: 'new Function() detected — equivalent to eval(), arbitrary code execution risk',
    fix: 'Avoid new Function(). Restructure to use static function definitions.',
  },
  {
    id: 'INJ-007',
    rule: 'command_injection_exec',
    severity: 'critical',
    // exec/execSync/spawn with template literal or concatenation containing variable
    pattern: /(?:exec|execSync|spawn|spawnSync)\s*\(\s*`[^`]*\$\{/,
    message: 'Shell command built with string interpolation — command injection risk',
    fix: 'Use execFile() with argument arrays instead of exec() with interpolated strings. Validate and sanitize all inputs.',
  },
  {
    id: 'INJ-008',
    rule: 'command_injection_concat',
    severity: 'critical',
    pattern: /(?:exec|execSync|spawn|spawnSync)\s*\(\s*["'][^"']*["']\s*\+/,
    message: 'Shell command built with string concatenation — command injection risk',
    fix: 'Use execFile() with argument arrays instead of exec() with concatenated strings.',
  },
  {
    id: 'INJ-009',
    rule: 'inner_html_assignment',
    severity: 'high',
    // el.innerHTML = something (assignment, not comparison)
    pattern: /\.innerHTML\s*=[^=]/,
    message: 'Direct innerHTML assignment detected — potential XSS vulnerability',
    fix: 'Use textContent for text, or sanitize with DOMPurify before assigning to innerHTML.',
  },
  {
    id: 'INJ-010',
    rule: 'document_write',
    severity: 'high',
    pattern: /document\.write\s*\(/,
    message: 'document.write() detected — XSS risk when used with user input',
    fix: 'Replace document.write() with DOM manipulation methods (createElement, appendChild, etc.).',
  },
];

/**
 * scanInjection(files) → Finding[]
 * @param {Record<string, string>} files
 * @returns {Array<object>}
 */
export function scanInjection(files) {
  const findings = [];

  for (const [filepath, content] of Object.entries(files)) {
    const lines = content.split('\n');

    for (const rule of RULES) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // Skip comment-only lines
        if (/^\s*(?:\/\/|\/\*|\*|#)/.test(line)) continue;
        if (rule.pattern.test(line)) {
          findings.push({
            id: rule.id,
            severity: rule.severity,
            category: 'injection',
            file: filepath,
            line: i + 1,
            rule: rule.rule,
            message: rule.message,
            fix: rule.fix,
          });
          // One finding per rule per file
          break;
        }
      }
    }
  }

  return findings;
}
