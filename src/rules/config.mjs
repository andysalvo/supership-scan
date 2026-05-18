/**
 * config.mjs — Detects security misconfigurations.
 *
 * Export: scanConfig(files) → Finding[]
 * files: object of { filepath: content }
 */

const RULES = [
  {
    id: 'CFG-001',
    rule: 'cors_wildcard',
    severity: 'high',
    pattern: /origin\s*:\s*['"`]\*['"`]/,
    message: 'CORS configured with wildcard origin (*) — allows requests from any domain',
    fix: 'Restrict CORS to specific allowed origins: origin: [\'https://yourdomain.com\']',
  },
  {
    id: 'CFG-002',
    rule: 'exposed_source_maps',
    severity: 'medium',
    pattern: /productionBrowserSourceMaps\s*:\s*true/,
    message: 'productionBrowserSourceMaps: true — exposes source code to end users in production',
    fix: 'Remove productionBrowserSourceMaps or set it to false in next.config.js.',
  },
  {
    id: 'CFG-003',
    rule: 'insecure_cookie_http_only_false',
    severity: 'high',
    pattern: /httpOnly\s*:\s*false/,
    message: 'Cookie configured with httpOnly: false — accessible to JavaScript, XSS risk',
    fix: 'Set httpOnly: true for all session and auth cookies.',
  },
  {
    id: 'CFG-004',
    rule: 'insecure_cookie_secure_false',
    severity: 'medium',
    pattern: /secure\s*:\s*false/,
    message: 'Cookie configured with secure: false — transmitted over unencrypted HTTP',
    fix: 'Set secure: true to ensure cookies are only sent over HTTPS.',
  },
  {
    id: 'CFG-005',
    rule: 'wildcard_image_domains',
    severity: 'medium',
    // next.config domains: ['*'] or remotePatterns with hostname: '**'
    pattern: /hostname\s*:\s*['"`]\*\*?['"`]/,
    message: 'Next.js image domains configured with wildcard hostname — allows images from any host',
    fix: 'Restrict image domains to specific trusted hostnames.',
  },
  {
    id: 'CFG-006',
    rule: 'disabled_csp',
    severity: 'high',
    // contentSecurityPolicy: false or removing CSP header
    pattern: /contentSecurityPolicy\s*:\s*false/,
    message: 'Content Security Policy disabled — increases XSS attack surface',
    fix: 'Configure a strict Content Security Policy appropriate for your application.',
  },
  {
    id: 'CFG-007',
    rule: 'debug_mode_production',
    severity: 'medium',
    pattern: /debug\s*:\s*(?:true|process\.env\.NODE_ENV\s*!==\s*['"`]production['"`])/,
    message: 'Debug mode may be enabled in production — leaks stack traces and internal details',
    fix: 'Ensure debug mode is disabled in production: debug: process.env.NODE_ENV !== \'production\'',
  },
  {
    id: 'CFG-008',
    rule: 'trust_proxy_unrestricted',
    severity: 'medium',
    // app.set('trust proxy', true) — trusts all proxies
    pattern: /set\s*\(\s*['"`]trust\s+proxy['"`]\s*,\s*true\s*\)/,
    message: "app.set('trust proxy', true) trusts all proxies — IP spoofing risk",
    fix: "Set 'trust proxy' to a specific count or IP range: app.set('trust proxy', 1)",
  },
  {
    id: 'CFG-009',
    rule: 'no_rate_limiting_auth',
    severity: 'high',
    // Auth endpoint defined without rate limit middleware nearby
    // We look for route definitions at /auth /login /signup /forgot-password without rate limit
    pattern: /(?:router|app)\s*\.(?:post|get)\s*\(\s*['"`]\/(?:auth|login|signin|signup|register|forgot-?password|reset-?password)['"`]/i,
    message: 'Auth endpoint detected — verify rate limiting is applied to prevent brute force attacks',
    fix: 'Apply rate limiting middleware (e.g., express-rate-limit) to all authentication endpoints.',
  },
  {
    id: 'CFG-010',
    rule: 'x_powered_by_exposed',
    severity: 'low',
    // Explicitly enabling x-powered-by after disabling
    pattern: /app\.enable\s*\(\s*['"`]x-powered-by['"`]\s*\)/,
    message: 'X-Powered-By header explicitly enabled — reveals server technology to attackers',
    fix: "Call app.disable('x-powered-by') to suppress the header.",
  },
];

/**
 * scanConfig(files) → Finding[]
 * @param {Record<string, string>} files
 * @returns {Array<object>}
 */
export function scanConfig(files) {
  const findings = [];

  for (const [filepath, content] of Object.entries(files)) {
    const lines = content.split('\n');

    for (const rule of RULES) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/^\s*(?:\/\/|\/\*|\*|#)/.test(line)) continue;
        if (rule.pattern.test(line)) {
          findings.push({
            id: rule.id,
            severity: rule.severity,
            category: 'config',
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
