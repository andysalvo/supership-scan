/**
 * auth.mjs — Detects missing or broken authentication in API routes.
 *
 * Export: scanAuth(files) → Finding[]
 * files: object of { filepath: content }
 */

// Files that are likely API route handlers or server middleware
// Note: filepath may or may not start with '/', so use both anchors
const ROUTE_FILE = /(?:^|\/)(?:api|routes?|server|middleware|handler|controllers?|pages\/api)\//i;
// Also match Next.js app router convention: route.ts/js
const ROUTE_FILENAME = /(?:route|handler|controller|middleware|server)\.[cm]?[jt]sx?$/i;

// Auth-related import patterns — if present, we assume auth is handled
const AUTH_IMPORT = /(?:getSession|getServerSession|auth\b|verify(?:Token|Jwt)?|requireAuth|withAuth|middleware|createMiddleware|checkAuth|isAuthenticated|useAuth|clerkClient|currentUser|getAuth|validateToken|jwt\.verify|passport\b)/i;

const RULES = [
  {
    id: 'AUTH-001',
    rule: 'api_route_no_auth',
    severity: 'high',
    message: 'API route handler exports GET/POST without any auth verification in this file',
    fix: 'Add authentication checks (e.g., getServerSession, auth(), or custom middleware) before handling the request.',
  },
  {
    id: 'AUTH-002',
    rule: 'inverted_auth_logic',
    severity: 'critical',
    // Matches patterns like: if (!session) { /* allow/continue/next/return res.json */ }
    pattern: /if\s*\(\s*!(?:session|user|auth|token|isAuthenticated|isLoggedIn)\s*\)\s*\{[^}]*(?:next\(\)|return\s+res\.(?:json|send)|continue|\/\/\s*allow)/i,
    message: 'Inverted auth logic: code continues/allows when session is falsy instead of rejecting',
    fix: 'Invert the condition: reject when !session, allow when session is valid.',
  },
  {
    id: 'AUTH-003',
    rule: 'sensitive_route_no_auth',
    severity: 'critical',
    // Sensitive route path patterns
    sensitivePattern: /['"`]\/api\/(?:admin|users?|billing|payments?|settings?|config|internal|private)[/'"`]/i,
    message: 'Sensitive API route detected without auth middleware import',
    fix: 'Add authentication middleware or session verification to this route.',
  },
];

/**
 * Checks if a file is likely an API route / server file.
 */
function isRouteFile(filepath) {
  return ROUTE_FILE.test(filepath) || ROUTE_FILENAME.test(filepath);
}

/**
 * Checks if file content contains auth-related imports or usage.
 */
function hasAuthImport(content) {
  return AUTH_IMPORT.test(content);
}

/**
 * Detects exported route handler functions (Next.js App Router, Express, etc.)
 */
function findRouteHandlerLines(lines) {
  const handlerLines = [];
  for (let i = 0; i < lines.length; i++) {
    // Next.js App Router: export async function GET/POST/PUT/DELETE/PATCH
    // Express: router.get/post/put/delete or app.get/post
    if (/export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b/.test(lines[i])) {
      handlerLines.push(i + 1);
    }
    if (/(?:router|app)\s*\.(?:get|post|put|delete|patch)\s*\(/.test(lines[i])) {
      handlerLines.push(i + 1);
    }
  }
  return handlerLines;
}

/**
 * scanAuth(files) → Finding[]
 * @param {Record<string, string>} files
 * @returns {Array<object>}
 */
export function scanAuth(files) {
  const findings = [];

  for (const [filepath, content] of Object.entries(files)) {
    if (!isRouteFile(filepath)) continue;

    const lines = content.split('\n');
    const hasAuth = hasAuthImport(content);

    // AUTH-001: route handler without any auth
    if (!hasAuth) {
      const handlerLines = findRouteHandlerLines(lines);
      for (const lineNum of handlerLines) {
        findings.push({
          id: 'AUTH-001',
          severity: 'high',
          category: 'auth',
          file: filepath,
          line: lineNum,
          rule: 'api_route_no_auth',
          message: RULES[0].message,
          fix: RULES[0].fix,
        });
      }
    }

    // AUTH-002: inverted auth logic (scan all route files)
    for (let i = 0; i < lines.length; i++) {
      if (RULES[1].pattern.test(lines[i])) {
        findings.push({
          id: 'AUTH-002',
          severity: 'critical',
          category: 'auth',
          file: filepath,
          line: i + 1,
          rule: 'inverted_auth_logic',
          message: RULES[1].message,
          fix: RULES[1].fix,
        });
      }
    }

    // AUTH-003: sensitive route path without auth imports
    if (!hasAuth) {
      for (let i = 0; i < lines.length; i++) {
        if (RULES[2].sensitivePattern.test(lines[i])) {
          findings.push({
            id: 'AUTH-003',
            severity: 'critical',
            category: 'auth',
            file: filepath,
            line: i + 1,
            rule: 'sensitive_route_no_auth',
            message: RULES[2].message,
            fix: RULES[2].fix,
          });
        }
      }
    }
  }

  return findings;
}
