/**
 * supabase.mjs — Detects Supabase-specific security misconfigurations.
 *
 * Export: scanSupabase(files) → Finding[]
 * files: object of { filepath: content }
 */

const SQL_FILE = /\.(sql)$/i;
const MIGRATION_FILE = /(?:migration|migrations|supabase\/migrations|schema|seed)\//i;
const JS_TS_FILE = /\.[cm]?[jt]sx?$/i;

const RULES = [
  {
    id: 'SB-001',
    rule: 'rls_not_enabled',
    severity: 'critical',
    message: 'CREATE TABLE detected without ENABLE ROW LEVEL SECURITY — table is publicly accessible',
    fix: 'Add "ALTER TABLE <table_name> ENABLE ROW LEVEL SECURITY;" after the CREATE TABLE statement.',
  },
  {
    id: 'SB-002',
    rule: 'permissive_rls_policy',
    severity: 'high',
    pattern: /USING\s*\(\s*true\s*\)/i,
    message: 'RLS policy uses USING (true) — grants access to all rows for all users',
    fix: 'Restrict the policy: use USING (auth.uid() = user_id) or another user-specific condition.',
  },
  {
    id: 'SB-003',
    rule: 'rls_role_without_uid',
    severity: 'medium',
    // Policy that checks role but not auth.uid()
    message: 'RLS policy checks role but not auth.uid() — may allow cross-user data access',
    fix: "Add auth.uid() check to the policy: USING (auth.uid() = user_id AND auth.role() = 'authenticated')",
  },
  {
    id: 'SB-004',
    rule: 'service_role_in_client',
    severity: 'critical',
    // createClient called with something that looks like a service_role key variable
    pattern: /createClient\s*\([^)]*service[_\-]?role[^)]*\)/i,
    message: 'createClient() called with service_role key — bypasses RLS, must only be used server-side',
    fix: 'Never use the service_role key in client-side code. Use the anon key for client, service_role only in trusted server environments.',
  },
  {
    id: 'SB-005',
    rule: 'public_storage_bucket',
    severity: 'medium',
    pattern: /createBucket\s*\([^)]*public\s*:\s*true/i,
    message: 'Supabase storage bucket created with public: true — files are publicly accessible',
    fix: 'Only set public: true for intentionally public assets. Use signed URLs for sensitive files.',
  },
];

/**
 * For SQL files: find all CREATE TABLE statements and check that each has
 * a corresponding ENABLE ROW LEVEL SECURITY statement in the same file.
 */
function checkRLS(filepath, content, findings) {
  // Extract table names from CREATE TABLE
  const createTableRx = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:"?(\w+)"?\.)?"?(\w+)"?/gi;
  const enableRlsRx = /ALTER\s+TABLE\s+(?:"?(\w+)"?\.)?"?(\w+)"?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi;

  const tables = new Set();
  const rlsEnabled = new Set();

  let match;
  const lines = content.split('\n');

  while ((match = createTableRx.exec(content)) !== null) {
    const tableName = (match[2] || match[1]).toLowerCase();
    // Skip system/pg tables
    if (!tableName.startsWith('pg_') && !tableName.startsWith('_')) {
      tables.add(tableName);
    }
  }

  while ((match = enableRlsRx.exec(content)) !== null) {
    rlsEnabled.add((match[2] || match[1]).toLowerCase());
  }

  for (const table of tables) {
    if (!rlsEnabled.has(table)) {
      // Find the line of the CREATE TABLE statement
      let lineNum = 1;
      for (let i = 0; i < lines.length; i++) {
        if (new RegExp(`CREATE\\s+TABLE.*\\b${table}\\b`, 'i').test(lines[i])) {
          lineNum = i + 1;
          break;
        }
      }
      findings.push({
        id: 'SB-001',
        severity: 'critical',
        category: 'supabase',
        file: filepath,
        line: lineNum,
        rule: 'rls_not_enabled',
        message: `${RULES[0].message}: table "${table}"`,
        fix: RULES[0].fix.replace('<table_name>', table),
      });
    }
  }
}

/**
 * Check for RLS policies that use role() but not auth.uid()
 */
function checkRoleWithoutUid(filepath, content, findings) {
  const lines = content.split('\n');
  // Look for USING or WITH CHECK clauses that mention role() but not auth.uid()
  const policyBlockRx = /CREATE\s+POLICY/i;
  let inPolicy = false;
  let policyStart = 0;
  let policyContent = '';

  for (let i = 0; i < lines.length; i++) {
    if (policyBlockRx.test(lines[i])) {
      inPolicy = true;
      policyStart = i + 1;
      policyContent = lines[i];
    } else if (inPolicy) {
      policyContent += '\n' + lines[i];
      // End of policy block (semicolon)
      if (lines[i].includes(';')) {
        if (
          /auth\.role\(\)/i.test(policyContent) &&
          !(/auth\.uid\(\)/i.test(policyContent))
        ) {
          findings.push({
            id: 'SB-003',
            severity: 'medium',
            category: 'supabase',
            file: filepath,
            line: policyStart,
            rule: 'rls_role_without_uid',
            message: RULES[2].message,
            fix: RULES[2].fix,
          });
        }
        inPolicy = false;
        policyContent = '';
      }
    }
  }
}

/**
 * scanSupabase(files) → Finding[]
 * @param {Record<string, string>} files
 * @returns {Array<object>}
 */
export function scanSupabase(files) {
  const findings = [];

  for (const [filepath, content] of Object.entries(files)) {
    const isSqlFile = SQL_FILE.test(filepath);
    const isMigration = isSqlFile && MIGRATION_FILE.test(filepath);
    const isJsTs = JS_TS_FILE.test(filepath);

    if (isSqlFile || isMigration) {
      // SB-001: CREATE TABLE without ENABLE ROW LEVEL SECURITY
      checkRLS(filepath, content, findings);

      // SB-002: USING (true) in RLS policies
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (RULES[1].pattern.test(lines[i])) {
          findings.push({
            id: 'SB-002',
            severity: 'high',
            category: 'supabase',
            file: filepath,
            line: i + 1,
            rule: 'permissive_rls_policy',
            message: RULES[1].message,
            fix: RULES[1].fix,
          });
          break;
        }
      }

      // SB-003: role() without auth.uid()
      checkRoleWithoutUid(filepath, content, findings);
    }

    if (isJsTs) {
      const lines = content.split('\n');

      // SB-004: createClient with service_role
      for (let i = 0; i < lines.length; i++) {
        if (RULES[3].pattern.test(lines[i])) {
          findings.push({
            id: 'SB-004',
            severity: 'critical',
            category: 'supabase',
            file: filepath,
            line: i + 1,
            rule: 'service_role_in_client',
            message: RULES[3].message,
            fix: RULES[3].fix,
          });
          break;
        }
      }

      // SB-005: public storage bucket
      for (let i = 0; i < lines.length; i++) {
        if (RULES[4].pattern.test(lines[i])) {
          findings.push({
            id: 'SB-005',
            severity: 'medium',
            category: 'supabase',
            file: filepath,
            line: i + 1,
            rule: 'public_storage_bucket',
            message: RULES[4].message,
            fix: RULES[4].fix,
          });
          break;
        }
      }
    }
  }

  return findings;
}
