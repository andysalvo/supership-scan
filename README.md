# supership-scan

Predeploy security scanner for the agent economy. Built by [Crest Deployment Systems](https://crestsystems.ai).

Scans your code for 80+ vulnerability patterns across secrets, auth, injection, config, Supabase, and logging. Runs locally. Your code never leaves the machine.

## Install

```bash
npm install -g supership-scan
```

Requires Node.js 18+.

## Usage

### CLI

```bash
supership-scan .
```

Scans the current directory and prints findings.

```bash
supership-scan ./my-project --attest
```

Scans and requests a witnessed attestation ($0.01 USDC on Base). Only the report envelope (hashes and findings) is transmitted. Never source code.

### MCP Server

```bash
supership-mcp
```

Starts an MCP server for AI editors (Claude Code, Cursor, Windsurf). Exposes the scanner as tools that agents can call directly.

## Example Output

```
supership v1.0.0

Scanning 42 files...

Score: 87/100
Grade: B

Findings:
  HIGH   AUTH-003  Missing auth middleware on /api/admin   src/routes/admin.js:14
  MEDIUM CFG-002   CORS wildcard in production             src/server.js:8
  LOW    LOG-001   Error stack in response body            src/middleware/error.js:22

Scan complete. Code never left this machine.
```

## Rule Categories

| Category | Patterns | Examples |
|----------|----------|----------|
| Secrets | 30+ | API keys, credentials, .env exposure, private keys |
| Auth | 12+ | Missing middleware, inverted logic, RLS gaps |
| Injection | 15+ | SQL interpolation, XSS, eval(), command injection |
| Config | 10+ | CORS wildcards, source maps, insecure cookies |
| Supabase | 8+ | RLS disabled, permissive policies, service_role misuse |
| Logging | 6+ | Sensitive data in logs, error stack exposure |

## Scoring

Score starts at 100. Penalties: critical (-25), high (-10), medium (-5), low (-1).

Severity gates override the score:
- Any critical finding = grade **F**
- Any high finding = grade **C** max

| Grade | Score |
|-------|-------|
| A | 90+ |
| B | 75-89 |
| C | 60-74 |
| D | 40-59 |
| F | <40 or any critical |

## Attestations

The scan is free. The attestation costs $0.01.

When you run `--attest`, supership sends a report envelope to the attestation server. The envelope contains hashes and findings only. The server signs it, anchors the hash to the chain, and returns a witnessed attestation.

The attestation proves a specific scan occurred at a specific time with specific results. It does not certify that code is secure.

**What's transmitted:** input hash, rule pack hash, engine version, findings, score, grade.

**What's never transmitted:** source code, file contents, environment variables.

## Benchmark

```bash
npm test
```

Runs 20 deliberately vulnerable fixtures against the scanner. Expected: 90% true positive rate, 0 harmful false positives.

## Privacy

- Scanning is entirely local. No network calls during a scan.
- Attestation transmits hashes and findings only. Never source code.
- No telemetry. No analytics. No tracking.

## Links

- [Documentation](https://supership.crestsystems.ai/docs)
- [Crest Deployment Systems](https://crestsystems.ai)

## License

Apache 2.0. See [LICENSE](LICENSE) for details.

Rule engines (`src/rules/`) are Apache 2.0 with a relicense notice. See LICENSE for the full NOTICE.
