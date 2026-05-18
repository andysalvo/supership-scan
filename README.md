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

## API

supership also runs as an x402-native API. Pay per scan with USDC on Base. No API keys, no subscriptions.

| Endpoint | Method | Price | Description |
|----------|--------|-------|-------------|
| `/check` | GET | Free | Trust check for any x402 service URL |
| `/scan/free` | POST | Free | Score + grade, all 6 categories |
| `/scan/quick` | POST | $1 | Secrets + config findings |
| `/scan/full` | POST | $5 | All categories + fixes |
| `/scan/deep` | POST | $15 | Full + LLM contextual review |
| `/attest` | POST | $0.01 | Sign and witness a scan result |

API base: `https://supership.crestsystems.ai`

Discovery endpoints: [agent.json](https://supership.crestsystems.ai/.well-known/agent.json) | [llms.txt](https://supership.crestsystems.ai/llms.txt) | [OpenAPI](https://supership.crestsystems.ai/openapi.json)

## Crest x402 Services

supership is part of the Crest Deployment Systems x402 service fleet. All services accept USDC payments on Base mainnet via the x402 protocol.

| Service | What it does | URL |
|---------|-------------|-----|
| **supership** | Predeploy security scanner + attestation | [supership.crestsystems.ai](https://supership.crestsystems.ai) |
| **data** | Crypto market data, token lookups, gas prices | [data.crestsystems.ai](https://data.crestsystems.ai) |
| **audit** | Smart contract audit, code security, wallet risk | [audit.crestsystems.ai](https://audit.crestsystems.ai) |

## Links

- [supership API](https://supership.crestsystems.ai)
- [Documentation](https://github.com/andysalvo/supership-docs)
- [npm: supership-scan](https://www.npmjs.com/package/supership-scan)
- [npm: @crestdeploymentsystems/supership-mcp](https://www.npmjs.com/package/@crestdeploymentsystems/supership-mcp)
- [Crest Deployment Systems](https://crestsystems.ai)

## License

Apache 2.0. See [LICENSE](LICENSE) for details.

Rule engines (`src/rules/`) are Apache 2.0 with a relicense notice. See LICENSE for the full NOTICE.
