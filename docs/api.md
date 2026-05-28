# Local HTTP API

Agent Surface Map ships a dependency-free local HTTP API for editor plugins,
local dashboards, and agent control planes that cannot use stdio MCP directly.
It runs on the developer machine and uses the same scanner, reviewer, schemas,
and policy validation path as the CLI.

Start the API:

```bash
asm api --host 127.0.0.1 --port 8765 --allowed-root "$PWD"
```

By default, local scans are limited to the current working directory. To allow
more roots:

```bash
ASM_API_ALLOWED_ROOTS="$PWD:/tmp/review-work" asm api
```

Use `--no-remote-github` to disable public GitHub scans. Use `--gemma` only when
a Gemma/OpenAI-compatible provider is configured and model review is desired.

## Auth And Limits

By default, the local API has no auth and should stay bound to `127.0.0.1`.
Require API keys by setting `ASM_API_KEYS` before startup:

```bash
ASM_API_KEYS="dev-key-1,dev-key-2" asm api
```

Clients may pass either header:

```http
authorization: Bearer dev-key-1
x-asm-api-key: dev-key-1
```

Health checks do not require auth. All schema, scan, and validation endpoints do
when keys are configured.

Protected endpoints are rate-limited per client IP:

```bash
ASM_API_RATE_LIMIT_PER_MINUTE=60 asm api
asm api --rate-limit-per-minute 120
```

Use `--rate-limit-per-minute 0` only behind another trusted limiter.

## Health

```http
GET /healthz
```

Response:

```json
{
  "ok": true,
  "service": "agent-surface-map"
}
```

## Scan

```http
POST /v1/scan
content-type: application/json

{
  "target": "./examples/demo-agent-stack",
  "allow_gemma": false
}
```

`target` may be a local directory under an allowed root or a simple public
GitHub repository URL such as `https://github.com/org/repo`. GitHub scans use
bounded zip download/extraction and do not execute repository code.

The response is an Agent Surface Map report. See `docs/report-format.md` and
`schemas/report-v1.schema.json`.

## Validate

```http
POST /v1/validate
content-type: application/json

{
  "report": { "...": "scan report" },
  "config": {
    "mcpServers": {
      "filesystem": {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home"]
      }
    }
  },
  "policy": {
    "denied_paths": ["/home"]
  }
}
```

`config` may be a JSON object or a raw config string. `policy` is optional and
uses the same keys as `agent-surface-policy.yml`.

## Schemas

```http
GET /v1/schema/report
GET /v1/schema/policy
GET /v1/schema/validation
GET /v1/schema/drift
```

These endpoints return the same schema artifacts exposed by `asm schema`.

## Boundary

The local API is not a multi-tenant hosted service. Its API-key check and
in-memory rate limiter are enough for local plugins, small internal gateways,
and demos, but public hosted API work still needs durable rate limits,
retention controls, abuse handling, key management, audit logs, and private-repo
data policy before it is treated as production infrastructure.
