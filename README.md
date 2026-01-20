# AIP Go Proxy

The reference implementation of the [Agent Identity Protocol](../../spec/aip-v1alpha1.md) — a policy enforcement proxy for MCP (Model Context Protocol).

**"Sudo for AI Agents"**

## Features

- **Tool allowlist enforcement** — Only permitted tools can be called
- **Argument validation** — Regex patterns for tool parameters
- **Human-in-the-Loop** — Native OS dialogs for sensitive operations
- **DLP scanning** — Redact secrets from tool responses
- **Audit logging** — Immutable JSONL trail of all decisions
- **Monitor mode** — Test policies without enforcement

## Quick Start

### Install

```bash
# From source
git clone https://github.com/ArangoGutierrez/agent-identity-protocol.git
cd agent-identity-protocol/implementations/go-proxy
make build
./bin/aip --help

# Or with go install (after v1.0 release)
go install github.com/ArangoGutierrez/agent-identity-protocol/implementations/go-proxy/cmd/aip-proxy@latest
```

### Create a Policy

```yaml
# policy.yaml
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: my-policy
spec:
  mode: enforce
  allowed_tools:
    - read_file
    - list_directory
  tool_rules:
    - tool: write_file
      action: ask    # Require approval
    - tool: exec_command
      action: block  # Never allow
```

### Run

```bash
# Wrap any MCP server with policy enforcement
./bin/aip --policy policy.yaml --target "npx @modelcontextprotocol/server-filesystem /tmp"

# Verbose mode for debugging
./bin/aip --policy policy.yaml --target "python mcp_server.py" --verbose
```

### Integrate with Cursor

```bash
# Generate Cursor config
./bin/aip --generate-cursor-config \
  --policy /path/to/policy.yaml \
  --target "your-mcp-server-command"
```

Add the output to `~/.cursor/mcp.json`.

## CLI Reference

| Flag | Description | Default |
|------|-------------|---------|
| `--target` | MCP server command to wrap (required) | — |
| `--policy` | Path to policy YAML file | `agent.yaml` |
| `--audit` | Path to audit log file | `aip-audit.jsonl` |
| `--verbose` | Enable detailed logging to stderr | `false` |
| `--generate-cursor-config` | Output Cursor IDE config JSON | `false` |

## Documentation

| Document | Description |
|----------|-------------|
| [Quickstart](docs/quickstart.md) | Step-by-step tutorial with echo server |
| [Architecture](docs/architecture.md) | Deep dive into proxy design |
| [Integration Guide](docs/integration-guide.md) | Cursor, VS Code, Claude Desktop setup |
| [Policy Reference](../../docs/policy-reference.md) | Complete YAML schema |
| [AIP Specification](../../spec/aip-v1alpha1.md) | Formal protocol spec |

## Examples

See [`examples/`](examples/) for ready-to-use policies:

- `agent.yaml` — Full-featured example with all options
- `read-only.yaml` — Block all write operations
- `gpu-policy.yaml` — GPU/ML workload controls
- `gemini-jack-defense.yaml` — Prompt injection mitigation
- `monitor-mode.yaml` — Dry-run testing

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  MCP Client │────▶│    AIP Proxy     │────▶│   MCP Server    │
│   (Agent)   │◀────│  Policy Engine   │◀────│  (Subprocess)   │
└─────────────┘     └──────────────────┘     └─────────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │ Audit Log   │
                    │ (JSONL)     │
                    └─────────────┘
```

The proxy:
1. Intercepts JSON-RPC messages on stdin/stdout
2. Evaluates `tools/call` requests against the policy
3. Blocks, allows, or prompts for approval
4. Logs all decisions to the audit file
5. Applies DLP redaction to responses

## Development

```bash
# Build
make build

# Test
make test

# Lint
make lint

# All checks
make all
```

## License

Apache 2.0 — See [LICENSE](../../LICENSE)
