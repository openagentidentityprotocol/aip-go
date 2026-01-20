# AIP Architecture

This document provides a deep dive into the Agent Identity Protocol's architecture, design decisions, and security model.

## Table of Contents

- [Overview](#overview)
- [Core Components](#core-components)
- [Data Flow](#data-flow)
- [Security Model](#security-model)
- [Policy Engine](#policy-engine)
- [Human-in-the-Loop](#human-in-the-loop)
- [DLP (Data Loss Prevention)](#dlp-data-loss-prevention)
- [Audit System](#audit-system)
- [Design Decisions](#design-decisions)

## Overview

AIP is a **Man-in-the-Middle (MitM) security proxy** for the Model Context Protocol (MCP). It intercepts tool calls between AI agents and tool servers, enforcing security policies before allowing requests to proceed.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          TRUST BOUNDARY                                      │
│  ┌──────────┐    ┌─────────────────┐    ┌──────────────┐    ┌────────────┐ │
│  │          │    │                 │    │              │    │            │ │
│  │  Agent   │───▶│   AIP Proxy     │───▶│ Policy Check │───▶│ Real Tool  │ │
│  │  (LLM)   │    │   (Sidecar)     │    │ (agent.yaml) │    │ (GitHub)   │ │
│  │          │◀───│                 │◀───│              │◀───│            │ │
│  └──────────┘    └─────────────────┘    └──────────────┘    └────────────┘ │
│                         │                      │                            │
│                         ▼                      ▼                            │
│                  ┌─────────────┐       ┌──────────────┐                    │
│                  │ Audit Log   │       │     DLP      │                    │
│                  │ (immutable) │       │   Scanner    │                    │
│                  └─────────────┘       └──────────────┘                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Proxy Core (`cmd/aip-proxy/main.go`)

The main entry point that:
- Parses CLI flags and loads configuration
- Spawns the target MCP server as a subprocess
- Creates bidirectional pipes for stdin/stdout interception
- Manages graceful shutdown via signal handling

**Key principle**: stdout is sacred. Only JSON-RPC messages go to stdout. All operational logs go to stderr, audit logs go to a file.

### 2. Policy Engine (`pkg/policy/engine.go`)

Loads and evaluates YAML policy files. Supports:

| Feature | Description |
|---------|-------------|
| `allowed_tools` | Allowlist of permitted tool names |
| `tool_rules` | Fine-grained rules per tool with actions |
| `action: allow` | Permit the tool call |
| `action: block` | Deny unconditionally |
| `action: ask` | Prompt user for approval |
| `allow_args` | Regex validation of tool arguments |
| `rate_limit` | Per-tool rate limiting |
| `mode: monitor` | Log violations but don't block |

### 3. Protocol Types (`pkg/protocol/types.go`)

JSON-RPC 2.0 message types for MCP communication:

```go
type Request struct {
    JSONRPC string          `json:"jsonrpc"`
    Method  string          `json:"method"`
    Params  json.RawMessage `json:"params,omitempty"`
    ID      json.RawMessage `json:"id,omitempty"`
}
```

### 4. DLP Scanner (`pkg/dlp/scanner.go`)

Scans tool responses for sensitive data using configurable regex patterns. Redacts matches before forwarding to the agent.

### 5. Audit Logger (`pkg/audit/logger.go`)

Writes structured JSONL logs for every policy decision. Supports both enforce and monitor mode logging.

### 6. UI Prompter (`pkg/ui/prompt.go`)

Native OS dialogs for Human-in-the-Loop approval. Uses `osascript` on macOS, `zenity`/`kdialog` on Linux.

## Data Flow

### Upstream Flow (Client → Server)

```
1. Agent sends JSON-RPC request to stdin
2. Proxy reads and parses the message
3. If method == "tools/call":
   a. Extract tool name and arguments
   b. Evaluate policy: engine.IsAllowed(tool, args)
   c. If action == "ask": prompt user via OS dialog
   d. Log decision to audit file
   e. If BLOCKED: return JSON-RPC error to stdout
   f. If ALLOWED: forward to subprocess stdin
4. For other methods: passthrough to subprocess
```

### Downstream Flow (Server → Client)

```
1. Subprocess writes JSON-RPC response to stdout
2. Proxy reads the response
3. If DLP is enabled:
   a. Parse response to find content fields
   b. Scan for sensitive data patterns
   c. Replace matches with [REDACTED:<RuleName>]
   d. Log redaction events
4. Forward (potentially modified) response to stdout
```

## Security Model

### Threat Model

AIP defends against:

| Threat | Mitigation |
|--------|------------|
| **Indirect Prompt Injection** | Policy blocks unexpected tool calls |
| **Privilege Escalation** | Explicit allowlist; no implicit permissions |
| **Data Exfiltration** | DLP scans responses for secrets/PII |
| **Consent Fatigue** | Fine-grained policies replace broad OAuth scopes |
| **Shadow AI** | Audit trail captures all tool usage |

### Security Properties

1. **Fail-Closed**: Unknown tools are denied by default
2. **Zero-Trust**: Every `tools/call` is checked; no implicit permissions
3. **Least Privilege**: Agents start with zero capabilities
4. **Defense in Depth**: Multiple layers (policy, DLP, audit, human approval)
5. **Immutable Audit**: Log file is append-only from agent's perspective

### Trust Boundaries

```
┌─────────────────────────────────────────────┐
│ UNTRUSTED ZONE (Agent)                      │
│  - LLM with unpredictable behavior          │
│  - Potentially manipulated by prompt inject │
└─────────────────────────────────────────────┘
                     │
                     ▼ stdin
┌─────────────────────────────────────────────┐
│ TRUST BOUNDARY (AIP Proxy)                  │
│  - Policy enforcement                       │
│  - Audit logging                            │
│  - Human approval gates                     │
└─────────────────────────────────────────────┘
                     │
                     ▼ subprocess stdin
┌─────────────────────────────────────────────┐
│ TRUSTED ZONE (Tool Server)                  │
│  - Executes only policy-approved calls      │
│  - Responses scanned by DLP                 │
└─────────────────────────────────────────────┘
```

## Policy Engine

### Evaluation Order

```
1. Check tool_rules for explicit block → DENY
2. Check tool_rules for action=ask → PROMPT USER
3. Check allowed_tools allowlist → DENY if not present
4. Check allow_args regex patterns → DENY if validation fails
5. Check rate_limit → DENY if exceeded
6. ALLOW
```

### Monitor Mode

When `spec.mode: monitor`:
- Policy is evaluated normally
- Violations are logged with `decision: ALLOW_MONITOR`
- Requests are forwarded anyway (dry-run)
- Use for testing policies before enforcement

### Rate Limiting

```yaml
tool_rules:
  - tool: list_gpus
    rate_limit: "10/minute"
```

Rate limits are evaluated using a token bucket algorithm per tool name.

## Human-in-the-Loop

For sensitive operations, AIP can prompt the user via native OS dialogs:

```yaml
tool_rules:
  - tool: run_training
    action: ask
```

### Implementation

| OS | Method |
|----|--------|
| macOS | `osascript` with AppleScript dialog |
| Linux | `zenity` or `kdialog` |
| Headless | Auto-deny (fail-closed) |

### Timeout Behavior

- Default timeout: 60 seconds
- If user doesn't respond: **auto-deny** (fail-closed)
- If user clicks "Deny": request blocked
- If user clicks "Allow": request forwarded

## DLP (Data Loss Prevention)

### Response Scanning

DLP inspects tool responses for sensitive patterns:

```yaml
dlp:
  patterns:
    - name: "AWS Key"
      regex: "(AKIA|ASIA)[A-Z0-9]{16}"
    - name: "SSN"
      regex: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
```

### Redaction Format

Matched content is replaced with: `[REDACTED:<RuleName>]`

Example:
```
Input:  "API Key: AKIAIOSFODNN7EXAMPLE"
Output: "API Key: [REDACTED:AWS Key]"
```

### Content Parsing

DLP scans the `text` fields within MCP content arrays:

```json
{
  "result": {
    "content": [
      {"type": "text", "text": "sensitive data here"}
    ]
  }
}
```

If response doesn't match expected structure, a full-string scan is performed.

## Audit System

### Log Format

JSONL (JSON Lines) format, one record per line:

```json
{
  "timestamp": "2026-01-20T10:30:00Z",
  "event_type": "TOOL_CALL",
  "tool": "github_create_review",
  "args": {"repo": "mycompany/backend", "event": "APPROVE"},
  "decision": "ALLOW",
  "violation": false,
  "policy_mode": "enforce"
}
```

### Event Types

| Event | Description |
|-------|-------------|
| `TOOL_CALL` | Tool call evaluation (allow/block) |
| `DLP_TRIGGERED` | Sensitive data redacted |
| `USER_PROMPT` | Human-in-the-loop prompt result |
| `RATE_LIMITED` | Rate limit exceeded |

### Querying Logs

```bash
# All violations
cat aip-audit.jsonl | jq 'select(.violation == true)'

# Tool usage summary
cat aip-audit.jsonl | jq -r '.tool' | sort | uniq -c

# DLP events
cat aip-audit.jsonl | jq 'select(.event_type == "DLP_TRIGGERED")'
```

## Design Decisions

### Why stdin/stdout Proxy?

MCP uses JSON-RPC over stdio. The proxy pattern allows:
- **Transparency**: No changes to client or server
- **Composability**: Chain multiple proxies
- **Debuggability**: All traffic flows through one point

### Why YAML Policies?

- Human-readable and editable
- GitOps-friendly (version control, code review)
- Established pattern (Kubernetes, CloudFormation)
- Extensible schema

### Why Not OAuth?

OAuth scopes are:
- Coarse-grained ("repo access" vs "read pull requests")
- Static (granted at install time)
- User-facing (consent fatigue)

AIP policies are:
- Fine-grained (per-tool, per-argument)
- Dynamic (can change without re-auth)
- Developer-controlled (in config files)

### Why Local Binary, Not Service?

- **Zero network latency**: Proxy runs in same process chain
- **No shared state**: Each agent gets isolated policy
- **Offline operation**: Works without external dependencies
- **Simpler deployment**: Single binary, no database
