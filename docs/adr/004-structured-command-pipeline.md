# ADR: Structured command pipeline

Date: 2026-10-08

## Status

Accepted. Supersedes [ADR 001](001-bashlex.md).

## Context

The original MCP contract accepted an arbitrary Bash command string. `bashlex` parsed that string so every command in pipelines, lists, and substitutions could be checked against the policy. This provided broad shell expressiveness but created three problems:

- The MCP schema could not distinguish commands, arguments, and shell operators for the agent.
- Security depended on parsing every supported Bash construct correctly before sending the original text to the remote shell.
- `bashlex` is GPL-3.0-or-later, which constrains distribution of the server.

The server still needs read-only command composition, especially pipelines such as `journalctl | grep` and the `cat | jq | curl` diagnostic flow covered by ADR 003.

## Decision

`ssh_execute` and `ssh_validate_command` accept one `pipeline` array. Every stage contains exactly:

```json
{
  "command": "journalctl",
  "arguments": ["-u", "myservice", "-n", "200", "--no-pager"]
}
```

A single command is a one-stage pipeline. A multi-stage example is:

```json
[
  {
    "command": "journalctl",
    "arguments": ["-u", "myservice", "-n", "200", "--no-pager"]
  },
  {
    "command": "grep",
    "arguments": ["-i", "error"]
  }
]
```

The server validates every stage independently against the existing YAML command policies and command-specific handlers. It then renders every stage with Python's `shlex.join` and inserts the only shell operator itself: ` | ` between stages.

Arguments are literal values. Values such as `$HOME`, `$(whoami)`, `>`, `&&`, `*`, and `error|warning` cannot introduce shell behavior because `shlex.join` quotes them. Shell redirection, command lists, substitutions, expansions, background execution, and agent-controlled pipeline operators have no representation in the contract.

The following structural limits apply before policy validation or SSH access:

- Maximum pipeline stages: 16.
- Maximum arguments per stage: 128.
- Maximum command or argument length: 4,096 characters.
- Maximum rendered pipeline length: 65,536 UTF-8 bytes.
- Empty pipelines, empty command names, non-string arguments, unknown stage fields, and NUL characters are rejected.

The rendered pipeline continues to be executed through the SSH account's configured remote shell, preserving the existing runtime requirement. The reported exit status is therefore the final pipeline stage's status under normal shell pipeline semantics.

`bashlex` and its AST validation are removed. The raw command-string contract is not retained as a compatibility union because accepting both shapes would preserve the parsing ambiguity this decision removes. Clients must migrate to the structured pipeline contract.

## Rejected alternatives

### Keep the raw Bash command string

Rejected because it retains parser dependence, an ambiguous MCP schema, and a larger shell-language attack surface.

### Accept both raw strings and structured pipelines

Rejected because a union schema is harder for agents to use and would require retaining the raw Bash security boundary.

### Execute through a fixed `bash -o pipefail -c` wrapper

Rejected because Bash was not previously required on remote hosts. It would add a deployment prerequisite solely to make earlier pipeline-stage failures affect the final exit status.

### Pipe locally between separate SSH commands

Rejected because it changes remote streaming and process semantics, opens multiple remote commands, and sends intermediate output through the MCP host.

## Consequences

- The MCP schema exposes commands and arguments directly, making valid tool calls easier for agents to construct and correct.
- Only server-controlled pipelines retain shell composition; other Bash features are intentionally removed.
- Existing YAML policies and handler configuration remain unchanged because they already describe command names and argument tokens.
- Human-facing prompts may retain shell notation for readability but must tell agents to submit the structured equivalent.
- ADR 002 remains the command-policy and threat-model decision, and ADR 003 remains the value-aware curl decision.
