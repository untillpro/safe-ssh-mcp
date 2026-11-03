# ADR: Policy-validated Docker execution

Date: 2026-10-13

Revised: 2026-11-03

## Status

Accepted. The original Docker-specific handler is replaced by generic subcommand dispatch and nested command validation in the policy DSL.

## Context

Operational commands may be installed only inside a container. For example, a database container may provide `nodetool` while the Docker host does not. Inner commands should share the effective host policies instead of duplicating their permissions inside Docker configuration.

The original flat Docker whitelist could select inspection verbs through positional variants but could not scope flags or requirements to individual subcommands. For example, `ps` filters must not enable log following, and requiring `--no-stream` for stats must not require it for every inspection command. The initial `handler: docker` implementation solved container execution through special Python code but left ordinary inspection on the flat policy model.

## Decision

Express Docker behavior entirely through generic whitelist policies:

- `subcommands` maps exact leading tokens to independent policies with their own flags, required flags, and positional rules; maps can nest for multi-level commands.
- Root rules support `docker -h` and `docker --help` without allowing those flags automatically on child policies.
- `nested_commands` lists raw-token regex prefixes before a command which must pass its own effective policy.
- Docker uses `nested_commands: [["exec", "[^-].*"]]`: consume `exec` and one non-empty, non-option container reference, then validate the remaining command recursively.
- Nested prefix matching happens before subcommand dispatch or flag parsing, preserving the ownership of inner flags.
- Multiple prefix matches, a missing nested command, failed inner validation, and re-entry into an active command policy are rejected without fallback.
- The engine allows at most eight nested command levels and eight subcommand levels, with bounded routing collections and the existing pipeline, argument, token, and pattern limits.
- The specialized curl handler remains available for inner commands and retains its destination and credential checks.
- The original structured stage is rendered once with `shlex.join`; no nested pipeline syntax, shell text, or `sh -c` layer is introduced.

The container may be any non-option reference accepted by Docker and is not allowlisted. Docker remains authoritative for resolving it. This retains the trust assumption that a command form considered safe on the host is also safe inside any container reachable by the SSH account.

## Configuration and migration

The policy shape is:

```yaml
docker:
  mode: whitelist
  flags:
    - {flag: --help, value_pattern: null}
  nested_commands:
    - ['exec', '[^-].*']
  subcommands:
    ps:
      mode: whitelist
      flags:
        - {flag: -a, value_pattern: null}
      positional_variants:
        - []
```

The complete bundled policy covers `ps`, `images`, `version`, `info`, `inspect`, `logs`, `stats`, `top`, and `port`. Logs require a bounded `--tail` value from 0 through 9999 and reject following; stats require the bare `--no-stream` flag. Root and child flags are independent. When positional variants are omitted, routing nodes default to no positionals; flat policies keep their existing semantics.

To migrate, remove `handler: docker`, declare the nested prefix above, and move inspection rules into child policies. The removed handler selector fails startup rather than falling back to weaker validation. Update policy schemas and restart the server with the matching implementation and policies.

To disable container execution while retaining inspection, remove only `nested_commands` and restart the server. Removing the entire Docker policy disables all Docker commands. Activation remains server-wide; per-host or per-container policy selection is outside this decision.

## Consequences

- Inspection flags and required options can be constrained independently without Docker-specific Python dispatch.
- Wrapper commands can reuse the same nested-command feature, including nesting across different command policies within the generic bounds.
- Nested Docker invocations remain rejected by the generic command-cycle guard.
- Discovery describes recursive policies generically and continues teaching agents to find containers before running diagnostics inside them.
- Policies with overlapping nested prefixes fail closed for matching invocations; startup does not attempt to prove arbitrary regex overlap.
- Enabling container execution exposes the effective command policies in every container reachable by the SSH account; operators requiring narrower boundaries need separate MCP instances with different policy directories.

## Reference implementation

- Recursive policy loading, generic dispatch, nested validation, and discovery: [safe_ssh_mcp.py](../../safe_ssh_mcp.py).
- Bundled configuration: [docker.yaml](../../config/policies/docker.yaml).
- Editor schema: [policy.schema.json](../../config/policies/policy.schema.json).
- Regression coverage: [test_dsl.py](../../tests/test_dsl.py).

## References

- [ADR 002: MVP command whitelist](002-mvp-command-whitelist.md)
- [ADR 003: Target-allowlisted curl handler](003-curl-handler.md)
- [ADR 004: Structured command pipeline](004-structured-command-pipeline.md)
