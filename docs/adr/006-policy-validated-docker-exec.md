# ADR: Policy-validated Docker execution

Date: 2026-10-13

## Status

Accepted. Extends the Docker inspection policy with container execution while retaining the effective command policies as the authorization boundary.

## Context

Operational commands may be installed only inside a container. For example, a database container may provide `nodetool` while the Docker host does not. The existing Docker whitelist permits inspection such as `docker ps`, `docker inspect`, and `docker logs`, but rejects `docker exec` entirely.

Duplicating every allowed command and argument rule inside the Docker policy would create a second policy system which could drift from host command validation. Restricting container names would add deployment-specific configuration without strengthening the accepted trust model: a command considered safe on the host is also considered safe inside any container reachable by the SSH account.

## Decision

Add a built-in `docker` handler selected by `handler: docker` in the Docker policy. The bundled policy enables it by default.

The handler composes with the generic Docker whitelist:

- Ordinary Docker forms continue through the policy's `mode`, `flags`, and `positional_variants` rules.
- `docker exec <container> <command> [arguments...]` is parsed as one container boundary followed by one inner command stage.
- The container may be any non-option name or ID reference accepted by Docker. It is not allowlisted, and Docker remains authoritative for resolving it.
- Docker exec options are rejected. The token immediately after `exec` must be the container.
- The inner command is resolved from the complete effective command policy and validated by the same shared stage validator used for top-level pipeline stages.
- Generic inner policies and other specialized handlers such as `curl` remain available.
- An inner command using `handler: docker` is rejected, preventing nested Docker handling and recursion.
- The original structured stage is rendered once with `shlex.join`; the handler neither constructs shell text nor invokes `sh -c`.

A top-level structured pipeline may contain a Docker stage and other stages. The handler does not parse or permit a nested pipeline inside `docker exec`.

## Configuration and opt-out

The default policy is shaped as follows:

```yaml
docker:
  handler: docker
  mode: whitelist
  positional_variants:
    # Existing inspection-only variants
```

To disable `docker exec` while retaining Docker inspection, remove only `handler: docker`, leave `mode: whitelist` and `positional_variants` unchanged, and restart the MCP server. Removing the entire Docker command policy disables all Docker commands.

Policy selection is server-wide. Per-host or per-container activation is not part of this decision.

## Rationale

- **Shared safety assumption.** This design assumes that a command form accepted as safe by the effective host policy is also safe when executed inside any container reachable by the same SSH account. Therefore, host and container execution share one command policy rather than maintaining separate allowlists. Operators who do not accept this assumption can remove `handler: docker` or run a separate MCP instance with a narrower policy.
- **One authorization boundary.** The effective command policy remains the source of truth for both host and container commands.
- **No duplicated command lists.** Adding or tightening a command policy immediately changes its Docker execution behavior after restart.
- **Explicit parser boundary.** Python understands only Docker's `exec` envelope; each inner command remains owned by its existing generic or specialized validator.
- **Fail closed at the authorization boundary.** Missing tokens, Docker options, unknown inner commands, rejected arguments, and nested Docker handlers all cause rejection before SSH execution. An unknown or malformed non-option container reference is harmlessly passed to Docker, which rejects it before starting the inner command.

## Consequences

### Positive

- Agents can run existing read-only diagnostic commands where those binaries actually exist.
- Docker inspection retains declarative YAML validation and can be preserved when execution is disabled.
- Discovery can describe both inspection variants and the nested policy-validation rule.

### Negative

- Enabling the handler exposes every effective command policy in every container reference resolvable by Docker for the SSH account.
- The design does not distinguish host-safe from container-safe command semantics.
- Operators requiring host-specific or container-specific restrictions need separate MCP instances with different policy directories or a future scoped-policy design.

## Reference implementation

- Handler dispatch, Docker parsing, and the shared single-command validator: `safe_ssh_mcp.py`.
- Default configuration: `policies/docker.yaml`.
- Editor schema: `policies/policy.schema.json`.
- Regression coverage: `tests/test_dsl.py`.

## References

- [ADR 002: MVP command whitelist](002-mvp-command-whitelist.md)
- [ADR 003: Target-allowlisted curl handler](003-curl-handler.md)
- [ADR 004: Structured command pipeline](004-structured-command-pipeline.md)
