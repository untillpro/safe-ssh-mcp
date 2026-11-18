# ADR: Policy-validated sudo execution

Date: 2026-11-18

## Status

Accepted. Supersedes the exclusion of `sudo` in [ADR 002](002-mvp-command-whitelist.md); `su` and every other privilege change remain blocked.

## Context

Several bundled inspection commands report useful data only as root, for example `iptables -L`, `nft list ruleset`, `ufw status`, `auditctl -s`, and `fail2ban-client status`. Root-only logs and configuration files are equally unreadable for an unprivileged SSH account. [ADR 002](002-mvp-command-whitelist.md) blocked `sudo` entirely, so these checks could only be reported as not performed.

The threat model already accepts that the agent reads whatever the SSH account can read and concentrates on preventing system modification and network data exfiltration. The generic `nested_commands` rule introduced for Docker in [ADR 006](006-policy-validated-docker-exec.md) can validate a command that follows a fixed prefix without a specialized handler.

## Decision

Allow two `sudo` forms through a generic whitelist policy:

- `sudo -n -- COMMAND [ARGUMENTS...]` runs a command whose name and arguments pass the same effective policy as a top-level pipeline stage.
- `sudo -n -l` lists the account's sudo privileges without running a command.

Every enabled command is available under sudo; there is no separate list of privileged commands. The agent is assumed cooperative and may read everything the host exposes to root, including private keys and password hashes. Policy validation continues to reject modifying forms and is the only barrier against modification as root.

The prefix is exact:

- `-n` makes sudo fail instead of prompting when the account has no matching `NOPASSWD` rule. Standard input is already detached, so a prompt could never be answered.
- `--` ends sudo option parsing, so flags of the inner command are never interpreted by sudo.
- Every other sudo option is rejected, including a target user or group, environment preservation, login and shell modes, editing, background execution, and option bundles such as `-ni`.
- An environment assignment before the command is rejected because it is not a policy command name.
- `sudo` inside `sudo`, directly or through another wrapper such as `docker exec`, is rejected by the generic command-cycle guard.

The list form requires both `-n` and `-l` and accepts no operands, so `-l` without `-n`, a command to check, another user, and another host are rejected. Repeating `-l` selects sudo's long listing format and is harmless.

The policy is enabled in the bundled configuration. The effective privilege is still decided by each host's sudoers: an account without sudo rights gains nothing.

## Configuration

The policy shape is:

```yaml
sudo:
  mode: whitelist
  valueless_flags: [-n, -l]
  require_flags:
    - -n
    - -l
  positional_variants:
    - []
  nested_commands:
    - ['-n', '--']
```

Nested prefix matching happens before flag parsing, so `require_flags` and the positional rule apply only to invocations that do not match the `-n --` prefix, which leaves `sudo -n -l` as the single accepted root invocation.

To disable privileged execution, remove the `sudo` policy and restart the server. To keep the list form only, remove `nested_commands`. Activation is server-wide; operators who need sudo on some hosts only restrict it in each host's sudoers or run separate MCP instances with different policy directories.

## Consequences

- Root-only inspection commands and files become available without a new handler or validator change.
- Reading is no longer limited by file permissions on hosts where the account has unrestricted `NOPASSWD` sudo. Secrets readable by root can reach the agent and the model provider.
- A gap in any command policy becomes a root-level gap. Policies for commands with modifying forms must enumerate or block those forms completely; the `uniq` output operand and the `file` compile option were closed together with this decision.
- Blacklist policies carry the highest risk under sudo because every undeclared flag is allowed. The validator rejects abbreviations of blocked long options, which getopt-style commands accept, but it cannot infer differently spelled aliases; each spelling must be listed, and whitelist mode is preferred for commands with modifying forms.
- A least-privilege account remains the recommended second layer: restrict the sudoers rule to the binaries that need root when the full command set is not required.
- sudo logs each invocation on the host, including failed attempts by accounts without sudo rights.
- Each pipeline stage is validated and elevated independently; a pipeline needs the prefix on every stage that requires root.

## Reference implementation

- Bundled configuration: [core.yaml](../../config/policies/core.yaml).
- Generic nested validation and the command-cycle guard: [safe_ssh_mcp.py](../../safe_ssh_mcp.py).
- Regression coverage: [test_dsl.py](../../tests/test_dsl.py).

## References

- [ADR 002: MVP command whitelist](002-mvp-command-whitelist.md)
- [ADR 004: Structured command pipeline](004-structured-command-pipeline.md)
- [ADR 006: Policy-validated Docker execution](006-policy-validated-docker-exec.md)
