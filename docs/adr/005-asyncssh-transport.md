# ADR: AsyncSSH transport and strict host trust

Date: 2026-10-11

## Status

Accepted. Replaces Paramiko as the SSH transport. Preserves the structured command boundary in [ADR 004](004-structured-command-pipeline.md).

## Context

The server needs to reuse the operator's OpenSSH configuration and non-interactive credentials while keeping connections open across MCP calls. The previous Paramiko transport introduced blocking calls into an async MCP server, accepted unknown host keys through `AutoAddPolicy`, implemented incomplete OpenSSH configuration behavior, and required custom workarounds for host discovery, `Match`, known-hosts markers, and native Windows agent access.

AsyncSSH already owns supported OpenSSH configuration semantics. Duplicating alias authorization and `Include` traversal in the server would create a second parser whose results can disagree with the library which actually establishes the connection.

## Decision

Use AsyncSSH 2.24.1 or newer as the only SSH backend.

- Pass the requested hostname, address, or alias to AsyncSSH without a custom `config` argument. AsyncSSH loads `~/.ssh/config` by default and applies its supported OpenSSH client directives, including `Host`, `Match`, `Include`, `HostName`, `User`, `Port`, identity files, connection timeout, keepalive, `ProxyCommand`, and `ProxyJump`.
- Keep `ssh_list_hosts` as best-effort discovery only. Its local reader lists concrete `Host` entries directly present in the main config, but does not follow `Include`, evaluate `Match`, reproduce connection options, or restrict connection targets.
- Accept unlisted hostnames and addresses. Reject only empty, overlong, whitespace-bearing, or control-character-bearing host values before passing them to AsyncSSH.
- Pass `~/.ssh/known_hosts` explicitly on every new connection. Never pass `known_hosts=None`, install a permissive callback, accept an unknown key, or write the trust store. AsyncSSH validates plain and hashed entries and the `@cert-authority` and `@revoked` markers.
- Tell the operator to run `ssh <alias>` in a terminal when a key is unknown or changed, so a person verifies the fingerprint before OpenSSH adds it. An untrusted presented key is reported only by alias, key type, and SHA-256 fingerprint. Raw transport errors are not returned because they may contain unsafe or sensitive text.
- Make one connection attempt. Do not retry after host-key rejection, authentication failure, timeout, DNS failure, configuration failure, or another connection failure.
- Use configured identities and SSH-agent authentication non-interactively. On native Windows, pass `\\.\pipe\openssh-ssh-agent` when `SSH_AUTH_SOCK` is absent. Pageant remains optional and no mandatory `pywin32` dependency is added.
- Let AsyncSSH read SSH configuration for each new connection. An existing connection retains the connection settings from its handshake until it closes; a replacement connection re-reads both SSH configuration and `~/.ssh/known_hosts`.
- Remove `ssh_download`, its SFTP implementation, and its download-size limit. Agents can read bounded remote content through validated `ssh_execute` commands. A future transfer tool would require a separate design with server-chosen local destinations and streaming limits.
- Keep runtime logs in `.logs/` beside the server by default and allow an explicit `SAFE_SSH_MCP_LOG_DIR` override. Do not introduce a general `.work` directory or `SAFE_SSH_WORK_DIR`: host keys remain in `~/.ssh/known_hosts`, and no download destination is needed.
- Keep at most one usable AsyncSSH connection per requested host. Protect lookup, creation, closed-connection replacement, and eviction with a per-host async lock while allowing concurrent process channels over the shared connection.
- Preserve configured `ServerAliveInterval` values, default to 30 seconds when unset, and bound keepalive failures to three. Replace a connection which is already closed before process creation, but never retry after process creation starts because an ambiguous transport loss could otherwise execute a command twice.
- Create command processes in byte mode and consume stdout and stderr concurrently. Retain at most 50 KB from each stream; if either exceeds the limit, close the process and report truncation with the exit status unavailable. Otherwise preserve the final pipeline stage's exit status.
- Apply one command deadline to process creation, stream consumption, and completion. Close the process on timeout or cancellation and await local cleanup. Close and await all pooled connections during repeat-safe MCP lifespan shutdown.
- Keep the remaining MCP tool schemas, structured pipeline validation, `shlex.join` rendering, and remote-shell behavior unchanged.

## Rejected alternatives

### Keep Paramiko

Rejected because a smaller initial diff would retain blocking transport calls, worker-thread cancellation limits, incomplete OpenSSH configuration behavior, and custom security-sensitive parsing around known hosts and `Match` blocks.

### Execute the OpenSSH client for every command

Rejected because Windows OpenSSH does not provide `ControlMaster`. The server would create a new connection for every command on Windows or would need platform-specific multiplexing behavior.

### Use the host-list reader as an authorization parser

Rejected because AsyncSSH, not the local reader, owns `Host`, `Match`, and `Include` semantics. Turning a best-effort list into an allowlist would reject valid AsyncSSH destinations and require duplicate security-sensitive parsing.

### Automatically trust or save first-seen keys

Rejected because the MCP agent must not make a trust-on-first-use decision for the operator. Trust changes remain an explicit terminal workflow.

### Retain and harden `ssh_download`

Rejected for the current public interface because the tool allows an agent to select a local write path and its size pre-check cannot safely bound streams or size-0 special files. Server logs showed no real agent use, while validated commands already cover bounded remote-file inspection. A redesigned transfer tool remains possible as separate work.

## Consequences

- SSH I/O is native asyncio. stdout and stderr drain concurrently without worker threads, and retained response memory is bounded independently for each stream.
- Concurrent commands for one requested host share a connection but use separate AsyncSSH channels. Concurrent connection creation for that host is serialized.
- Output truncation deliberately makes the exit status unavailable because the server closes the command channel before normal completion.
- OpenSSH configuration behavior is the subset implemented by AsyncSSH, not a promise of complete OpenSSH compatibility. Unsupported directives such as OpenSSH connection multiplexing settings do not become server features.
- AsyncSSH 2.24.1 does not resolve backslash-form absolute Windows `Include` paths. Operators must use forward slashes such as `C:/Users/operator/.ssh/config.d/*.conf`; the server does not normalize paths or duplicate `Include` expansion.
- `ssh_list_hosts` is intentionally incomplete: aliases present only in included files are usable but may not appear in its output.
- A malformed connection config is rejected by AsyncSSH. A missing or malformed known-hosts file fails closed. The server does not repair either file.
- Unknown, changed, and revoked keys stop before authentication or command execution.
- The MCP server exposes no SFTP or local file-write tool. Removing `ssh_download` is an intentional schema change.
