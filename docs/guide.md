# safe-ssh-mcp: guide

<!-- markdownlint-disable MD024 -->

## Quick start

### Prerequisites

- Git to clone the repository, and Bash for the local launcher. On Windows, use Git Bash, MSYS2, or another Bash available on `PATH`. Remote accounts need a POSIX-compatible shell for literal argument quoting and pipelines; Bash itself is not required remotely.
- One Python script runner:
  - Recommended: [uv](https://docs.astral.sh/uv/getting-started/installation/), which installs Python 3.10+ and the dependencies itself.
  - Fallback: [pipx](https://pipx.pypa.io/stable/how-to/install-pipx.html) 1.12.0 or newer, with Python 3.10+ installed; the launcher explicitly uses its `pip` backend.
- SSH keys loaded into ssh-agent or configured with `IdentityFile`
- Optional host aliases and connection settings in `~/.ssh/config`
- A `~/.ssh/known_hosts` file containing a verified key for every destination

Windows users can follow the dedicated [Windows SSH setup guide](windows.md) for OpenSSH agent, key, host-verification, configuration, and authentication details.

Run the `bash` code blocks in Bash, including on Windows. The MCP client must also be able to find Bash and the selected Python runner on its `PATH`.

### 1. Add keys and hosts

Add your SSH keys to the agent:

```bash
ssh-add ~/.ssh/your-key-name
ssh-add -l
```

Define convenient hosts in `~/.ssh/config`:

```text
Host example-web
    HostName 192.0.2.10
    User operator
    IdentityFile ~/.ssh/id_ed25519

Host example-database
    HostName 198.51.100.20
    User operator
    IdentityFile ~/.ssh/id_ed25519
```

Connect once from a terminal and verify the host-key fingerprint before accepting it:

```bash
ssh example-web
```

### 2. Get the code

Replace `<your-workspace-directory>` with the absolute parent directory in which to clone the repository. The checkout will be `<your-workspace-directory>/safe-ssh-mcp`. On Windows, use a forward-slash path such as `C:/workspaces/work`; keep paths quoted when they appear in shell commands.

```bash
cd "<your-workspace-directory>"
git clone https://github.com/untillpro/safe-ssh-mcp
cd safe-ssh-mcp
```

### 3. Add the server to your MCP client

Use the registration for your client below. For a replacement configuration, use the corresponding command in step 4 instead. The client launches the server as a local stdio process.

#### Claude Code

```bash
claude mcp add --scope user safe-ssh -- bash "<your-workspace-directory>/safe-ssh-mcp/safe_ssh_mcp.sh"
```

`--scope user` makes the server available in every project. Without it, registration uses local scope for the current project. Check it with `claude mcp list`, or `/mcp` inside a session. See [Claude Code MCP configuration](https://code.claude.com/docs/en/mcp#mcp-installation-scopes).

#### Codex CLI

```bash
codex mcp add safe-ssh -- bash "<your-workspace-directory>/safe-ssh-mcp/safe_ssh_mcp.sh"
```

By default, this writes the server to `~/.codex/config.toml` using the following entry. See [Codex MCP configuration](https://developers.openai.com/codex/mcp#connect-codex-to-an-mcp-server).

```toml
[mcp_servers.safe-ssh]
command = "bash"
args = ["<your-workspace-directory>/safe-ssh-mcp/safe_ssh_mcp.sh"]
```

Check it with `codex mcp list`, or `/mcp` inside a session.

#### Other clients

For clients that accept an `mcpServers` JSON object, use:

```json
{
  "mcpServers": {
    "safe-ssh": {
      "command": "bash",
      "args": ["<your-workspace-directory>/safe-ssh-mcp/safe_ssh_mcp.sh"]
    }
  }
}
```

### 4. Select a configuration directory (optional)

By default, the server uses [config/](../config/), which contains the required `config.yaml` and the complete policy under `policies/`. The ignored `.logs/` runtime directory is created at startup. No environment variable is needed for this bundled configuration.

To use a complete replacement configuration, copy that layout, customize it, and select its directory with `SAFE_SSH_MCP_CONFIG_DIR`. Its policy files replace the bundled policy files; the two directories are not merged. Replace `<custom-config-directory>` with the directory containing both `config.yaml` and `policies/`.

If `safe-ssh` is already registered, edit its existing entry to add the environment variable rather than adding a duplicate registration.

#### Claude Code

```bash
claude mcp add --scope user safe-ssh \
  -e "SAFE_SSH_MCP_CONFIG_DIR=<custom-config-directory>" \
  -- bash "<your-workspace-directory>/safe-ssh-mcp/safe_ssh_mcp.sh"
```

#### Codex CLI

```bash
codex mcp add safe-ssh \
  --env "SAFE_SSH_MCP_CONFIG_DIR=<custom-config-directory>" \
  -- bash "<your-workspace-directory>/safe-ssh-mcp/safe_ssh_mcp.sh"
```

#### Other clients

Add the variable to the existing server entry's `env` object:

```json
{
  "env": {
    "SAFE_SSH_MCP_CONFIG_DIR": "<custom-config-directory>"
  }
}
```

Every configuration directory must contain this strictly validated file:

```yaml
version: 1

logging:
  directory: .logs
  retention_days: 30
```

`logging` may be omitted to use `.logs` and retain inactive logs for 30 days. A relative `logging.directory` is resolved from the effective configuration directory; an absolute path is used directly. `logging.retention_days` is optional and must be a positive integer; zero, negative values, booleans, and non-integer values stop startup. Unknown fields, duplicate keys, unsupported versions, empty paths, a missing `config.yaml`, missing or empty `policies/`, and an unusable log directory stop startup.

An absolute `SAFE_SSH_MCP_CONFIG_DIR` is used directly. A relative value is resolved from the directory containing `safe_ssh_mcp.py`, not the MCP client's working directory. On Windows, use a forward-slash path such as `C:/safe-ssh/config`.

### 5. Try it

Ask the agent in plain language, for example:

- `List the available SSH hosts.`
- `Run uptime on example-web.`
- `Check the operational health of example-web.`
- `Assess the security posture of example-web.`

## Launcher details

The dependencies are declared at the top of `safe_ssh_mcp.py`. The launcher resolves them on first start through either `uv run` or `pipx run --backend pip`.

### Preload dependencies with uv

From the checkout directory, dependency resolution can be completed before the first MCP client start:

```bash
uv sync --script safe_ssh_mcp.py
```

This optional step avoids dependency installation during the MCP client's startup deadline. Launcher commands below also assume the checkout directory is current.

### Select the script runner

The launcher prefers uv and falls back to pipx. Select a runner explicitly when deterministic startup is required:

```bash
bash safe_ssh_mcp.sh --runner uv
bash safe_ssh_mcp.sh --runner pipx
```

An explicit runner selection fails instead of falling back when that runner is unavailable or incompatible. Both `--runner pipx` and `--runner=pipx` are accepted. `--` ends launcher option parsing and forwards the remaining arguments unchanged; the Python server currently defines no command-line options, so use `SAFE_SSH_MCP_CONFIG_DIR` for runtime configuration.

In an MCP configuration, append `--runner` and the selected runner after the launcher path. For example, the Bash arguments for an explicit pipx selection are `<your-workspace-directory>/safe-ssh-mcp/safe_ssh_mcp.sh`, `--runner`, and `pipx`.

## Assessment prompts

Attach or reference a prompt and name the target host:

- [check-security.md](../prompts/check-security.md) - security audit of a host
- [check-operation-health.md](../prompts/check-operation-health.md) - resources, processes and operational metrics

## SSH behavior

Safe SSH MCP uses AsyncSSH's supported subset of `~/.ssh/config` settings and verifies every host against the explicit `~/.ssh/known_hosts` file. Unknown, changed, and revoked keys are rejected. Authentication is non-interactive, so encrypted keys must already be unlocked in the agent. See [supported SSH configuration](design.md#ssh-configuration-and-trust).

`safe_ssh_list_hosts` lists concrete `Host` entries directly in the main SSH configuration file. It does not follow `Include` or evaluate `Match`, and it is not a host allowlist. You can still request an included alias, unlisted hostname, or address when host-key verification and authentication succeed.

Connections are reused. New connections reread SSH configuration; restart the MCP server to replace an existing connection immediately. Windows-specific behavior is documented in the [Windows SSH setup guide](windows.md).

## Command policy

The bundled policy permits inspection commands and constrains commands that also have modifying forms. The agent discovers the effective configuration progressively:

1. Call `safe_ssh_list_allowed_commands()` for sorted top-level command names and their count.
2. Call `safe_ssh_get_command_rules(commands=["docker", "head"])` for complete rules for selected commands, including subcommands, nested-command prefixes, flag/value rules, and pipeline limits. Requests must contain exact top-level names; an empty list or an unknown name is rejected.
3. Use `safe_ssh_describe_validation_rules()` for shared matching and execution semantics, and optionally `safe_ssh_validate_command` to check a proposed pipeline before `safe_ssh_execute`.

Discovery and dry runs do not make SSH connections. A valid dry run confirms policy acceptance; it does not check whether a command exists on the host or whether the remote account can run it. `safe_ssh_test_connection(host="example-web")` checks SSH connectivity and authentication.

The bundled rules are designed to prevent system modification and limit network data exfiltration. Shell redirection, substitution, and command chaining cannot be expressed as structured operations; permitted argument values containing shell symbols are passed literally. The bundled curl policy restricts requests to allowlisted targets, using loopback by default. Custom policy authors remain responsible for the behavior they permit.

Each pipeline has a 10-second execution deadline after SSH connection establishment and retains at most 50 KiB per output stream. Exceeding either output limit closes the command channel and returns a truncation marker with the exit status unavailable. There is no download or local file-write tool. See [design limits](design.md#limits).

### Docker containers

The default [Docker policy](../config/policies/docker.yaml) uses generic subcommand and nested-command rules. Each leaf has its own allowed flags; root help flags are not inherited by subcommands. It permits:

- Root help: `docker -h` and `docker --help`.
- Container and image inspection: `ps`, `images`, `version`, `info`, `inspect`, `logs`, `stats`, `top`, and `port`.
- Swarm inspection: `node ls`, `node inspect`, `node ps`, `service ls`, `service inspect`, `service ps`, `stack ls`, `stack services`, and `stack ps`.
- Disk usage: `system df`, including `--verbose`/`-v` and `--format`.

Useful examples include `docker ps -a --no-trunc`, `docker inspect --format '{{json .}}' web`, `docker logs --tail 200 --since 30m web`, and `docker stats --no-stream`. Logs require an explicit `--tail` from 0 through 9999, and follow mode is not allowed. Stats require `--no-stream` to return one snapshot.

The policy also permits `docker exec <container> <command> [arguments...]` when the inner command and arguments pass the same effective policy used for host commands. Any non-empty, non-option container reference is passed to Docker without a configured name allowlist. Exec options are rejected; another nested Docker invocation is rejected by the generic policy-cycle guard. For example, `docker exec database nodetool status` is accepted only when the effective policy also permits `nodetool status`.

To disable `docker exec` while retaining inspection, remove only `nested_commands` from the Docker policy and restart the MCP server. Keep the root help rules and `subcommands` unchanged. Removing the entire Docker command policy disables all Docker commands.

Existing configurations using `handler: docker` must replace that selector with `nested_commands: [["exec", "[^-].*"]]` and move inspection rules into `subcommands`; the old handler selector now stops startup. The bundled Docker policy is a complete migration example. Other flat policies and the curl handler keep their existing syntax and behavior.

## Agent-facing command format

`safe_ssh_execute` and `safe_ssh_validate_command` accept a `pipeline` array of structured stages, each containing exactly `command` and `arguments`. For example, execute a bounded container listing with:

```json
{
  "host": "example-web",
  "pipeline": [
    {"command": "docker", "arguments": ["ps", "-a"]},
    {"command": "head", "arguments": ["-n", "20"]}
  ]
}
```

For `safe_ssh_validate_command`, omit `host` and pass the same `pipeline` field. Agents translate `|`-separated examples in assessment prompts into ordered stages. A `|` argument remains literal; it does not create a pipeline. The returned exit status belongs to the final stage. See [command validation](design.md#command-validation).

## Allowing more commands

The default command-specific policy is declared in YAML files under [config/policies/](../config/policies/). [core.yaml](../config/policies/core.yaml) contains the base inspection commands, and the repository also ships policies for curl, Docker, additional system information, and constrained security-status commands. Use `safe_ssh_list_allowed_commands` for names and `safe_ssh_get_command_rules` for effective syntax.

To add a command, put its policy in an existing policy file or add another `*.yaml` or `*.yml` file in the effective configuration's `policies/` directory, then restart the server. To change an existing command, edit its owning definition; duplicate command names stop startup. Select the entries you need from [example.yaml.template](../config/policies/example.yaml.template) rather than copying existing command definitions into a second file. [policy.schema.json](../config/policies/policy.schema.json) provides editor validation and completion.

For example, add a block-device inspection command with explicit flags and no positional operands:

```yaml
lsblk:
  mode: whitelist
  flags:
    - flag: --json
      value_pattern: null
    - flag: --output
      value_pattern: '(?:NAME|SIZE|TYPE|MOUNTPOINT)(?:,(?:NAME|SIZE|TYPE|MOUNTPOINT)){0,3}'
  positional_variants:
    - []
```

Every generic command and subcommand must explicitly declare `mode: permissive`, `mode: blacklist`, or `mode: whitelist`. There is no default, and a child does not inherit its parent's mode. Missing or invalid modes stop startup. Handler policies such as `handler: curl` use their handler's validation and must not declare `mode`. Older custom generic policies that omitted `mode` previously selected permissive behavior; add `mode: permissive` to preserve that behavior, or choose another mode and declare its rules explicitly. The bundled policies already declare their modes.

Every flag object must contain `value_pattern`. A string requires one value and validates it with a full-string Python regular-expression match, case-sensitive unless the pattern uses inline flags; `null` means the flag accepts no value. Generic policies accept equivalent forms `--flag value` and `--flag=value`, and `-n value` and `-nvalue`. Set `allows_flag_bundling: true` only when the command supports combined short flags; the default is `false`. The curl handler has its own grammar, reported in `handler_rules` by `safe_ssh_get_command_rules`.

In whitelist mode, `positional_variants` defines complete allowed positional sequences. Array variants have exact arity. Bounded-rest variants use `args`, `rest_pattern`, `min_rest`, and `max_rest`. Set `positional_variants: [[]]` to reject positional operands. Flat whitelist policies without this field allow unrestricted positional arguments; routing nodes instead default to no root positionals. The field is rejected in blacklist and permissive modes because the values of undeclared flags cannot be distinguished reliably from positional arguments.

### Subcommand and nested-command rules

In whitelist mode, `subcommands` maps a leading token to a child policy, which can itself contain further subcommands. Each generic child must declare its own mode and has independent flags, required flags, and positional rules; no mode, flags, or requirements are inherited from the parent. Routing nodes default to no root positionals, and unknown subcommands are rejected. Root flags are used on root invocations such as `docker --help`, not before a subcommand. Flat policies retain their existing flag and positional behavior when their mode is explicitly declared.

`nested_commands` lists regex prefixes preceding another command:

```yaml
docker:
  mode: whitelist
  positional_variants:
    - []
  nested_commands:
    - ['exec', '[^-].*']
```

Every pattern matches one entire raw argument, with case-sensitive matching unless inline regex flags specify otherwise. After `exec` and the container reference, the remaining tokens are validated as a command and its arguments using the effective policies. The split happens before parsing flags. Prefix matching precedes subcommand dispatch; ambiguous matches, missing commands, failed inner validation, and command cycles are rejected without fallback. An empty prefix delegates all arguments but still requires a command. Nesting and subcommand depth are each limited to eight levels. Removing `nested_commands` disables delegation without affecting inspection subcommands.

Use `safe_ssh_get_command_rules(commands=["docker"])` for the effective Docker policy tree and pipeline limits, and `safe_ssh_describe_validation_rules` for shared validation semantics. Include inner command names in the rules request when planning nested execution. See [technical design](design.md#subcommands-and-nested-commands) for dispatch order and startup validation.

Policy files are trusted operator configuration and must not come from remote or untrusted sources. They own command names, modes, flags, positional grammars, and handler configuration such as curl targets. Python owns pipeline shape, safe serialization, structural limits, and specialized value-aware handler implementations; these executable checks are not replaceable through YAML.

The schema modeline in each packaged policy overrides unrelated automatic schema matches made by YAML editors. It is editor metadata only and does not replace runtime validation. If a policy is moved outside the repository, update the modeline's relative path or omit it.

All `*.yaml` and `*.yml` files are loaded in filename order. Every command must have exactly one owner: duplicate YAML mapping keys and command names repeated across files stop server startup instead of silently replacing an earlier definition. A missing policy directory, no policy files, invalid policy structures, unknown fields, missing flag metadata, invalid or oversized patterns, and invalid positional variants also stop startup. The complete mode and matching rules are explained in [design.md](design.md#command-validation).

## Logs

Each server process writes a log file named `{YYMMDDHHmm}-{pid}.log` to the `logging.directory` selected by the effective `config.yaml`, which is `config/.logs/` by default. It records connections, execution requests and their exit status when available, and rejected execution requests with the reason. Discovery and policy dry runs do not log an execution.

At startup, the server removes inactive session logs whose last modification time is more than `logging.retention_days` days old, defaulting to 30 days. Cleanup considers only regular, non-symlink files with the server's filename format directly inside the effective log directory; it does not traverse subdirectories. The current log and files whose PID is still running or cannot be checked are preserved. PID reuse can therefore preserve an old log until a later startup.

Cleanup failures produce warnings in the current log and on stderr without preventing startup. An unusable current log directory or file still stops startup. Logs remain UTF-8, individual files have no size limit, and retention cleanup runs only at startup; a long-running server does not periodically remove old logs or impose a total directory size limit.

## SSH troubleshooting

- `SSH host must be ... without whitespace or control characters`: pass one hostname, address, or configured alias without embedded whitespace.
- `SSH host key ... is unknown or changed`: compare the reported SHA-256 fingerprint through a trusted channel, then run `ssh <alias>` in a terminal. Do not delete known-hosts entries merely to silence the warning.
- `SSH host key ... is revoked`: treat this as a security failure and contact the host operator. The MCP server will not bypass `@revoked`.
- `known-hosts file ... is malformed or unreadable`: repair `~/.ssh/known_hosts` with OpenSSH tooling. The server never rewrites it.
- `SSH authentication failed`: verify `ssh-add -l`, `IdentityFile`, file permissions, and a non-interactive `ssh <alias>` login. Unlock encrypted keys in the agent first.
- Proxy connection failures: verify the same alias with the OpenSSH client, then confirm that the directives are supported by Safe SSH MCP.
