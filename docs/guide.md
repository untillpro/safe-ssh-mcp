# safe-ssh-mcp: guide

<!-- markdownlint-disable MD024 -->

## Quick start

### Prerequisites

- Bash for the local launcher. On Windows, use Git Bash, MSYS2, or another Bash available on `PATH`. Remote Bash is not required; SSH continues to use each account's configured shell.
- One Python script runner:
  - Recommended: [uv](https://docs.astral.sh/uv/getting-started/installation/), which installs Python 3.10+ and the dependencies itself.
  - Fallback: [pipx](https://pipx.pypa.io/stable/how-to/install-pipx.html) 1.12.0 or newer; the launcher explicitly uses its `pip` backend.
- SSH keys loaded into ssh-agent or configured with `IdentityFile`
- Optional host aliases and connection settings in `~/.ssh/config`
- A `~/.ssh/known_hosts` file containing a verified key for every destination

Windows users can follow the dedicated [Windows SSH setup guide](windows.md) for OpenSSH agent, key, host-verification, configuration, and authentication details.

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

Replace `REPOSITORY_URL` with the URL of the repository or distribution you use.

```bash
cd your-workspace-directory
git clone REPOSITORY_URL
cd safe-ssh-mcp
```

### 3. Add the server to your MCP client

Replace `/path/to` with the absolute checkout path. On Windows, use a forward-slash path such as `C:/workspaces/work`.

#### Claude Code

```bash
claude mcp add --scope user safe-ssh -- bash /path/to/safe-ssh-mcp/safe_ssh_mcp.sh
```

`--scope user` makes the server available in every project. Without it, the server is added only for the current directory. Check it with `claude mcp list`, or `/mcp` inside a session.

#### Codex CLI

```bash
codex mcp add safe-ssh -- bash /path/to/safe-ssh-mcp/safe_ssh_mcp.sh
```

This writes the server to `~/.codex/config.toml`:

```toml
[mcp_servers.safe-ssh]
command = "bash"
args = ["/path/to/safe-ssh-mcp/safe_ssh_mcp.sh"]
```

Check it with `codex mcp list`, or `/mcp` inside a session.

#### Other clients

Most other clients (Augment Code, Claude Desktop, Cursor) take a JSON config:

```json
{
  "mcpServers": {
    "safe-ssh": {
      "command": "bash",
      "args": ["/path/to/safe-ssh-mcp/safe_ssh_mcp.sh"]
    }
  }
}
```

### 4. Configure runtime directories (optional)

By default, the server reads policies from `policies/` and writes logs to `.logs/` beside `safe_ssh_mcp.py`. No environment variables are needed for these defaults.

To use custom locations, add the server with the environment variables below instead of the corresponding command in step 3. Specify only the variable you need to override.

#### Claude Code

```bash
claude mcp add --scope user safe-ssh \
  -e SAFE_SSH_MCP_POLICY_DIR=/path/to/policies \
  -e SAFE_SSH_MCP_LOG_DIR=/path/to/logs \
  -- bash /path/to/safe-ssh-mcp/safe_ssh_mcp.sh
```

#### Codex CLI

```bash
codex mcp add safe-ssh \
  --env SAFE_SSH_MCP_POLICY_DIR=/path/to/policies \
  --env SAFE_SSH_MCP_LOG_DIR=/path/to/logs \
  -- bash /path/to/safe-ssh-mcp/safe_ssh_mcp.sh
```

#### Other clients

Add the variables to the server's `env` object:

```json
{
  "env": {
    "SAFE_SSH_MCP_POLICY_DIR": "/path/to/policies",
    "SAFE_SSH_MCP_LOG_DIR": "/path/to/logs"
  }
}
```

Absolute paths are used directly. Relative paths are resolved from the directory containing `safe_ssh_mcp.py`, not the MCP client's working directory. A configured policy directory replaces the packaged policy completely; it is not merged with `policies/`. Missing or empty policies and an unusable log directory stop server startup. On Windows, use forward-slash paths such as `C:/safe-ssh/policies`.

### 5. Try it

Ask the agent in plain language, for example:

- `List the available SSH hosts.`
- `Run uptime on example-web.`
- `Check the operational health of example-web.`
- `Assess the security posture of example-web.`

## Launcher details

The dependencies are declared at the top of `safe_ssh_mcp.py`. The launcher resolves them on first start through either `uv run` or `pipx run --backend pip`.

### Preload dependencies with uv

When using uv, dependency resolution can be completed before the first MCP client start:

```bash
uv sync --script safe_ssh_mcp.py
```

This step is optional.

### Select the script runner

The launcher prefers uv and falls back to pipx. Select a runner explicitly when deterministic startup is required:

```bash
bash safe_ssh_mcp.sh --runner uv
bash safe_ssh_mcp.sh --runner pipx
```

An explicit runner selection fails instead of falling back when that runner is unavailable or incompatible. Both `--runner pipx` and `--runner=pipx` are accepted. Use `--` before arguments intended for the Python server:

```bash
bash safe_ssh_mcp.sh --runner uv -- server-argument
```

In an MCP configuration, append `--runner` and the selected runner after the launcher path. For example, the Bash arguments for an explicit pipx selection are `/path/to/safe-ssh-mcp/safe_ssh_mcp.sh`, `--runner`, and `pipx`.

## Assessment prompts

Attach or reference a prompt and name the target host:

- [check-security.md](../prompts/check-security.md) - security audit of a host
- [check-operation-health.md](../prompts/check-operation-health.md) - resources, processes and operational metrics

## SSH behavior

Safe SSH MCP reads supported settings from `~/.ssh/config` and verifies every host against `~/.ssh/known_hosts`. Authentication is non-interactive, so encrypted keys must already be unlocked in the agent.

Connections are reused. New connections reread SSH configuration; restart the MCP server to replace an existing connection immediately. Windows-specific behavior is documented in the [Windows SSH setup guide](windows.md).

## Command policy

Only policy-approved read-only command forms run. The agent discovers allowed syntax with `ssh_list_allowed_commands` and can check a pipeline with `ssh_validate_command`.

File and system inspection is supported. Mutation, process control, unrestricted network access, shell redirection, substitution, and command chaining are blocked.

Commands have a 10-second timeout and 50 KB limit per output stream. There is no download or local file-write tool. See [design limits](design.md#limits).

### Docker containers

The default Docker policy permits its inspection commands and `docker exec <container> <command> [arguments...]`. The inner command and arguments must pass the same effective policy used for host commands. Docker exec options and nested Docker commands are rejected; any non-option container name or ID reference is passed to Docker and is not restricted to a configured list.

For example, `docker exec database nodetool status` is accepted only when the effective policy also permits `nodetool status`.

To disable `docker exec` while retaining `docker ps`, `inspect`, `logs`, and the other inspection forms, remove `handler: docker` from [docker.yaml](../policies/docker.yaml), leave `mode: whitelist` and `positional_variants` unchanged, and restart the MCP server. Remove the entire Docker command policy to disable all Docker commands.

## Agent-facing command format

`ssh_execute` and `ssh_validate_command` accept structured pipeline stages containing a command and its arguments. Agents translate `|`-separated examples in assessment prompts into ordered stages; shell operators are not accepted as input. See [command validation](design.md#command-validation).

## Allowing more commands

The default command-specific policy is declared in YAML files under [policies/](../policies/). [core.yaml](../policies/core.yaml) contains the base read-only commands, and the repository also ships policies for curl, Docker, additional system information, and strictly constrained security-status commands. Use `ssh_list_allowed_commands` for the effective syntax. To add a command, put its policy in one of these YAML files or add another `*.yaml` or `*.yml` file and restart the server. [example.yaml.template](../policies/example.yaml.template) shows the format, and [policy.schema.json](../policies/policy.schema.json) provides editor validation and completion:

```yaml
lsblk:
  mode: permissive

traceroute:
  mode: whitelist
  flags:
    - flag: -m
      value_pattern: '(?:[1-9]|[12][0-9]|30)'
    - flag: -w
      value_pattern: '[0-9]+(?:\.[0-9]+)?'
    - flag: -q
      value_pattern: '[1-9][0-9]?'
  require_flags:
    - -m

systemctl:
  mode: whitelist
  positional_variants:
    - ['(?:list-units|list-unit-files)']
    - args:
        - '(?:status|is-active|is-enabled|is-failed|show|list-dependencies|cat)'
      rest_pattern: '[A-Za-z0-9_.@:-]{1,128}'
      min_rest: 0
      max_rest: 10
```

Every flag object must contain `value_pattern`. A string requires one value and validates it with a case-sensitive full-string regular-expression match; `null` means the flag accepts no value. The equivalent forms `--flag value` and `--flag=value`, and `-n value` and `-nvalue`, receive the same validation result. Set `allows_flag_bundling: true` only when the command supports combined short flags; the default is `false`.

In whitelist mode, `positional_variants` defines complete allowed positional sequences. Array variants have exact arity. Bounded-rest variants use `args`, `rest_pattern`, `min_rest`, and `max_rest`. Omit `positional_variants` only when unrestricted positional arguments are safe. It is rejected in blacklist and permissive modes because the values of undeclared flags cannot be distinguished reliably from positional arguments.

Policy files are trusted operator configuration and must not come from remote or untrusted sources. They own command names, modes, flags, positional grammars, and handler configuration such as curl targets. Python owns pipeline shape, safe serialization, structural limits, and specialized value-aware handler implementations; these executable checks are not replaceable through YAML.

The schema modeline in each packaged policy overrides unrelated automatic schema matches made by YAML editors. It is editor metadata only and does not replace runtime validation. If a policy is moved outside the repository, update the modeline's relative path or omit it.

All `*.yaml` and `*.yml` files are loaded in filename order. Every command must have exactly one owner: duplicate YAML mapping keys and command names repeated across files stop server startup instead of silently replacing an earlier definition. A missing policy directory, no policy files, invalid policy structures, unknown fields, missing flag metadata, invalid or oversized patterns, and invalid positional variants also stop startup. The complete mode and matching rules are explained in [design.md](design.md#command-validation).

## Logs

Each server process writes a log file named `{YYMMDDHHmm}-{pid}.log` to `.logs/` next to `safe_ssh_mcp.py` or the directory selected by `SAFE_SSH_MCP_LOG_DIR`. It records connections, every executed command with its exit code, and every rejected command with the reason.

## SSH troubleshooting

- `SSH host must be ... without whitespace or control characters`: pass one hostname, address, or configured alias without embedded whitespace.
- `SSH host key ... is unknown or changed`: compare the reported SHA-256 fingerprint through a trusted channel, then run `ssh <alias>` in a terminal. Do not delete known-hosts entries merely to silence the warning.
- `SSH host key ... is revoked`: treat this as a security failure and contact the host operator. The MCP server will not bypass `@revoked`.
- `known-hosts file ... is malformed or unreadable`: repair `~/.ssh/known_hosts` with OpenSSH tooling. The server never rewrites it.
- `SSH authentication failed`: verify `ssh-add -l`, `IdentityFile`, file permissions, and a non-interactive `ssh <alias>` login. Unlock encrypted keys in the agent first.
- Proxy connection failures: verify the same alias with the OpenSSH client, then confirm that the directives are supported by Safe SSH MCP.
