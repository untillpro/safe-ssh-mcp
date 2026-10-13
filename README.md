# safe-ssh-mcp

MCP server for policy-validated, read-only SSH access, designed to limit command abuse and data exfiltration.

Agents submit structured command stages rather than shell text. The server validates every stage against the configured policy, renders literal arguments safely, and permits only server-created pipelines.

SSH uses persistent connections and the operator's supported `~/.ssh/config` settings. Safe SSH MCP reads and interprets SSH configuration directly; `ssh_list_hosts` is only a best-effort convenience list and is not an allowlist. Every new connection verifies the host against the explicit `~/.ssh/known_hosts` file; unknown, changed, and revoked keys fail closed, and the server never accepts or saves a key.

See the [user and operator guide](docs/guide.md) for installation, host-key setup, supported SSH configuration, and troubleshooting. Windows users should also follow the dedicated [Windows SSH setup guide](docs/windows.md). See the [technical design](docs/design.md) and [SSH transport ADR](docs/adr/005-asyncssh-transport.md) for the security boundaries and implementation decisions.
