# safe-ssh-mcp: Windows SSH setup

This guide covers Windows-specific SSH setup for safe-ssh-mcp. See the main [user and operator guide](guide.md) for installation, launcher and MCP client configuration, common usage, command policies, limits, and troubleshooting.

## Prerequisites

- Windows OpenSSH Client
- A verified host key in `%USERPROFILE%\.ssh\known_hosts` for every destination

## Start the OpenSSH agent

Safe SSH MCP cannot display a key passphrase prompt over MCP stdio. Start the Windows OpenSSH Authentication Agent and load encrypted keys before starting the MCP server.

Run PowerShell as Administrator:

```powershell
Set-Service -Name ssh-agent -StartupType Automatic
Start-Service ssh-agent
```

## Load an SSH key

Load the private key:

```powershell
& "$env:WINDIR\System32\OpenSSH\ssh-add.exe" "$env:USERPROFILE\.ssh\your-key-name"
```

## Verify loaded SSH keys

List the keys available to the agent:

```powershell
& "$env:WINDIR\System32\OpenSSH\ssh-add.exe" -l
```

## Configure a host

Optional aliases and connection settings belong in `%USERPROFILE%\.ssh\config`:

```text
Host example-web
    HostName 192.0.2.10
    User operator
    IdentityFile ~/.ssh/id_ed25519
```

## Verify a host

Connect once from PowerShell and verify the host-key fingerprint through a trusted channel before accepting it:

```powershell
ssh example-web
```

This creates or updates `%USERPROFILE%\.ssh\known_hosts` through the ordinary OpenSSH confirmation flow. Confirm that the command logs in without asking for a passphrase. Safe SSH MCP never accepts or saves a host key itself.

## SSH connection configuration

Safe SSH MCP reads supported settings from `%USERPROFILE%\.ssh\config` when it opens a connection. It does not separately resolve connection settings such as `HostName`, `User`, `IdentityFile`, `ProxyJump`, or `Include`.

Write absolute `Include` paths with forward slashes:

```text
Include C:/Users/operator/.ssh/config.d/*.conf
```

Backslash-form absolute `Include` paths are not supported. Safe SSH MCP does not rewrite or separately expand them.

## Host discovery with `ssh_list_hosts`

The `ssh_list_hosts` tool is only a best-effort list of concrete `Host` entries in the main config file. It does not follow `Include` or evaluate `Match`, and it is not an allowlist. Safe SSH MCP can still connect to included aliases, unlisted hostnames, and addresses when their host keys are trusted and authentication succeeds.

## Authentication notes

On native Windows, Safe SSH MCP uses the Windows OpenSSH agent pipe `\\.\pipe\openssh-ssh-agent` when `SSH_AUTH_SOCK` is absent. Pageant can be selected through SSH configuration but is not required.

Authentication is non-interactive and attempted once. An encrypted key must already be unlocked in the agent. A key named only in `IdentityFile` still needs to be unencrypted or available through an agent because the MCP server cannot prompt for its passphrase.

## Windows troubleshooting

- `SSH authentication failed`: verify the key with `& "$env:WINDIR\System32\OpenSSH\ssh-add.exe" -l` and confirm that `ssh <alias>` logs in non-interactively from PowerShell.
- An included SSH alias is ignored: change absolute `Include` paths to forward-slash form and start a new connection.
- Host-key errors and other transport failures: follow the common [SSH troubleshooting](guide.md#ssh-troubleshooting) guidance.
