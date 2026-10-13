# ADR: MVP command whitelist

Date: 2025-11-14

## Status

Accepted

## Threat model

Prevent system MODIFICATION and data EXFILTRATION via network.
Users already have SSH access, so reading files and system information is acceptable.

What is blocked:

> **Amended by [ADR 003](003-curl-handler.md):** `curl` is no longer fully blocked. It is allowed in handler mode to explicitly allowlisted targets only; every other curl invocation remains blocked.

- File writes/deletes (rm, mv, cp, touch, mkdir, chmod, chown)
- Shell redirections (>, >>, <, 2>&1) -- prevents file creation
- Network exfiltration (wget, ssh, scp, rsync; curl except to allowlisted targets -- see ADR 003)
- Process control (kill, pkill, sudo, su)
- Command execution via flags (find -exec, find -delete)
- Archive extraction (tar -x, unzip without -l) -- creates files

What is allowed:

- All read-only operations (file reading, searching, system info)
- Bash pipes (read-only composition)
- Variable expansions in permissive-mode commands

## Context

The safe-ssh-mcp server needs a practical set of commands for initial release that balances security, functionality, and maintainability. The command set must:

- Enable common remote inspection and analysis tasks
- Prevent system modification and data exfiltration
- Provide good user experience with minimal surprises
- Be maintainable with clear security boundaries
- Support bash pipelines and composition

Users need to perform typical remote system tasks like examining files, searching content, analyzing logs, and gathering system information without ability to modify the remote system.

## Decision

Implement a 40-command MVP whitelist organized into eleven categories.
Most commands use permissive mode since they have no flags that modify the system.
Only commands with write/extract/execute flags use whitelist or blacklist mode.
Commands with internal execution/write capabilities that flag validation cannot catch are excluded.

### File operations (all permissive)

- `ls`, `cat`, `pwd`, `file`, `stat`

### Text processing

- `grep`, `head`, `tail`, `wc`, `uniq`, `cut`, `tr`, `diff`, `comm` (all permissive)
- `sort` (blacklist mode): block `-o`, `--output` -- writes to file
- REMOVED: `awk` -- `system()` executes commands, `print>"file"` writes, `print|"cmd"` pipes
- REMOVED: `sed` -- `e` command executes shell, `w` command writes files

### File search

- `find` (blacklist mode): block `-exec`, `-execdir`, `-ok`, `-okdir`, `-delete`

### System information

- `whoami`, `hostname`, `uname`, `which` (all permissive)
- `date` (blacklist mode): block `-s`, `--set` -- sets system date

### Disk usage (all permissive)

- `du`, `df`

### Path manipulation (all permissive)

- `basename`, `dirname`

### Process inspection (all permissive)

- `ps`, `top`, `free`

### System logs

- `journalctl` (blacklist mode): block `--vacuum-size`, `--vacuum-time`, `--vacuum-files`, `--rotate`, `--flush` -- journal maintenance

### Archive inspection

- `tar` (whitelist mode): `-t`, `-tz`, `-tj`, `-v` -- list only, no extraction
- `unzip` (whitelist mode): `-l`, `-v` -- list only, no extraction
- `zipinfo` (permissive mode)

### Structured data processing

- `jq` (permissive)
- `xmllint` (blacklist mode): block `--output` (writes to file), `--shell` (interactive shell)
- `yq` (blacklist mode): block `-i`, `--in-place` (edits files)

### Network diagnostics

- `ping` (whitelist mode): `-c`, `-W`, `-i` -- requires `-c` flag, max count 100
- `netstat` (permissive mode)
- `ss` (permissive mode)
- `iostat` (permissive mode)
- `nc` (whitelist mode): `-z`, `-v`, `-w`, `-u` -- requires `-z` (scan only)

## Rationale

### Category selection

File operations form the foundation for remote inspection. Text processing enables log analysis and data extraction. File search provides discovery capabilities. System information allows context gathering. Disk usage helps diagnose space issues. Process inspection enables system diagnostics. Archive inspection allows examining packaged files without extraction. Structured data processing enables modern config and API response analysis. Network diagnostics enable connectivity troubleshooting and socket inspection.

### Mode assignments

Permissive mode (most commands):

- Command has NO flags that can modify the system or exfiltrate data
- All flags are read-only by design (ls, cat, grep, head, tail, ps, df, etc.)
- This is the default - only use whitelist/blacklist when there is a specific dangerous flag

Whitelist mode (tar, unzip, ping, nc):

- Command has flags that write files or enable network transfer
- Only explicitly safe flags are allowed
- `tar`: only `-t` (list), blocks `-x` (extract which creates files)
- `unzip`: only `-l` (list), blocks extraction
- `ping`: requires `-c` (count limit) to prevent floods
- `nc`: requires `-z` (scan only) to prevent data transfer

Blacklist mode (find, sort, date, journalctl, xmllint, yq):

- Command has many useful flags but a few that modify the system
- `find`: blocked `-exec`, `-execdir`, `-ok`, `-okdir`, `-delete`
- `sort`: blocked `-o`, `--output` (writes to file)
- `date`: blocked `-s`, `--set` (sets system date)
- `journalctl`: blocked `--vacuum-*`, `--rotate`, `--flush` (journal maintenance)
- `xmllint`: blocked `--output` (writes to file), `--shell` (interactive shell)
- `yq`: blocked `-i`, `--in-place` (edits files)

Removed (internal exec/write -- flag validation cannot catch):

- `awk`: `system()` executes commands, `print>"file"` writes, `print|"cmd"` pipes
- `sed`: `e` command executes shell, `w` command writes files
- These are scripting languages with internal capabilities invisible to flag-level validation

### Commands excluded from MVP

Network exfiltration: `curl`, `wget`, `ssh`, `scp`, `rsync` (`curl` later re-admitted in handler mode to allowlisted targets -- see [ADR 003](003-curl-handler.md))

Process control: `kill`, `pkill`, `htop`

System modification: `rm`, `mv`, `cp`, `touch`, `mkdir`, `chmod`, `chown`

Scripting languages: `awk`, `sed` (internal exec/write bypasses flag validation)

Archive extraction: `tar` with `-x`, `unzip` without `-l`, `gzip`, `bzip2` (can create files)

Privilege escalation: `sudo`, `su`

## Assumptions

- Users already have SSH access - reading is not a threat
- Threat model focuses on preventing modification and exfiltration only
- Archive inspection without extraction is safe
- Modern config formats (JSON/YAML/XML) are common
- Bash pipelines provide sufficient composability
- MVP can expand via YAML policy files
- Dangerous `find` and `tar` flags unchanged since POSIX standardization
- 40 base commands sufficient for 95% of use cases
- Additional commands can be added via `policies/` YAML files

## Reference Implementation

See `policies/core.yaml` for the base command policies and `COMMAND_POLICIES` in `safe_ssh_mcp.py` for their validated runtime representation.
The validator comment block documents the threat model and mode assignment rationale.

## Risks

| Risk                                       | Severity | Mitigation                                         |
|--------------------------------------------|----------|----------------------------------------------------|
| Archive extraction via tar/unzip flags     | High     | Whitelist mode: only -t (list) allowed             |
| Unbounded ping flood                       | High     | Require -c flag, max count 100                     |
| find -exec/-delete modifies system         | High     | Blacklist mode blocks these flags                  |
| nc used for data exfiltration              | High     | Require -z (scan only), no data transfer           |
| Scripting languages bypass flag validation | High     | awk and sed removed entirely                       |
| Permissive mode allows unexpected flags    | Low      | Only used for commands with no write/execute flags |
| find blacklist misses new dangerous flags  | Low      | POSIX find stable since 1970s                      |
| Users expect commands not in base set      | Low      | Extensible via `policies/` YAML files              |

## Consequences

### Positive

- Permissive mode for most commands reduces false rejections
- Clear threat model prevents over-engineering
- Extensible via YAML policy files for environment-specific commands
- Comprehensive coverage of remote inspection and troubleshooting
- Enables sophisticated pipelines with 40+ commands
- Low maintenance - only 4 commands need whitelist mode
- Scripting languages with internal exec/write removed to prevent bypass

### Negative

- No data transfer commands (curl, wget, scp)
- No process control (kill, pkill)
- No archive extraction capability
- No awk/sed (users must use grep, cut, tr for text processing)
- May frustrate users expecting full shell access

## Future additions

Post-MVP commands to consider based on user feedback:

- `xargs` (blacklist mode, block shell invocation)
- `expr` (permissive mode)
- `test`/`[` (permissive mode)
- `printf`/`echo` (permissive mode)
- `base64` (permissive mode)
- `md5sum`/`sha256sum` (permissive mode)
- `strings` (permissive mode)
- `hexdump`/`xxd` (permissive mode)
- `ip` (permissive mode)
- `route` (permissive mode)

## References

- [ADR 001: Bash command validation for safe operations](001-bashlex.md)
