# Operational Health Assessment

Perform a best-effort, point-in-time operational health assessment of the requested remote Linux host or hosts. Use only read-only Safe SSH MCP tools and base every conclusion on collected evidence.

## Execution contract

1. Call `ssh_list_allowed_commands` before constructing commands. Treat its current output as authoritative.
2. Use `ssh_validate_command` when uncertain about a command or pipeline. Do not work around a rejection.
3. The examples below use shell notation for readability. For `ssh_execute`, submit each command as a structured `{command, arguments}` stage and convert each `|`-separated segment into an ordered pipeline stage.
4. Keep checks bounded. Do not use interactive, continuous, recursive whole-filesystem, or follow-mode operations.
5. If a command is unavailable, a file does not exist, permission is denied, output is truncated, or a check times out, record the check as not assessed with the reason. Do not use `sudo` or substitute a broader command.
6. Do not change the host. Recommendations are advice only and must not be executed.

## Evidence collection

Use only commands which discovery reports as allowed. The following are examples, not a requirement to run every command.

### System context

- `hostname`
- `cat /etc/os-release`
- `uname -a`
- `uptime`
- `grep -c '^processor' /proc/cpuinfo` for the logical CPU count

Report the host role only when the operator supplied it. A role inferred from processes, services, ports, or containers must be labeled as an unverified hypothesis.

### Storage

- `df -h`
- `df -i`
- `du -ah <bounded-path> | sort -hr | head -n 30` only when a specific filesystem or directory needs investigation

Report capacity, inode usage, mount points, and observed constraints. Treat percentage thresholds as attention heuristics rather than universal severity rules. Consider growth history, reserved space, workload, and operational policy when that context is available.

### Memory and load

- `free -h`
- `cat /proc/meminfo`
- `cat /proc/loadavg`
- `cat /proc/pressure/memory` when present
- `cat /proc/pressure/cpu` when present
- `cat /proc/pressure/io` when present

Use `MemAvailable` rather than treating all non-free memory as pressure. Swap absence or use is not automatically a defect; assess it against workload design and observed pressure. The three load averages summarize different time windows from one observation and do not establish a trend. Compare them with logical CPU count and corroborate suspected pressure with process and pressure-stall evidence.

### Processes and services

- `ps -eo pid,ppid,user,stat,etimes,pcpu,pmem,comm --sort=-pcpu | head -n 30`
- `ps -eo pid,ppid,user,stat,etimes,pcpu,pmem,comm --sort=-pmem | head -n 30`
- `ps -eo stat,pid,ppid,etimes,user,comm`
- `systemctl list-units`
- `systemctl list-unit-files`
- `systemctl status <known-unit>` for a unit identified from evidence or supplied by the operator
- `docker ps` when Docker is present

Inspect the `STAT` column directly for zombie (`Z`) or stopped (`T`) processes; do not search `ps aux` with a self-matching `grep`. A zombie or stopped process is an observation, not automatically an incident. Consider count, age, parent process, recurrence, and service impact.

Do not run continuous commands such as `top` in interactive mode, `docker stats` without a bounded one-shot form, `tail -f`, or `journalctl -f`.

### Logs

- `journalctl -p warning -n 200 --no-pager`
- `find /var/log -maxdepth 2 -type f -size +100M -printf '%s %p\n'`
- `stat <specific-log>` and `tail -n 200 <specific-log>` when evidence identifies a relevant file

A large log is not automatically a critical problem. Report its observed size and connect it to rotation state, available storage, growth evidence, or service impact before assigning severity. Avoid collecting unrelated authentication, credential, or application payload data.

### Network exposure

- `ss -lntup`
- `netstat -lntup` only when `ss` is unavailable

Distinguish loopback, specific-interface, and wildcard listeners. Do not call a port unexpected solely from its number; use process, service, host-role, and operator context. Do not perform outbound probes or port scans.

## Analysis rules

- Separate observation from interpretation. Quote the command and the minimal relevant output for each finding.
- Describe a symptom as a root cause only when evidence establishes the causal link.
- Use Critical only for observed or imminent loss of service, data, or essential capacity. Use lower severities according to demonstrated impact and urgency, not a fixed metric alone.
- State uncertainty and missing context explicitly.
- Do not claim historical behavior, growth, recurrence, or trends from a single snapshot.
- Do not claim that an unqueried service is healthy.

## Output format

### Assessment Scope

- Host or hosts
- Observation time
- Commands or areas assessed
- Important limitations, permissions, timeouts, or truncated output

### Executive Summary

- Overall point-in-time status: Healthy, Operational with Concerns, Degraded, or Critical
- Highest-confidence findings and their operational impact
- Important uncertainty or missing context

### Per-Host Evidence

For each host, report:

- System context
- Storage and inode usage
- Memory, swap, pressure, and load
- Process and service health
- Relevant log observations
- Network listeners
- Positive observations

### Findings

For each finding include:

- Severity
- Evidence: command and minimal relevant output
- Observation
- Assessment and operational impact
- Confidence and assumptions
- Recommended next diagnostic or remediation step, without executing it

### Not Assessed

List every material check skipped because a command or file was unavailable, permission was denied, the operation timed out, output was truncated, or required context was missing.

### Multi-Host Comparison

When multiple hosts are requested, compare equivalent measurements collected at approximately the same time. Highlight meaningful differences without treating unlike roles or workloads as directly comparable.
