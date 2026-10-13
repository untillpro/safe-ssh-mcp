# Security Posture Assessment

Perform a best-effort, point-in-time security posture assessment of the requested remote Linux host. This is a read-only configuration and exposure review, not a vulnerability scan, penetration test, compliance certification, or guarantee that the host is secure.

## Execution contract

1. Call `ssh_list_allowed_commands` before constructing commands. Treat its current output as authoritative.
2. Use `ssh_validate_command` when uncertain about a command or pipeline. Do not work around a rejection.
3. The examples below use shell notation for readability. For `ssh_execute`, submit each command as a structured `{command, arguments}` stage and convert each `|`-separated segment into an ordered pipeline stage.
4. Keep checks bounded. Do not use recursive whole-filesystem searches, interactive or follow-mode commands, outbound probes, package updates, or network scans.
5. Never use `sudo`. If a binary is missing, permission is denied, a file is absent, output is truncated, or a check times out, classify the check as Not Assessed and record the reason.
6. Do not change the host. Recommendations are advice only and must not be executed.

## Data minimization

- Do not read `/etc/shadow` or `/etc/gshadow` contents.
- Do not read private keys, authorized-key contents, `.netrc` files, tokens, environment dumps, password hashes, or credential-bearing application configuration.
- Do not collect complete authentication logs or unrelated application payloads. Request only bounded, directly relevant evidence.
- Prefer metadata from `stat` or bounded summaries when content is unnecessary.
- Do not expose sensitive values in the report. Redact any credential-like value encountered unexpectedly.

## Evidence collection

Use only commands which discovery reports as allowed. The following are examples, not a requirement to run every command.

### System context

- `hostname`
- `cat /etc/os-release`
- `uname -a`
- `uptime`

Do not claim whether the kernel or installed packages are current unless a trusted version baseline was supplied. The default policy does not perform package updates or contact external repositories.

### SSH configuration

- `stat /etc/ssh/sshd_config`
- `grep -Ei '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords|MaxAuthTries|LoginGraceTime|X11Forwarding|AllowUsers|AllowGroups|DenyUsers|DenyGroups|ClientAliveInterval|ClientAliveCountMax|Ciphers|MACs|KexAlgorithms|UsePAM|StrictModes)[[:space:]]+' /etc/ssh/sshd_config`
- `find /etc/ssh/sshd_config.d -maxdepth 1 -type f -print` when the directory exists, followed by the same bounded inspection of each discovered file

Treat absent settings, `Include`, and `Match` blocks carefully. File text alone may not establish the effective configuration for every connection. A non-default SSH port is neither inherently secure nor inherently insecure.

### Network exposure and firewall status

- `ss -lntup`
- `netstat -lntup` only when `ss` is unavailable
- `ufw status verbose`
- `nft list ruleset`
- `iptables -L -n -v`
- `ip6tables -L -n -v`

Use `which` to avoid repeatedly invoking firewall tools which are not installed. Run only the exact read-only forms exposed by `ssh_list_allowed_commands`. Do not use `sudo`, and do not infer that a firewall is absent merely because the SSH account cannot read its state. Distinguish loopback, specific-interface, and wildcard listeners, and use host-role context before judging exposure.

### Accounts and critical-file metadata

- `getent passwd`
- `getent passwd 0`
- `id`
- `last -n 20`
- `stat /etc/passwd /etc/shadow /etc/group /etc/gshadow`
- `stat /etc/ssh/sshd_config`
- `find /etc/ssh -maxdepth 1 -type f -name 'ssh_host_*_key' -printf '%m %u %g %p\n'`

Report account attributes and file metadata without retrieving password hashes or key material. Additional UID 0 accounts, login shells, permissions, and ownership require local policy and operational context before they become findings.

### Processes, services, and security controls

- `ps -eo pid,ppid,user,stat,etimes,comm`
- `systemctl list-unit-files`
- `systemctl status <known-unit>` for a unit identified from evidence or supplied by the operator
- `getenforce`
- `aa-status`
- `auditctl -s`
- `fail2ban-client status`
- `fail2ban-client status <known-jail>` for a jail named by the status output

Missing optional security software is not automatically a weakness. Evaluate whether the control is applicable, whether another control provides equivalent protection, and whether the command failed because of permissions.

### Logging and recent access

- `systemctl status systemd-journald`
- `systemctl status rsyslog`
- `systemctl status auditd`
- `last -n 20`
- `ls -ld /var/log /etc/logrotate.d`

Assess whether logging components appear configured and active without collecting complete authentication logs. Do not claim centralized retention, alerting, or audit completeness unless direct evidence establishes it.

### Scoped configuration metadata

- `stat` specific certificate, service, repository, time-synchronization, or scheduled-task configuration paths only when the operator supplied the path or earlier evidence identified it
- `systemctl status systemd-timesyncd`, `systemctl status chronyd`, or another specifically identified time service

Do not search the entire filesystem for certificates, world-writable files, SUID files, keys, or scheduled tasks. Record package patch state, certificate validity, application-specific hardening, and compliance controls as Not Assessed unless the required scope, baseline, commands, and evidence are available.

## Classification rules

Classify each assessed item as one of:

- Confirmed Finding: evidence establishes the condition and its security relevance.
- Potential Concern: evidence suggests a concern but context, permissions, or corroboration is incomplete.
- Positive Observation: evidence confirms a relevant control or safe condition.
- Not Applicable: the check does not apply, with a stated reason.
- Not Assessed: the check could not be completed, with the missing command, permission, file, scope, timeout, truncation, or other reason.

Assign severity only to Confirmed Findings and Potential Concerns. Explain both likely impact and likelihood, state assumptions and uncertainty, and avoid deriving an overall risk rating from finding counts. Do not treat non-standard ports, IPv6, `NOPASSWD`, self-signed certificates, readable home directories, compilers, or absent security products as findings without relevant context.

Do not claim compliance unless the operator supplied the framework, profile, version, scope, and evidence requirements. Otherwise state that compliance was not assessed.

## Output format

### Assessment Scope and Limitations

- Host
- Observation time
- Areas assessed
- Important permission, command, file, timeout, truncation, and scope limitations

### Executive Summary

- Highest-confidence confirmed findings and potential concerns
- Material positive observations
- Important areas not assessed
- Overall posture narrative with confidence and scope, without score-by-count

### Findings

For each Confirmed Finding or Potential Concern include:

- Classification and severity
- Evidence: command and minimal relevant output
- Observation
- Impact and likelihood
- Confidence, assumptions, and required context
- Conditional recommendation, without executing it

### Positive Observations

List evidence-backed controls and safe conditions. Do not infer health for controls which were not queried.

### Not Applicable

List checks determined not to apply and why.

### Not Assessed

List every material check skipped or inconclusive because of missing binaries, insufficient privileges, unavailable files, unsupported commands, timeout, truncation, absent scope, or missing baseline information.
