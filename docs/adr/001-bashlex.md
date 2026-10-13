# ADR: Bash command validation for safe operations

Date: 2025-11-14

## Status

Superseded by [ADR 004: Structured command pipeline](004-structured-command-pipeline.md).

## Context

Need to allow users to execute bash commands with full pipeline and substitution capabilities while preventing system modification. Users need:

- Pipeline functionality (e.g., `ls | grep | wc`)
- Command and process substitutions for composability
- Variable expansions for flexibility

System must prevent:

- Execution of unsafe commands (network access, process control, privilege escalation)
- File creation, modification, or deletion
- Any writes to filesystem or system state

## Decision

Use `bashlex` to parse and validate bash commands. Primary security controls:

1. Command whitelist: only safe commands allowed
2. Block all redirections: prevents writing to filesystem
3. Recursive validation: ensure entire command tree uses whitelisted commands

Secondary defense (flag injection prevention) uses three-tier validation system:

### Validation modes

Commands are configured with one of three modes:

- Whitelist mode: only specified flags allowed, expansions blocked
- Permissive mode: all flags allowed, expansions allowed
- Blacklist mode: specified flags blocked, expansions allowed

### Validation rules

- Allow pipes between whitelisted commands
- Allow command and process substitutions with recursive validation
- Allow variable expansions (in permissive/blacklist modes)
- Block arithmetic expansion (unnecessary for safe operations)
- Block ALL redirections (`>`, `<`, `>>`, `2>&1`, etc.)
- Allow glob patterns
- Recursive AST validation ensures all commands in tree are whitelisted

## Security rationale

### Why this prevents unsafe command execution

1. **Command whitelist restricts to safe read operations**: Only commands for reading/processing local files are allowed (ls, cat, grep, find, etc.). Commands for network access (curl, wget), process control (ps, kill), system modification (useradd, passwd), or any other unsafe operations are excluded
2. **No command injection possible**: Even with expansions/substitutions, users cannot execute commands outside the whitelist

### Why this prevents file modifications

1. **Whitelist excludes write commands**: rm, mv, touch, cp, dd, tee, sed -i are not in whitelist
2. **Redirection blocking**: prevents `ls > file` or `cat < input`  
3. **Dangerous flag blocking**: prevents `find -delete` or `find -exec rm`

### Why expansions and substitutions are safe

- Variable expansion (`$VAR`): Expands to text, passed as arguments to whitelisted commands
- Command substitution (`$(cmd)`): Output becomes text argument, and `cmd` itself is validated
- Process substitution (`<(cmd)`): Creates read-only file descriptor, and `cmd` is validated
- Glob expansion (`*.txt`): Expands to filenames, no execution risk

All expansions produce text that becomes arguments to safe commands. No expansion can bypass the command whitelist or redirection blocking.

## Assumptions

- Primary goal: prevent system modification (file creation, writes, deletions)
- Safe command whitelist is sufficient for preventing modification
- Blocking redirections prevents all write operations
- Command substitutions and expansions are safe when all commands are safe
- Each command configured with whitelist, permissive, or blacklist mode
- Information disclosure is acceptable (users can read files)
- Denial of service is acceptable risk
- `bashlex` parser is trusted and maintained
- All dangerous bash features can be detected via AST node types
- Dangerous flags in commands like `find` are well-known and stable

## Implementation

```python
import bashlex

# Three-tier validation system
whitelist = {
    # Whitelist mode: only these flags allowed, no expansions
    'ls': {'mode': 'whitelist', 'flags': ['-l', '-a', '-la', '-h', '-R']},
    'grep': {'mode': 'whitelist', 'flags': ['-i', '-v', '-r', '-n']},
    'head': {'mode': 'whitelist', 'flags': ['-n']},
    'tail': {'mode': 'whitelist', 'flags': ['-n', '-f']},
    'wc': {'mode': 'whitelist', 'flags': ['-l', '-w', '-c']},
    'uniq': {'mode': 'whitelist', 'flags': ['-c']},
    
    # Permissive mode: all flags allowed, expansions allowed
    'cat': {'mode': 'permissive'},
    'sort': {'mode': 'permissive'},
    'cut': {'mode': 'permissive'},
    'tr': {'mode': 'permissive'},
    'sed': {'mode': 'permissive'},  # sed without -i is read-only
    'awk': {'mode': 'permissive'},
    
    # Blacklist mode: these flags blocked, expansions allowed
    'find': {'mode': 'blacklist', 'flags': ['-exec', '-execdir', '-ok', '-okdir', '-delete']},
}

def check_command_safe(command_node, whitelist):
    if not command_node.parts:
        return False, "Empty command"
    
    # Get command name (must be plain word)
    cmd_part = command_node.parts[0]
    if cmd_part.kind != 'word':
        return False, "Command name must be plain word"
    
    cmd_name = cmd_part.word
    if cmd_name not in whitelist:
        return False, f"Command '{cmd_name}' not allowed"
    
    config = whitelist[cmd_name]
    mode = config.get('mode', 'permissive')
    flags = config.get('flags', [])
    
    # Validate arguments
    for part in command_node.parts[1:]:
        if part.kind != 'word':
            continue
        
        arg_value = part.word
        is_flag = arg_value.startswith('-')
        
        if mode == 'whitelist':
            # Only listed flags allowed, no expansions
            if is_flag and arg_value not in flags:
                return False, f"Flag '{arg_value}' not allowed for {cmd_name}"
            
            # Block expansions/substitutions in whitelist mode
            if hasattr(part, 'parts'):
                for subpart in part.parts:
                    if subpart.kind in ('parameter', 'commandsubstitution', 'processsubstitution'):
                        return False, f"Expansions not allowed in whitelist mode for {cmd_name}"
        
        elif mode == 'blacklist':
            # Listed flags blocked, expansions allowed
            if is_flag and arg_value in flags:
                return False, f"Flag '{arg_value}' blocked for {cmd_name}"
        
        # Permissive mode: allow everything including expansions
    
    return True, "OK"

def check_node_safe(node, whitelist):
    # CRITICAL: Block all redirections to prevent filesystem writes
    if node.kind == 'redirect':
        return False, "Redirections not allowed"
    
    # Validate commands
    if node.kind == 'command':
        safe, msg = check_command_safe(node, whitelist)
        if not safe:
            return safe, msg
    
    # Recursively validate command substitutions
    if node.kind == 'commandsubstitution':
        safe, msg = check_node_safe(node.command, whitelist)
        if not safe:
            return False, f"In substitution: {msg}"
    
    # Recursively validate process substitutions
    if node.kind == 'processsubstitution':
        safe, msg = check_node_safe(node.command, whitelist)
        if not safe:
            return False, f"In process substitution: {msg}"
    
    # Always block arithmetic expansions
    if node.kind == 'word' and hasattr(node, 'parts'):
        for part in node.parts:
            if part.kind == 'arithmetic':
                return False, "Arithmetic expansion not allowed"
    
    # Recurse into all child nodes
    if hasattr(node, 'parts'):
        for part in node.parts:
            safe, msg = check_node_safe(part, whitelist)
            if not safe:
                return safe, msg
    
    return True, "OK"
```

## Mode selection guidance

Note: All modes prevent system modification via command whitelist and redirection blocking. Mode choice is about flag injection defense and user flexibility.

### Use whitelist mode when

- Command accepts flags that could change behavior unexpectedly
- Flag injection could bypass intended usage
- Command commonly used with specific, well-known flags
- Examples: `ls` (prevent `-R` recursion bombs), `grep` (prevent `-r` recursive searches), `head`/`tail` (control output size)

### Use blacklist mode when

- Command has many useful flags, but few dangerous ones
- Dangerous flags are well-known and stable
- Users need flexibility with most flags
- Examples: `find` (block `-exec`, `-execdir`, `-delete`, `-ok`, `-okdir`)

### Use permissive mode when

- Command is simple and safe regardless of flags
- Users benefit from variable expansion flexibility
- Command has many useful flags that are tedious to whitelist
- Flag injection risk is minimal
- Examples: `cat` (simple output), `sort` (sorting options don't affect security), `awk` (complex but read-only)

## Examples

### Allowed

Whitelist mode:

- `ls -la` - flag in whitelist
- `ls -la *.txt` - flag + globs
- `grep -i pattern file.txt` - whitelisted flag
- `head -n 10 file.txt` - whitelisted flag

Permissive mode:

- `cat file.txt` - no flags
- `cat $FILE` - variable expansion allowed
- `cat $(find . -name "*.txt")` - substitution allowed
- `sort --reverse` - any flag allowed
- `awk '{print $1}' file.txt` - complex patterns allowed

Blacklist mode:

- `find . -name "*.txt"` - safe flags
- `find . -type f -size +1M` - safe flags
- `find $DIR -name $PATTERN` - variable expansion allowed
- `find . -mtime -7 | wc -l` - piped to other commands

Mixed pipelines:

- `ls -la | grep test` - whitelist piped to whitelist
- `find . -name "*.txt" | wc -l` - blacklist piped to whitelist
- `cat $(ls -la | grep $VAR)` - nested: permissive cat, whitelist ls, whitelist grep with expansion blocked

### Blocked

Whitelist mode violations (flag injection defense):

- `ls -x` - flag not in whitelist
- `ls $HOME` - variable expansion in whitelist mode
- `grep $(echo pattern) file` - substitution in whitelist mode
- `ls --color=auto` - flag not in whitelist

Blacklist mode violations:

- `find . -name "*.txt" -delete` - blacklisted flag
- `find . -type f -exec rm {} \;` - blacklisted flag
- `find . -execdir sh -c 'rm *' \;` - blacklisted flag
- `find . -ok cat {} \;` - blacklisted flag
- `find . -okdir ls {} \;` - blacklisted flag

System modification prevention (primary security):

- `rm file.txt` - write command not in whitelist
- `touch newfile` - write command not in whitelist
- `mv old new` - write command not in whitelist
- `cp file backup` - write command not in whitelist
- `ls > output.txt` - redirection enables filesystem write
- `cat file.txt 2>&1 > log` - redirection enables filesystem write
- `grep pattern < input > output` - redirection enables filesystem write
- `tee output.txt` - command writes to filesystem

Always blocked (other):

- `echo $((5 + 5))` - arithmetic expansion unnecessary
- `curl http://example.com` - command not in whitelist (not read-only)

## Risks

| Risk                                           | Severity | Mitigation                                                                            |
|------------------------------------------------|----------|---------------------------------------------------------------------------------------|
| Command whitelist includes write operation     | Critical | Audit whitelist regularly, never include `rm`, `mv`, `touch`, `cp`, `dd`, `tee`, etc. |
| Redirection bypass in parser                   | Critical | Keep bashlex updated, test all redirection operators                                  |
| Parser bugs miss dangerous syntax              | Medium   | Keep library updated, test edge cases                                                 |
| Flag injection enables writes (e.g., `tar -x`) | High     | Use whitelist mode for commands with dangerous flags                                  |
| Blacklist incomplete for find-like commands    | High     | Audit blacklisted flags: `-exec`, `-execdir`, `-ok`, `-okdir`, `-delete`              |
| New dangerous flag added to stable commands    | Low      | Find execution flags unchanged since 1970s, monitor security advisories               |
| Variable expansion path traversal              | Low      | Acceptable (read-only access is permitted)                                            |
| Deeply nested substitutions missed             | Medium   | Comprehensive recursive validation, unit tests                                        |
| Complex AST traversal bugs                     | Medium   | Thorough testing of nested structures                                                 |
| Empty expansion causes unexpected behavior     | Low      | Document behavior for users                                                           |

## Consequences

### Positive

- Prevents all system modification through command whitelist + redirection blocking
- Users have full bash expressiveness (pipes, substitutions, expansions, globs)
- Granular security per command (whitelist/permissive/blacklist modes)
- Flag injection prevented in whitelist mode
- Dangerous execution flags blocked in blacklist mode
- Variable expansions allowed in permissive/blacklist modes for flexibility
- Command and process substitutions allowed for composability
- Strong security through recursive whitelist validation
- Defense in depth: multiple layers prevent modification
- Blacklist mode provides flexibility for complex commands like find

### Negative

- No arithmetic expansion (low impact for read operations)
- No output redirection (users must capture output programmatically)
- Depends on third-party parser library
- Complex recursive validation increases code complexity
- Deep nesting in substitutions requires careful testing
- Must carefully choose mode for each command
- Variable expansion behavior differs between modes (may confuse users)
- Blacklist maintenance required if new dangerous flags discovered

## Alternatives considered

### Block all expansions and substitutions

- Pros: simpler validation, smaller attack surface
- Cons: severely limited functionality, users cannot compose commands dynamically, defeats purpose of allowing bash

### Two-tier system only (no blacklist mode)

- Pros: simpler implementation, fewer concepts
- Cons: must choose between whitelisting 50+ find flags or permissive mode with no protection against `-exec`/`-delete`

### Single commands only (no pipes)

- Pros: simpler validation, fewer attack vectors
- Cons: limited user functionality, must chain manually

### Structured command API

- Pros: no parsing needed, complete control
- Cons: poor user experience, not bash-compatible

### Block all substitutions

- Pros: simpler validation, smaller attack surface
- Cons: reduced functionality, users cannot compose commands dynamically

### Whitelist all find flags

- Pros: explicit control
- Cons: 50+ flags to maintain, poor user experience

## References

- [Attempt 1](https://claude.ai/chat/6e54ea2f-4062-4ca3-8960-1e5f072d2c11)
- [Attempt 1, Review](https://claude.ai/chat/93e35550-1249-453a-91b9-e1d4f773fb64)
