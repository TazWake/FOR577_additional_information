# Self-Check - IR trust-check Binary - Use Guide

## Overview

**self-check** is a minimal trust beacon designed for incident response engagements. It's a statically-linked, small (<16KB) assembly binary that reports process identity, capabilities, and sandbox/container status without relying on libc or external dependencies.

### Purpose

When responding to incidents on potentially compromised Linux systems, you need to understand the execution environment without triggering sophisticated rootkits or relying on system libraries that may be backdoored. self-check provides:

- **Process identity** (PID, PPID, UID/EUID, GID/EGID)
- **Capability sets** (effective and permitted)
- **Sandbox status** (seccomp, NoNewPrivs)
- **No external dependencies** - uses raw syscalls only
- **Minimal attack surface** - ~8.7KB static binary, no dynamic linking

### When to Use

Use self-check during incident response to:

1. **Verify execution context** before deploying more complex tooling
2. **Detect container escapes** - Compare capabilities inside/outside container
3. **Identify privilege restrictions** - Check if seccomp or NoNewPrivs are active
4. **Baseline environment** - Quick sanity check of process context
5. **Test EDR/rootkit evasion** - Tiny binary may bypass detection focused on larger tools

**Common scenarios:**

- Initial triage on unknown systems
- Container/namespace investigation
- Privilege escalation analysis
- Pre-deployment environment check for forensic tools

## Building self-check

### Prerequisites

**Required:**

- NASM assembler (2.14+)
- GNU ld linker
- Linux system (or cross-compilation environment)

**Installation:**

```bash
# Debian/Ubuntu
sudo apt-get install nasm binutils

# RHEL/CentOS/Fedora
sudo dnf install nasm binutils

# Arch Linux
sudo pacman -S nasm binutils
```

### Build Instructions

**Standard build:**

```bash
cd /path/to/self-check
./build.sh
```

This produces a stripped, statically-linked binary: `self-check` (~8.7KB)

**Manual build:**

```bash
# Assemble
nasm -felf64 src/self-check.asm -o self-check.o

# Link statically
ld -static -nostdlib -o self-check self-check.o

# Strip symbols
strip self-check

# Verify
ls -lh self-check
file self-check
ldd self-check  # Should say "not a dynamic executable"
```

**Debug build (with symbols):**

```bash
nasm -felf64 -g -F dwarf src/self-check.asm -o self-check-debug.o
ld -static -nostdlib -o self-check-debug self-check-debug.o
# Don't strip - keeps symbols for debugging
```

### Build Verification

```bash
# Verify it's statically linked
ldd self-check
# Expected: "not a dynamic executable"

# Verify size
ls -lh self-check
# Expected: ~8.7KB

# Test run
./self-check
# Expected: Single line of key=value output
```

## Usage

### Basic Execution

```bash
./self-check
```

**Example output:**

```bash
pid=12345 ppid=12344 uid=1000 euid=1000 gid=1000 egid=1000 cap_eff=0x0 cap_prm=0x0 seccomp=0 nonewprivs=0
```

### Output Format

Single-line key=value format, space-separated:

| Field | Description | Example Values |
|-------|-------------|----------------|
| `pid` | Process ID | `12345` |
| `ppid` | Parent Process ID | `12344` |
| `uid` | Real User ID | `1000` |
| `euid` | Effective User ID | `0` (root), `1000` (user) |
| `gid` | Real Group ID | `1000` |
| `egid` | Effective Group ID | `0` (root), `1000` (user) |
| `cap_eff` | Effective capability set (hex) | `0x0`, `0x3fffffffff` (full) |
| `cap_prm` | Permitted capability set (hex) | `0x0`, `0x3fffffffff` (full) |
| `seccomp` | Seccomp mode | `0` (disabled), `1` (strict), `2` (filter) |
| `nonewprivs` | No new privileges flag | `0` (disabled), `1` (enabled) |

### Deployment to Target System

**Option 1**: Copy binary directly

```bash
# From IR workstation
scp self-check incident-responder@target.example.com:/tmp/
```

```bash
# On target
chmod +x /tmp/self-check
/tmp/self-check
```

**Option 2**: Base64 encode for copy-paste

```bash
# On IR workstation
base64 self-check > self-check.b64
```

```Bash
# Copy self-check.b64 contents to clipboard
# Paste on target system, then:
base64 -d > /tmp/self-check
chmod +x /tmp/self-check
/tmp/self-check
```

**Option 3**: Hex dump for manual transmission

```bash
# If only terminal access available
xxd -p self-check | tr -d '\n' > self-check.hex
```

```bash
# On target (with xxd):
xxd -r -p > /tmp/self-check
# Paste hex, then Ctrl+D
chmod +x /tmp/self-check
/tmp/self-check
```

### Integrity Verification

Always verify integrity after transferring to target:

```bash
# On IR workstation (before transfer)
sha256sum self-check > self-check.sha256

# On target (after transfer)
sha256sum -c self-check.sha256
```

## Incident Response Use Cases

### 1. Container Escape Detection

**Scenario:** Suspected container escape to host namespace

**Technique:**

```bash
# Inside container
./self-check
# Expected: cap_eff=0x0 or limited capabilities, possible seccomp=2

# On host
./self-check
# Expected: cap_eff=0x3fffffffff (if root), seccomp=0

# Compare outputs - significant differences indicate escape or misconfiguration
```

**Red flags:**

- Container has full capabilities (`cap_eff=0x3fffffffff`)
- Container has `seccomp=0` when policy should be active
- Unexpected EUID=0 in container
- PID=1 but not in expected container init process

### 2. Privilege Escalation Analysis

**Scenario:** Investigating how attacker gained root

**Technique:**

```bash
# Run as compromised user
./self-check
# Note: uid, euid, gid, egid, capabilities

# Check for inconsistencies:
# - uid != euid → SUID binary or setuid() called
# - cap_eff != 0x0 for non-root → capability-based privilege
# - nonewprivs=0 → Can gain more privileges via execve
```

**Example analysis:**

```bash
pid=5678 ppid=5677 uid=1000 euid=0 gid=1000 egid=0 cap_eff=0x3fffffffff cap_prm=0x3fffffffff seccomp=0 nonewprivs=0
```

This shows:

- Real UID is 1000 (normal user)
- Effective UID is 0 (root)
- Full capabilities
- **Likely cause:** SUID binary or exploitation leading to setuid(0)

### 3. Sandbox Evasion Check

**Scenario:** Verifying sandbox/AppArmor/SELinux enforcement

**Technique:**

```bash
# Before deploying forensic tools, check restrictions
./self-check

# If seccomp=2 (filter mode):
# - System may restrict certain syscalls
# - Some forensic tools may fail unexpectedly

# If nonewprivs=1:
# - Cannot escalate privileges
# - SUID binaries won't work
# - Some memory analysis tools may fail
```

### 4. Initial Triage Baseline

**Scenario:** First execution on unknown system

**Checklist:**

```bash
# 1. Deploy and run
./self-check > /tmp/self-check.baseline

# 2. Verify expected values
# - EUID should match your access level (0 for root, >1000 for user)
# - Capabilities should be 0x0 for normal user, 0x3fffffffff for root
# - Seccomp should typically be 0 on non-containerized systems

# 3. Document anomalies
# - Unexpected capabilities for non-root user
# - Root process with seccomp enabled (unusual outside containers)
# - EUID=0 when you didn't log in as root

# 4. Compare with clean reference system
# If available, run self-check on known-good system with same config
```

### 5. Kernel Exploit Verification

**Scenario:** Suspected kernel vulnerability exploitation

**Technique:**

```bash
# Run self-check before and after suspected exploit
# Document capability changes

# Before:
# uid=1000 euid=1000 cap_eff=0x0 cap_prm=0x0

# After successful kernel exploit:
# uid=1000 euid=0 cap_eff=0x3fffffffff cap_prm=0x3fffffffff
# Note: UID unchanged but EUID escalated - classic kernel exploit pattern
```

## Interpreting Capabilities

Capability values are hexadecimal bitmasks. Common values:

| Value | Meaning | Context |
|-------|---------|---------|
| `0x0` | No capabilities | Normal unprivileged process |
| `0x3fffffffff` | All capabilities (Linux 5.x) | Root-equivalent access |
| `0xa80425fb` | Docker default | Typical container |
| `0x20000420` | Minimal set | CAP_NET_BIND_SERVICE, CAP_SETUID, CAP_SETGID |

**Decode capabilities:**

```bash
# On system with capsh available:
capsh --decode=0x3fffffffff

# Manual bit-by-bit analysis:
# See /usr/include/linux/capability.h for bit definitions
```

**Important capability bits:**

- Bit 0 (0x1): CAP_CHOWN
- Bit 7 (0x80): CAP_SETUID - Can change UID
- Bit 8 (0x100): CAP_SETGID - Can change GID
- Bit 21 (0x200000): CAP_SYS_ADMIN - Nearly root-equivalent
- Bit 31 (0x80000000): CAP_NET_RAW - Raw socket access

## Seccomp Modes

| Value | Mode | Description |
|-------|------|-------------|
| `0` | Disabled | No syscall filtering |
| `1` | Strict | Only read, write, exit, sigreturn allowed |
| `2` | Filter | Custom BPF filter active (common in containers) |

**Forensic implications:**

- `seccomp=0`: Full syscall access, no restrictions
- `seccomp=1`: Extremely rare, indicates very high security posture
- `seccomp=2`: Container or sandboxed environment, some forensic tools may fail

## Forensic Workflow Integration

### Timeline Collection

```bash
# Include self-check output in initial triage
echo "=== Environment Check ===" >> /tmp/ir-timeline.log
date -Iseconds >> /tmp/ir-timeline.log
./self-check >> /tmp/ir-timeline.log
echo "" >> /tmp/ir-timeline.log

# Then proceed with other tools
```

### Automated Checks

```bash
#!/bin/bash
# ir-baseline.sh - Quick environment check

OUTPUT=$(./self-check)

# Parse output
EUID=$(echo "$OUTPUT" | grep -oP 'euid=\K\d+')
CAP_EFF=$(echo "$OUTPUT" | grep -oP 'cap_eff=\K0x[0-9a-f]+')
SECCOMP=$(echo "$OUTPUT" | grep -oP 'seccomp=\K\d+')

# Check for anomalies
if [ "$EUID" = "0" ]; then
    echo "[*] Running as root (EUID=0)"
    if [ "$CAP_EFF" != "0x3fffffffff" ]; then
        echo "[!] WARNING: Root but capabilities restricted: $CAP_EFF"
    fi
else
    if [ "$CAP_EFF" != "0x0" ]; then
        echo "[!] WARNING: Non-root with capabilities: $CAP_EFF"
    fi
fi

if [ "$SECCOMP" != "0" ]; then
    echo "[!] WARNING: Seccomp active (mode=$SECCOMP) - some tools may fail"
fi
```

### Evidence Collection

```bash
# Include in evidence package
mkdir -p /tmp/ir-evidence/baseline
./self-check > /tmp/ir-evidence/baseline/self-check-output.txt
cp /proc/$$/status /tmp/ir-evidence/baseline/proc-self-status.txt
sha256sum self-check > /tmp/ir-evidence/baseline/self-check.sha256
```

## Limitations

**What self-check does NOT detect:**

- Namespaces (PID, mount, network, etc.) - Use `/proc/self/ns/*` checks
- Cgroups configuration - Use `/proc/self/cgroup`
- SELinux/AppArmor context - Use `id -Z` or `/proc/self/attr/current`
- Resource limits (ulimit) - Use `prlimit`
- File capabilities on the binary itself - Use `getcap`

**Known issues:**

- Capabilities shown are for the current process, not the binary's file capabilities
- Does not show capability bounding set (CapBnd) or ambient set (CapAmb)
- No namespace detection (use `lsns` or parse `/proc/self/ns/`)

## Troubleshooting

### Binary won't execute

```bash
# Check file permissions
ls -l self-check

# Make executable
chmod +x self-check

# Verify it's for correct architecture
file self-check
# Should show: ELF 64-bit LSB executable, x86-64

# Check if 32-bit compatibility libraries needed (shouldn't be)
ldd self-check
# Should show: not a dynamic executable
```

### Unexpected output

```bash
# Compare with /proc/self/status
./self-check
cat /proc/self/status | grep -E '(Pid|PPid|Uid|Gid|CapEff|CapPrm|Seccomp|NoNewPrivs)'

# Verify capabilities decoding
capsh --decode=$(./self-check | grep -oP 'cap_eff=\K0x[0-9a-f]+')
```

### Permission denied

```bash
# If deployed to /tmp but noexec mount option active:
mount | grep /tmp
# If contains "noexec", remount or use different location

# Use /dev/shm instead (usually executable)
cp self-check /dev/shm/
/dev/shm/self-check
```

## Security Considerations

### Running on Production Systems

- **Read-only operations**: self-check only reads `/proc/self/status`
- **No persistence**: Doesn't write files or modify system state
- **Minimal footprint**: Small binary, low memory usage
- **Safe to run**: Uses only standard syscalls (getpid, getuid, open, read, write)

### Rootkit Evasion

**Why self-check may bypass rootkits:**

1. **No libc dependency** - Cannot be subverted via LD_PRELOAD
2. **Raw syscalls** - Direct syscall instructions, not wrapped libc functions
3. **Small binary** - May not match detection signatures for common tools
4. **Reads /proc directly** - Harder to intercept than libc getters

**Limitations:**

- Kernel-level rootkits can still intercept syscalls
- `/proc` filesystem can be manipulated
- Results should be cross-validated with other techniques

### Integrity Protection

```bash
# Sign binary for deployment
gpg --detach-sign self-check

# Verify on target
gpg --verify self-check.sig self-check
```

## References

- **Linux capabilities**: `man 7 capabilities`
- **Seccomp**: `man 2 seccomp`
- **Proc filesystem**: `man 5 proc`
- **NoNewPrivs**: See `Documentation/prctl/no_new_privs.txt` in Linux kernel source

## Related Tools

After running self-check, consider:

- `lsns` - List namespaces
- `pscap` - Show capabilities of running processes
- `getpcaps` - Query process capabilities
- `prlimit` - Display resource limits
- `id -Z` - Show SELinux context
- `aa-status` - AppArmor status (if available)

---

**Version:** 0.1-minimal  
**Architecture:** x86-64 Linux  
**Last update:** 2025-11-09  
**License:** See repository LICENSE file
