# /proc/sys/kernel/ Security Parameters - Forensic Reference

This document provides comprehensive forensic analysis of security-critical kernel tunables in `/proc/sys/kernel/`, focusing on parameters most frequently abused by attackers for privilege escalation, persistence, and anti-forensics.

---

## Address Space Layout Randomization (ASLR)

### randomize_va_space

**Location:** `/proc/sys/kernel/randomize_va_space`

**Purpose:** Controls Address Space Layout Randomization (ASLR), a critical exploit mitigation that randomizes memory layout of processes.

**Values:**
- `0` - Disabled (no randomization)
- `1` - Conservative randomization (randomizes stack, shared libraries, mmap)
- `2` - Full randomization (includes heap) **[SECURE DEFAULT]**

**DFIR Focus:**

**Secure Baseline:** `2` (full ASLR)

**Attack Indicators:**
- Value `0` or `1` indicates ASLR weakening, common prerequisite for memory corruption exploits
- Attackers disable ASLR to achieve reliable exploitation with hardcoded memory addresses
- Often modified before privilege escalation attempts or kernel exploitation

**Detection Strategy:**
```bash
# Check current ASLR status
cat /proc/sys/kernel/randomize_va_space

# Check persistence mechanisms
grep -r "randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/
grep -r "randomize_va_space" /etc/rc.local /etc/init.d/
```

**Incident Response Guidance:**
- If value is 0 or 1, immediately investigate for active exploitation attempts
- Review audit logs for privilege escalation around time of modification
- Check `/proc/[pid]/maps` for processes with suspicious memory layouts
- Examine for concurrent exploitation artifacts (core dumps, suspicious processes)

**Hardening:**
```bash
# Set full ASLR
sysctl -w kernel.randomize_va_space=2

# Make persistent
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/99-security.conf
```

---

## Kernel Address Exposure

### kptr_restrict

**Location:** `/proc/sys/kernel/kptr_restrict`

**Purpose:** Controls whether kernel addresses are exposed via /proc and other interfaces.

**Values:**
- `0` - No restrictions (kernel addresses visible to all users)
- `1` - Kernel addresses hidden from unprivileged users **[SECURE DEFAULT]**
- `2` - Kernel addresses hidden from all users (even root)

**DFIR Focus:**

**Secure Baseline:** `1` or `2`

**Attack Indicators:**
- Value `0` enables kernel address leakage, critical for KASLR bypass
- Attackers set to 0 before kernel exploitation to identify kernel symbols
- Often modified in conjunction with `dmesg_restrict=0` for reconnaissance

**Detection Strategy:**
```bash
# Check kernel pointer restriction
cat /proc/sys/kernel/kptr_restrict

# Verify dmesg restrictions (related control)
cat /proc/sys/kernel/dmesg_restrict
```

**Incident Response Guidance:**
- Value of 0 strongly suggests kernel exploitation preparation or active exploitation
- Cross-reference with kernel module loading activity
- Review /var/log/kern.log for exploitation attempts
- Check for suspicious kernel modules or rootkit indicators

**Attack Scenario:**
1. Attacker sets `kptr_restrict=0`
2. Reads kernel addresses from `/proc/kallsyms` or `/proc/modules`
3. Uses addresses to bypass KASLR in kernel exploit
4. Achieves arbitrary kernel code execution

**Hardening:**
```bash
# Hide kernel addresses from unprivileged users
sysctl -w kernel.kptr_restrict=1

# Or hide from all users (maximum security)
sysctl -w kernel.kptr_restrict=2
```

---

### dmesg_restrict

**Location:** `/proc/sys/kernel/dmesg_restrict`

**Purpose:** Controls unprivileged access to kernel ring buffer (dmesg).

**Values:**
- `0` - Unrestricted dmesg access
- `1` - Restrict dmesg to CAP_SYSLOG capability **[SECURE DEFAULT]**

**DFIR Focus:**

**Secure Baseline:** `1`

**Attack Indicators:**
- Value `0` allows kernel information leakage to unprivileged users
- Kernel ring buffer may contain kernel addresses, module information, hardware details
- Often disabled during reconnaissance phase of kernel exploitation

**Detection Strategy:**
```bash
# Check dmesg restrictions
cat /proc/sys/kernel/dmesg_restrict

# Test access (as unprivileged user)
sudo -u nobody dmesg  # Should fail if restricted
```

**Incident Response Guidance:**
- Unrestricted dmesg access (value 0) suggests information gathering for kernel attacks
- Review dmesg output for kernel exploit attempts or crashes
- Correlate with `kptr_restrict` modifications
- Check for kernel oops messages indicating exploitation attempts

---

## Kernel Module Security

### modules_disabled

**Location:** `/proc/sys/kernel/modules_disabled`

**Purpose:** Completely disables loading of kernel modules. **One-way flag** - once set to 1, cannot be reset without reboot.

**Values:**
- `0` - Module loading allowed **[DEFAULT]**
- `1` - Module loading permanently disabled until reboot **[SECURE]**

**DFIR Focus:**

**Secure Baseline:** `1` (after boot-time modules loaded)

**Attack Indicators:**
- Value `0` on hardened systems may indicate reboot after compromise
- Attackers cannot set this to 0 once enabled, but may avoid hardened systems with this set
- Absence of this flag on security-focused systems is concerning

**Detection Strategy:**
```bash
# Check module loading status
cat /proc/sys/kernel/modules_disabled

# Verify when modules were last loaded
journalctl -k | grep -i module | tail -20
```

**Incident Response Guidance:**
- If expected to be 1 but found as 0, system may have been rebooted by attacker
- Check last boot time: `who -b` or `uptime`
- Review loaded modules: `lsmod` and compare against baseline
- Examine module load timestamps in journalctl

**Hardening:**
```bash
# Disable module loading (after boot completes and all needed modules loaded)
sysctl -w kernel.modules_disabled=1

# Note: This can be set via systemd service to activate after boot
```

**Important:** This is a one-way flag. Setting to 1 prevents loading of legitimate kernel modules (including forensic tools like lime) until reboot.

---

### modprobe

**Location:** `/proc/sys/kernel/modprobe`

**Purpose:** Path to the modprobe binary used by the kernel to load modules.

**Default Value:** `/sbin/modprobe`

**DFIR Focus:**

**Secure Baseline:** `/sbin/modprobe`

**Attack Indicators:**
- Modified path indicates potential persistence or privilege escalation mechanism
- Kernel executes this path with root privileges when auto-loading modules
- Classic privilege escalation vector via path hijacking

**Detection Strategy:**
```bash
# Check modprobe path
cat /proc/sys/kernel/modprobe

# Verify modprobe binary integrity
ls -la /sbin/modprobe
sha256sum /sbin/modprobe  # Compare against known-good hash
```

**Attack Scenario:**
1. Attacker writes malicious script to `/tmp/evil`
2. Sets `kernel.modprobe=/tmp/evil`
3. Triggers kernel module auto-load (e.g., uncommon network protocol)
4. Kernel executes `/tmp/evil` as root
5. Attacker achieves privilege escalation

**Incident Response Guidance:**
- ANY value other than `/sbin/modprobe` is highly suspicious
- Examine the file at the modified path for malicious content
- Review audit logs for writes to `/proc/sys/kernel/modprobe`
- Check for persistence in sysctl.conf or init scripts
- Investigate processes spawned shortly after module load attempts

**Hardening:**
```bash
# Ensure correct path
sysctl -w kernel.modprobe=/sbin/modprobe

# Better: Use modules_disabled=1 to prevent module loading entirely
```

---

## Core Dump Security

### core_pattern

**Location:** `/proc/sys/kernel/core_pattern`

**Purpose:** Defines template for core dump file naming or handler program.

**Default Value:** `core` or `|/usr/lib/systemd/systemd-coredump`

**DFIR Focus:**

**Secure Baseline:** `core` (simple file) or legitimate handler like systemd-coredump

**Attack Indicators:**
- Pipe character `|` followed by suspicious script path indicates potential persistence
- Core dumps trigger when processes crash, allowing attacker code execution
- Classic persistence and privilege escalation vector

**Detection Strategy:**
```bash
# Check core dump pattern
cat /proc/sys/kernel/core_pattern

# If piped, verify handler integrity
ls -la /path/to/handler
file /path/to/handler
strings /path/to/handler | grep -i suspicious
```

**Attack Scenario - Persistence:**
1. Attacker creates malicious handler: `/tmp/core_handler.sh`
2. Sets `core_pattern=|/tmp/core_handler.sh`
3. Malicious handler logs crashes but also establishes reverse shell
4. Every time any process crashes, attacker gains access

**Attack Scenario - Privilege Escalation:**
1. Attacker sets `core_pattern=|/tmp/privesc`
2. Causes SUID binary to crash (e.g., via malformed input)
3. Kernel executes handler with crashed process's privileges (including SUID root)
4. Handler runs as root, escalating attacker privileges

**Incident Response Guidance:**
- Pipe handlers (`|`) require immediate investigation
- Validate handler path and script contents
- Check sysctl persistence mechanisms
- Review recent core dumps: `coredumpctl list` or `/var/lib/systemd/coredump/`
- Examine auditd for writes to this path

**Hardening:**
```bash
# Use simple core file pattern (no piping)
sysctl -w kernel.core_pattern=core

# Or use trusted handler
sysctl -w kernel.core_pattern="|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h"

# Disable core dumps entirely on production systems
echo "* hard core 0" >> /etc/security/limits.conf
```

---

### core_uses_pid

**Location:** `/proc/sys/kernel/core_uses_pid`

**Purpose:** Appends PID to core dump filename.

**Values:**
- `0` - No PID in filename **[DEFAULT]**
- `1` - Append PID to filename

**DFIR Focus:**

**Secure Baseline:** `1` (prevents core file overwriting)

**Attack Indicators:**
- Value `0` can facilitate DoS by allowing core file overwriting
- Less critical than `core_pattern` but relevant for forensic preservation

---

### core_pipe_limit

**Location:** `/proc/sys/kernel/core_pipe_limit`

**Purpose:** Maximum number of concurrent piped core dump handlers.

**Default Value:** `0` (unlimited)

**DFIR Focus:**

**Secure Baseline:** Low value (e.g., 4) or 0 with legitimate handler

**Attack Indicators:**
- High value with piped `core_pattern` enables resource exhaustion
- Attacker can trigger multiple crashes to spawn many handler processes

---

## Debugging and Tracing Restrictions

### yama/ptrace_scope

**Location:** `/proc/sys/kernel/yama/ptrace_scope`

**Purpose:** Controls ptrace restrictions to prevent process debugging and injection.

**Values:**
- `0` - Classic ptrace permissions (any process with same UID can attach)
- `1` - Restricted ptrace (only parent processes can attach) **[SECURE DEFAULT]**
- `2` - Admin-only attach (CAP_SYS_PTRACE required)
- `3` - No attach allowed (complete lockdown)

**DFIR Focus:**

**Secure Baseline:** `1` or higher

**Attack Indicators:**
- Value `0` enables process injection and debugging attacks
- Common prerequisite for:
  - Process injection (T1055)
  - Credential dumping from memory
  - Code injection into running processes
  - Anti-debugging bypass

**Detection Strategy:**
```bash
# Check ptrace restrictions
cat /proc/sys/kernel/yama/ptrace_scope

# Monitor for ptrace syscalls in auditd
ausearch -sc ptrace -i
```

**Incident Response Guidance:**
- Value `0` strongly suggests preparation for process injection or memory scraping
- Review processes for unexpected parent-child relationships
- Check for credential dumping tools (mimipenguin, etc.)
- Examine memory of sensitive processes (sshd, sudo, password managers)
- Correlate with LD_PRELOAD or other injection indicators

**Attack Techniques Enabled by ptrace_scope=0:**
- **Process Injection:** Inject malicious code into legitimate processes
- **Credential Harvesting:** Dump passwords from memory of sudo, su, ssh
- **Rootkit Injection:** Inject kernel modules or eBPF programs via process memory
- **Anti-debugging Evasion:** Attach debugger to anti-analysis-aware malware

**Hardening:**
```bash
# Restrict to parent-only ptrace
sysctl -w kernel.yama.ptrace_scope=1

# Or require admin capabilities
sysctl -w kernel.yama.ptrace_scope=2
```

---

### perf_event_paranoid

**Location:** `/proc/sys/kernel/perf_event_paranoid`

**Purpose:** Controls access to performance monitoring events (perf subsystem).

**Values:**
- `-1` - Unrestricted access
- `0` - Disallow CPU event access by unprivileged users
- `1` - Disallow kernel profiling by unprivileged users **[DEFAULT]**
- `2` - Disallow all perf events for unprivileged users **[SECURE]**
- `3` - Disallow all perf events, even for CAP_PERFMON **[MAXIMUM SECURITY]**

**DFIR Focus:**

**Secure Baseline:** `2` or `3`

**Attack Indicators:**
- Lower values enable performance profiling, useful for:
  - Timing attacks against crypto implementations
  - Cache side-channel attacks (Spectre, Meltdown variants)
  - Kernel reconnaissance
- Value `-1` is extremely permissive and highly suspicious

**Detection Strategy:**
```bash
# Check perf event restrictions
cat /proc/sys/kernel/perf_event_paranoid

# Monitor perf command usage
ausearch -c perf -i
```

**Incident Response Guidance:**
- Permissive settings (< 2) may indicate side-channel attack preparation
- Review bash history for `perf` command usage
- Check for suspicious performance monitoring tools
- Examine for cryptographic attacks or VM escape attempts

**Hardening:**
```bash
# Restrict to privileged users only
sysctl -w kernel.perf_event_paranoid=3
```

---

### perf_cpu_time_max_percent

**Location:** `/proc/sys/kernel/perf_cpu_time_max_percent`

**Purpose:** Maximum CPU time percentage that perf sampling can consume.

**DFIR Focus:** Lower values (< 25) may indicate DoS mitigation or anti-profiling measures. Higher values enable performance profiling for reconnaissance.

---

### perf_event_max_sample_rate

**Location:** `/proc/sys/kernel/perf_event_max_sample_rate`

**Purpose:** Maximum sample rate for perf events.

**DFIR Focus:** Extremely high values may enable fine-grained performance attacks. Default is typically 100000.

---

## Kernel Execution Control

### kexec_load_disabled

**Location:** `/proc/sys/kernel/kexec_load_disabled`

**Purpose:** Prevents loading of new kernels via kexec (fast reboot mechanism).

**Values:**
- `0` - kexec allowed **[DEFAULT]**
- `1` - kexec disabled **[SECURE]**

**DFIR Focus:**

**Secure Baseline:** `1`

**Attack Indicators:**
- Value `0` on production systems may enable kernel replacement attacks
- kexec can bypass secure boot protections
- Used in advanced persistence mechanisms

**Detection Strategy:**
```bash
# Check kexec status
cat /proc/sys/kernel/kexec_load_disabled

# Review kexec usage
journalctl | grep -i kexec
```

**Incident Response Guidance:**
- Enabled kexec on hardened systems is suspicious
- Review for unauthorized kernel replacements
- Check boot logs for unexpected kexec operations
- Verify kernel integrity with UEFI Secure Boot measurements

---

## Namespace and Container Security

### unprivileged_userns_clone

**Location:** `/proc/sys/kernel/unprivileged_userns_clone`

**Purpose:** Controls whether unprivileged users can create user namespaces.

**Values:**
- `0` - Unprivileged user namespace creation disabled **[SECURE]**
- `1` - Unprivileged user namespace creation allowed **[DEFAULT on some distros]**

**DFIR Focus:**

**Secure Baseline:** `0` (unless containers required by unprivileged users)

**Attack Indicators:**
- Value `1` enables numerous privilege escalation vectors
- User namespaces allow unprivileged users to gain fake root privileges
- Common prerequisite for:
  - Container escape exploits
  - Namespace-based privilege escalation
  - Bypassing file permission checks

**Detection Strategy:**
```bash
# Check user namespace restrictions
cat /proc/sys/kernel/unprivileged_userns_clone

# Monitor namespace creation
ausearch -sc unshare -sc clone -i | grep -i namespace
```

**Incident Response Guidance:**
- Enabled unprivileged user namespaces significantly expand attack surface
- Review for unexpected container or namespace usage
- Check for namespace-based privilege escalation exploits (CVE-2022-0847 "Dirty Pipe", etc.)
- Examine processes in unusual namespaces: `lsns`

**Attack Techniques:**
- **Fake Root:** Create user namespace with UID 0 mapping
- **Capability Exploitation:** Gain capabilities within namespace to exploit kernel
- **Mount Namespace Abuse:** Remount filesystems with different permissions
- **Container Escape:** Break out of poorly configured containers

**Hardening:**
```bash
# Disable unprivileged user namespaces (if containers not needed)
sysctl -w kernel.unprivileged_userns_clone=0

# Note: This will break unprivileged container tools (Podman, etc.)
```

---

### user.max_user_namespaces

**Location:** `/proc/sys/user/max_user_namespaces`

**Purpose:** Maximum number of user namespaces per user.

**Default Value:** 31396 (varies by system)

**DFIR Focus:**

**Secure Baseline:** Low value or 0 (if containers not needed)

**Attack Indicators:**
- Extremely high values enable namespace exhaustion attacks
- Value 0 completely disables user namespaces (most secure for non-container systems)

**Hardening:**
```bash
# Disable user namespaces entirely
sysctl -w user.max_user_namespaces=0
```

---

## System Integrity and Lockdown

### lockdown

**Location:** `/sys/kernel/security/lockdown`

**Purpose:** Kernel lockdown mode restricting access to kernel memory and security-sensitive features.

**Values:**
- `[none]` - Lockdown disabled
- `[integrity]` - Integrity mode (prevents kernel memory modification)
- `[confidentiality]` - Confidentiality mode (maximum restrictions)

**DFIR Focus:**

**Secure Baseline:** `[integrity]` or `[confidentiality]`

**Attack Indicators:**
- `[none]` indicates no lockdown, allowing:
  - Direct kernel memory access via /dev/mem, /dev/kmem
  - Kernel module signature bypass
  - eBPF privilege escalation vectors
  - Hibernation image manipulation

**Detection Strategy:**
```bash
# Check lockdown status (if available)
cat /sys/kernel/security/lockdown

# Alternative location on some systems
cat /proc/sys/kernel/lockdown
```

**Incident Response Guidance:**
- Missing or disabled lockdown on UEFI Secure Boot systems is concerning
- Review for direct kernel memory access attempts
- Check for unsigned kernel module loads
- Examine eBPF program loading activity

---

## Message and Logging Controls

### printk

**Location:** `/proc/sys/kernel/printk`

**Purpose:** Controls console log levels for kernel messages.

**Format:** `<current> <default> <minimum> <boot-time-default>`

**DFIR Focus:** Attackers may suppress kernel messages by lowering log levels to hide exploitation artifacts. Monitor for changes from baseline.

---

### panic

**Location:** `/proc/sys/kernel/panic`

**Purpose:** Seconds to wait before rebooting after kernel panic (0 = never reboot).

**DFIR Focus:**

**Attack Indicators:**
- Value > 0 causes automatic reboot, destroying volatile evidence
- Attackers may set high value to clear memory after exploitation
- Value 0 preserves crash state for forensic analysis

**Hardening (Forensic Focus):**
```bash
# Preserve panic state for analysis
sysctl -w kernel.panic=0
```

---

### panic_on_oops

**Location:** `/proc/sys/kernel/panic_on_oops`

**Purpose:** Trigger kernel panic on oops (kernel error).

**Values:**
- `0` - Log oops but continue **[DEFAULT]**
- `1` - Panic on oops **[SECURE for critical systems]**

**DFIR Focus:**

**Secure Baseline:** `1` (fail-closed behavior)

**Attack Indicators:**
- Value `0` allows kernel to continue after exploitation attempts
- Some kernel exploits trigger oops as side effect; continuing execution helps attackers
- Value `1` causes crash, generating forensic evidence

---

## Process and Task Management

### pid_max

**Location:** `/proc/sys/kernel/pid_max`

**Purpose:** Maximum process ID value.

**Default Value:** 32768 or 4194304 (64-bit systems)

**DFIR Focus:**

**Attack Indicators:**
- Lowered values enable PID exhaustion DoS
- Raised values may indicate preparation for fork bomb or resource exhaustion

---

### threads-max

**Location:** `/proc/sys/kernel/threads-max`

**Purpose:** Maximum number of threads system-wide.

**DFIR Focus:**

**Attack Indicators:**
- Lowered values indicate potential resource exhaustion attack
- Extremely high values may facilitate fork bomb or threading DoS

---

## Filesystem and Execution Security

### suid_dumpable

**Location:** `/proc/sys/fs/suid_dumpable`

**Purpose:** Controls core dump creation for SUID/SGID processes.

**Values:**
- `0` - Disable core dumps for setuid processes **[SECURE]**
- `1` - Enable core dumps (traditional unsafe behavior)
- `2` - Enable core dumps readable only by root

**DFIR Focus:**

**Secure Baseline:** `0` or `2`

**Attack Indicators:**
- Value `1` allows unprivileged users to dump SUID process memory
- Classic information disclosure vector
- May reveal credentials or cryptographic keys from privileged processes

**Hardening:**
```bash
# Disable SUID core dumps
sysctl -w fs.suid_dumpable=0
```

---

## Incident Response Checklist

### Rapid Triage Commands
```bash
# Collect all security-critical kernel parameters
cat /proc/sys/kernel/randomize_va_space
cat /proc/sys/kernel/kptr_restrict
cat /proc/sys/kernel/dmesg_restrict
cat /proc/sys/kernel/modules_disabled
cat /proc/sys/kernel/modprobe
cat /proc/sys/kernel/core_pattern
cat /proc/sys/kernel/yama/ptrace_scope
cat /proc/sys/kernel/perf_event_paranoid
cat /proc/sys/kernel/kexec_load_disabled
cat /proc/sys/kernel/unprivileged_userns_clone

# Generate comprehensive snapshot
sysctl -a | grep -E 'kernel\.(randomize|kptr|dmesg|modules|modprobe|core_|yama|perf_|kexec|unprivileged)' > /tmp/kernel_security_audit.txt
```

### Persistence Check
```bash
# Check sysctl persistence mechanisms
cat /etc/sysctl.conf
ls -la /etc/sysctl.d/
grep -r "kernel\." /etc/sysctl.conf /etc/sysctl.d/

# Check init scripts for sysctl modifications
grep -r "sysctl" /etc/rc.local /etc/init.d/ /etc/systemd/system/
```

### Baseline Comparison
```bash
# Generate current state
sysctl -a | sort > /tmp/current_sysctl.txt

# Compare against known-good baseline
diff /path/to/baseline/sysctl.txt /tmp/current_sysctl.txt | grep kernel
```

---

## Attack Scenario Matrix

| Attack Type | Modified Parameter | Indicator Value | Follow-up Investigation |
|-------------|-------------------|----------------|-------------------------|
| Kernel Exploitation Prep | `randomize_va_space` | 0 or 1 | Memory forensics, exploit artifacts |
| KASLR Bypass | `kptr_restrict` | 0 | /proc/kallsyms access, exploitation tools |
| Rootkit Installation | `modules_disabled` | 0 (unexpected) | Module list comparison, kernel integrity |
| Privilege Escalation | `modprobe` | Non-standard path | Examine modprobe replacement, spawned processes |
| Persistence via Crash | `core_pattern` | Piped to script | Handler script analysis, core dump review |
| Process Injection | `yama.ptrace_scope` | 0 | Memory dumps, ptrace syscalls in audit logs |
| Side-Channel Attacks | `perf_event_paranoid` | -1 or 0 | Perf command history, crypto timing attacks |
| User Namespace Exploit | `unprivileged_userns_clone` | 1 | Namespace enumeration, container escapes |
| Anti-Forensics | `dmesg_restrict` | 0 | Information gathering, kernel exploit prep |

---

## References

- Linux Kernel Documentation: `/Documentation/admin-guide/sysctl/`
- CIS Benchmarks for Linux
- MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation), T1014 (Rootkit)
- NIST SP 800-53: SI-16 (Memory Protection)

---

**Part of FOR577 Additional Information**
These materials support SANS FOR577: Linux Incident Response and Threat Hunting.
Visit [https://sans.org/for577](https://sans.org/for577) for comprehensive Linux IR training.
