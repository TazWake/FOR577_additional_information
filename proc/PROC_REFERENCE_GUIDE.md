# Linux /proc Filesystem - Complete DFIR Reference Guide

## Purpose

This is the comprehensive reference guide for Linux `/proc` filesystem forensics, providing both quick-reference tables and detailed analysis for incident response and threat hunting.

**Use this guide when:**
- Performing live system triage and forensic data collection
- Investigating suspicious processes or system behavior
- Hunting for rootkits, persistence mechanisms, or privilege escalation
- Understanding kernel tunables that impact system security

## Table of Contents

- [Quick Reference](#quick-reference)
  - [System-Wide Files Quick Reference](#system-wide-files-quick-reference)
  - [Per-Process Files Quick Reference](#per-process-files-quick-reference)
  - [Kernel Tunables Quick Reference](#kernel-tunables-quick-reference)
- [Detailed References](#detailed-references)
  - [System-Wide Files and Directories](#system-wide-files-and-directories-detailed)
  - [Per-Process Directories](#per-process-directories-detailed)
  - [Kernel Tunables (proc/sys)](#kernel-tunables-procsys-detailed)
- [Practical DFIR Guidance](#practical-dfir-guidance)
- [Glossary](#glossary)

---

## Quick Reference

These tables provide rapid lookup for IR practitioners who need immediate context during live response.

### System-Wide Files Quick Reference

The `/proc` filesystem exposes kernel and process information. Reading from `/proc` does not alter system state.

| Entry | Summary | DFIR Focus |
|--------|----------|------------|
| **acpi** | Power and thermal management data. | Check for abnormal power or thermal events that correlate with tampering. |
| **asound** | ALSA sound subsystem configuration. | Review for microphone activation or data capture. |
| **bootconfig** | Kernel boot configuration parameters. | Verify for altered boot options or injected init processes. |
| **buddyinfo** | Memory fragmentation data. | Monitor for unusual fragmentation (indicative of memory exhaustion or miners). |
| **bus** | Hardware bus information (PCI, USB, etc.). | Identify rogue or virtualised devices. |
| **cgroups** | Resource control group hierarchy. | Detect hidden or malicious cgroups. |
| **cmdline** | Kernel boot parameters. | Look for `selinux=0` or `init=/bin/bash`. |
| **consoles** | Active system consoles. | Detect unauthorised console access. |
| **cpuinfo** | CPU information and flags. | Confirm hardware identity; watch for VM evasion. |
| **crypto** | Kernel crypto API status. | Look for non-standard algorithms or user-injected modules. |
| **devices** | Registered character/block devices. | Identify unusual device drivers or virtual volumes. |
| **diskstats** | Disk I/O statistics. | Detect high I/O linked to wiping or exfiltration. |
| **dma** | Direct Memory Access usage. | Inspect for abnormal DMA controllers. |
| **driver** | Kernel driver info. | Identify unknown or modified driver entries. |
| **dynamic_debug** | Controls for kernel debugging. | Verify debugging not enabled by attackers. |
| **execdomains** | Execution domain list. | Detect unauthorised ABI or emulation modes. |
| **fb** | Framebuffer data. | Limited value; can confirm GUI sessions. |
| **filesystems** | Supported filesystem types. | Identify added encrypted or FUSE filesystems. |
| **fs** | Filesystem driver data. | Detect stealth mounts or pseudo-filesystems. |
| **interrupts** | IRQ usage statistics. | Monitor excessive IRQ activity (malware or miners). |
| **iomem** | Memory-mapped device regions. | Look for unknown mappings (rootkits). |
| **ioports** | I/O port assignments. | Check for abnormal allocations. |
| **irq** | IRQ subsystem details. | Cross-check for missing or hijacked handlers. |
| **kallsyms** | Kernel symbol table. | Compare against baseline to detect rootkit symbol hiding. |
| **kcore** | Kernel memory image. | Can be memory-dumped for volatile forensics. |
| **keys** | Kernel keyrings. | Inspect for unauthorised key storage. |
| **key-users** | Keyring usage by users. | Identify privileged key holders. |
| **kmsg** | Kernel message buffer. | Examine boot and module load events. |
| **kpagecgroup** | Page-to-cgroup mapping. | Useful for advanced memory analysis. |
| **kpagecount** | Physical page reference counts. | Identify hidden persistent pages. |
| **kpageflags** | Per-page memory flags. | Spot executable pages in unexpected areas. |
| **loadavg** | System load averages. | Identify sustained high load (crypto-mining). |
| **locks** | File locks currently held. | Detect locked files blocking forensic access. |
| **mdstat** | Software RAID status. | Verify against tampering or hidden drives. |
| **meminfo** | Memory usage statistics. | Identify leaks or manipulated cache. |
| **misc** | Miscellaneous registered devices. | Watch for unknown minor devices. |
| **modules** | Loaded kernel modules. | Key forensic check for rootkits or unsigned modules. |
| **mounts** | Active filesystem mounts. | Identify deleted, hidden, or overlay mounts. |
| **mpt** | Message Passing Tech (storage). | Rarely relevant unless driver abuse suspected. |
| **mtrr** | Memory type range registers. | Inspect for firmware-level tampering. |
| **net** | Networking subsystem info. | Review active sockets, routing, and interfaces. |
| **pagetypeinfo** | Memory allocation types. | Low-level memory forensics. |
| **partitions** | Detected block partitions. | Detect hidden partitions. |
| **pressure** | CPU/memory/I/O pressure stats. | High pressure may indicate abusive workloads. |
| **schedstat** | Kernel scheduling stats. | Compare CPU time vs visible processes. |
| **scsi** | Attached SCSI devices. | Identify rogue storage. |
| **self** | Symlink to the current process. | Useful for scripts. |
| **slabinfo** | Kernel memory allocator stats. | Detect leaks or abnormal cache use. |
| **softirqs** | Soft interrupt counts. | Identify packet-processing abuse or DoS. |
| **stat** | Global CPU/system counters. | Detect excessive context switching. |
| **swaps** | Swap usage and devices. | Check for cleared swap areas. |
| **sys** | Kernel sysctl tunables (mirror of `/sys`). | Audit for weakened parameters. |
| **sysrq-trigger** | Allows triggering SysRq commands. | Dangerous; check permissions. |
| **sysvipc** | System V IPC resources. | Detect inter-process communication channels. |
| **thread-self** | Symlink to current thread. | Script utility, not forensic. |
| **timer_list** | Active kernel timers. | Detect periodic callbacks used by malware. |
| **tty** | Terminal devices. | Find hidden or injected TTYs. |
| **uptime** | System uptime and idle time. | Correlate compromise timeline. |
| **version** | Kernel version string. | Validate kernel build integrity. |
| **version_signature** | Distro-specific kernel signature. | Detect tampered kernel packages. |
| **vmallocinfo** | Kernel virtual memory allocations. | Identify suspicious memory usage. |
| **vmstat** | Virtual memory stats. | Detect abnormal paging. |
| **zoneinfo** | Memory zone allocation. | Used in deep kernel memory analysis. |

### Per-Process Files Quick Reference

Each process has a directory `/proc/[pid]/` containing detailed runtime information.

| Entry | Summary | DFIR Focus |
|--------|----------|------------|
| **arch_status** | Architecture-specific process data. | Check execution modes or hardware anomalies. |
| **attr** | Security attributes (SELinux, LSM). | Identify context manipulation for stealth. |
| **autogroup** | Scheduler group data. | Look for manipulated CPU prioritisation. |
| **auxv** | ELF auxiliary vector. | Detect exploit artefacts or injected values. |
| **cgroup** | Process control group membership. | Identify containerisation or isolation. |
| **clear_refs** | Clears memory reference bits. | Tampering may disrupt analysis. |
| **cmdline** | Process command-line arguments. | Inspect for encoded or suspicious commands. |
| **comm** | Short process name. | Compare against `cmdline` for masquerading. |
| **coredump_filter** | Core dump inclusion mask. | Modified to hide memory contents. |
| **cpu_resctrl_groups** | CPU resource control group. | Rarely relevant; anomalies hint at sandbox evasion. |
| **cpuset** | CPU affinity. | Restricted cores may indicate stealth. |
| **cwd** | Current working directory. | Check for deleted or hidden paths. |
| **environ** | Process environment variables. | Review for malicious variables (LD_PRELOAD). |
| **exe** | Symlink to the executable binary. | Confirm it exists; deleted = suspicious. |
| **fd/** | File descriptors in use. | Identify open deleted files or network sockets. |
| **fdinfo/** | Per-descriptor details. | Correlate with open file or socket usage. |
| **gid_map** | Group ID namespace mapping. | Detect privilege escalation within namespaces. |
| **io** | I/O statistics. | High I/O may imply exfiltration or logging. |
| **limits** | Resource limits. | Check for disabled core dumps (anti-forensics). |
| **loginuid** | User ID for audit purposes. | Manipulated to anonymise attacker activity. |
| **map_files/** | File-backed memory mappings. | Detect deleted or injected library mappings. |
| **maps** | Virtual memory layout. | Identify injected code or shellcode regions. |
| **mem** | Process memory space. | Extract for live analysis. |
| **mountinfo** | Mounts visible to the process. | Spot isolated namespaces or hidden mounts. |
| **mounts** | Simplified view of mounts. | Cross-validate visibility. |
| **mountstats** | Per-mount I/O statistics. | Reveal abnormal activity against specific mounts. |
| **net/** | Network connections and stats. | Detect active sockets or backdoors. |
| **ns/** | Namespace references. | Identify isolation or container escapes. |
| **numa_maps** | NUMA memory allocation. | Anomalies signal memory locality manipulation. |
| **oom_adj** | Deprecated OOM adjustment. | Low values prevent termination (persistence). |
| **oom_score** | OOM score for the process. | Cross-reference with oom_adj for persistence tactics. |
| **oom_score_adj** | Modern OOM interface. | Low scores indicate persistence tactics. |
| **pagemap** | Virtual-to-physical mapping. | Identify shared memory between processes. |
| **patch_state** | Live kernel patching state. | Indicates kernel live patching - verify legitimacy. |
| **personality** | Process execution domain flags. | Abnormal flags = exploitation. |
| **projid_map** | Project ID mapping. | Identify filesystem mapping manipulation. |
| **root** | Process root directory. | Detect chrooted or deleted roots. |
| **sched** | Process scheduling stats. | Identify CPU abuse or stealth tasks. |
| **schedstat** | Scheduling performance summary. | Detect excessive runtime vs. visibility. |
| **sessionid** | Process session identifier. | Group related attack processes. |
| **setgroups** | Controls setgroups() in namespaces. | Used in privilege-escalation exploits. |
| **smaps** | Memory allocation details. | Locate injected regions or leaks. |
| **smaps_rollup** | Aggregated memory statistics. | Detect total footprint of suspicious activity. |
| **stack** | Kernel stack trace. | Detect injected threads or kernel calls. |
| **stat** | Process statistics (PID, state, CPU). | Identify zombies or abnormal CPU use. |
| **statm** | Memory usage metrics. | Unusually high memory suggests injection. |
| **status** | Readable summary (UIDs, GIDs, state). | Validate privileges and capabilities. |
| **syscall** | Current system call and args. | Live inspection during compromise. |
| **task/** | Thread list. | Identify hidden or injected threads. |
| **timens_offsets** | Time namespace offsets. | Attackers manipulate to evade correlation. |
| **timers** | Active kernel timers. | Identify persistent background actions. |
| **timerslack_ns** | Timer slack (precision). | Modified for timing manipulation. |
| **uid_map** | User ID namespace mapping. | Used in containerisation or privilege abuse. |
| **wchan** | Kernel wait channel. | Detect processes waiting in unusual states. |

### Kernel Tunables Quick Reference

`/proc/sys/` holds kernel parameters configurable at runtime. Changes significantly alter system security or stability.

| Path | Summary | DFIR Focus |
|-------|----------|------------|
| **/proc/sys/abi** | ABI compatibility settings. | Detect legacy execution modes aiding exploits. |
| **/proc/sys/debug** | Kernel debugging controls. | Ensure debug options are not enabled. |
| **/proc/sys/dev** | Device-specific tunables. | Inspect `/dev/random` and entropy settings. |
| **/proc/sys/fs** | Filesystem security & behaviour. | Check `protected_symlinks`, `suid_dumpable`, etc. |
| **/proc/sys/kernel** | Core kernel behaviour. | Validate `core_pattern`, `modules_disabled`, ASLR, ptrace. |
| **/proc/sys/net** | Network stack configuration. | Review `ip_forward`, redirects, conntrack, IPv6 settings. |
| **/proc/sys/sunrpc** | RPC/NFS parameters. | Identify lateral movement or persistence via RPC. |
| **/proc/sys/user** | User namespace settings. | Ensure `max_user_namespaces` not excessive. |
| **/proc/sys/vm** | Virtual memory management. | Detect cache clearing, overcommit, or swap tampering. |
| **/proc/sysrq-trigger** | Manual SysRq control. | Writable access = severe compromise indicator. |
| **/proc/sys/crypto** | Kernel crypto API. | Confirm only standard algorithms present. |
| **/proc/sys/vfs** | Virtual filesystem caching. | Check manipulation of file metadata behaviour. |

**For detailed kernel tunable analysis, see:**
- **[../sys/kernel_security_parameters.md](../sys/kernel_security_parameters.md)** - Deep dive into `/proc/sys/kernel/` with attack scenarios and hardening guidance
- **[../sys/network_security_parameters.md](../sys/network_security_parameters.md)** - Deep dive into `/proc/sys/net/` for network security forensics

---

## Detailed References

### System-Wide Files and Directories (Detailed)

The quick reference table above covers all major system-wide `/proc` entries. For most DFIR purposes, the table provides sufficient context. Key entries to always examine:

**Critical Forensic Targets:**
- `/proc/modules` - Loaded kernel modules (rootkit detection)
- `/proc/mounts` - Active filesystems (hidden mounts, overlays)
- `/proc/net/tcp` and `/proc/net/udp` - Network connections
- `/proc/kallsyms` - Kernel symbol table (compare against baseline)
- `/proc/cmdline` - Kernel boot parameters (tampering detection)
- `/proc/version` - Kernel version verification

**Common DFIR Commands:**
```bash
# Capture loaded kernel modules
cat /proc/modules > modules_snapshot.txt
lsmod > lsmod_output.txt

# Identify active mounts
cat /proc/mounts > mounts_snapshot.txt

# Network connection enumeration
cat /proc/net/tcp > tcp_connections.txt
cat /proc/net/udp > udp_connections.txt

# Kernel symbol baseline
cat /proc/kallsyms > kallsyms_snapshot.txt
```

### Per-Process Directories (Detailed)

Each entry in the quick reference table above has specific forensic value. Below are expanded details for high-value artifacts:

#### arch_status

- **Location:** `/proc/[pid]/arch_status`
- **Summary:** Contains architecture-specific process state information (e.g., for ARM or x86).
- **DFIR Focus:** Check for unusual architecture flags or execution modes (e.g., hardware-assisted code execution anomalies).
- **When to examine:** Investigating exploitation on multi-architecture systems or unusual CPU features.

#### attr

- **Location:** `/proc/[pid]/attr`
- **Summary:** Holds security attributes used by SELinux and related LSMs (Linux Security Modules).
- **Contents:** Subdirectories/files like `current`, `exec`, `fscreate` containing SELinux contexts.
- **DFIR Focus:**
  - Examine for manipulated SELinux contexts that might hide processes or files
  - Check if processes are running in permissive mode when system is enforcing
  - Look for context transitions that enable privilege escalation
- **Common checks:**
  ```bash
  cat /proc/[pid]/attr/current  # Current SELinux context
  cat /proc/[pid]/attr/exec     # Context for next exec
  ```

#### autogroup

- **Location:** `/proc/[pid]/autogroup`
- **Summary:** Shows scheduling group information for processes under automatic task grouping.
- **DFIR Focus:** Identify performance manipulation (e.g., CPU scheduling bias used to prioritise malicious tasks).
- **Attack scenario:** Malware may adjust nice values or scheduling to remain hidden while maintaining CPU access.

#### auxv

- **Location:** `/proc/[pid]/auxv`
- **Summary:** Lists ELF auxiliary vector data passed to the process at startup.
- **Contents:** Binary data with environment information from kernel to userspace (AT_PLATFORM, AT_RANDOM, etc.).
- **DFIR Focus:**
  - Review for abnormal entries that could indicate exploitation or memory corruption attempts
  - Verify AT_RANDOM (entropy source for ASLR)
  - Check AT_SECURE flag for setuid/setgid execution
- **Analysis:** Requires parsing with hexdump or specialized tools.

#### cgroup

- **Location:** `/proc/[pid]/cgroup`
- **Summary:** Displays control group membership for the process.
- **DFIR Focus:**
  - Determine if malware isolates itself within unexpected cgroups
  - Useful in container forensics to identify escape attempts
  - Look for resource limit evasion (CPU, memory quotas)
- **Example output:**
  ```
  12:pids:/user.slice/user-1000.slice
  11:cpuset:/
  ```

#### clear_refs

- **Location:** `/proc/[pid]/clear_refs`
- **Summary:** Write-only interface to clear referenced memory bits for the process.
- **DFIR Focus:**
  - Check for tampering attempts
  - Attackers may reset this to manipulate memory analysis tools
  - Rarely examined directly, but write access indicates privilege

#### cmdline

- **Location:** `/proc/[pid]/cmdline`
- **Summary:** Shows the command-line arguments used to start the process (null-separated).
- **DFIR Focus:**
  - **PRIMARY TRIAGE ARTIFACT** - Always examine during process analysis
  - Inspect for suspicious parameters, encoded commands, or script execution
  - Look for:
    - Base64-encoded payloads
    - Obfuscated scripts (bash -c "$(echo ...)")
    - Unusual interpreter invocations
    - Suspicious network destinations in args
- **Common check:**
  ```bash
  cat /proc/[pid]/cmdline | tr '\0' ' '
  ```

#### comm

- **Location:** `/proc/[pid]/comm`
- **Summary:** Contains the process's short name (comm field in task_struct), limited to 16 characters.
- **DFIR Focus:**
  - **CRITICAL:** Validate against `/proc/[pid]/cmdline` for mismatches
  - Common indicator of process masquerading (malware pretending to be legitimate process)
  - Example: `comm` shows "sshd" but `cmdline` shows "/tmp/.hidden/backdoor"
- **Detection pattern:**
  ```bash
  # Check for mismatches
  for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    comm=$(cat /proc/$pid/comm 2>/dev/null)
    cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
    exe=$(readlink /proc/$pid/exe 2>/dev/null)
    echo "PID $pid: comm=$comm | exe=$exe"
  done
  ```

#### coredump_filter

- **Location:** `/proc/[pid]/coredump_filter`
- **Summary:** Specifies which memory mappings are included in a core dump (bitmask).
- **DFIR Focus:**
  - Look for modified filters designed to exclude incriminating data from dumps
  - Default value varies; attackers may set to 0 to prevent forensic core dump analysis
- **Bitmask values:**
  - Bit 0: anonymous private mappings
  - Bit 1: anonymous shared mappings
  - Bit 2: file-backed private mappings
  - Bit 3: file-backed shared mappings

#### cpu_resctrl_groups

- **Location:** `/proc/[pid]/cpu_resctrl_groups`
- **Summary:** Displays CPU resource control group information (Intel RDT).
- **DFIR Focus:** Rarely relevant; anomalies may hint at performance tuning or sandbox evasion.

#### cpuset

- **Location:** `/proc/[pid]/cpuset`
- **Summary:** Indicates which CPUs the process is allowed to execute on.
- **DFIR Focus:**
  - Restriction to specific cores could suggest stealth tactics (avoiding monitoring CPUs)
  - May indicate containerization or resource isolation
- **Example:** `/docker/abc123` indicates Docker container

#### cwd

- **Location:** `/proc/[pid]/cwd`
- **Summary:** Symlink to the current working directory.
- **DFIR Focus:**
  - **HIGH VALUE ARTIFACT** - Useful for locating execution context
  - Check for deleted or unexpected paths
  - Look for execution from volatile directories (/tmp, /dev/shm, /var/tmp)
  - Deleted paths show as "(deleted)" suffix
- **Common check:**
  ```bash
  readlink /proc/[pid]/cwd
  ```

#### environ

- **Location:** `/proc/[pid]/environ`
- **Summary:** Lists the process's environment variables (null-separated).
- **DFIR Focus:**
  - **CRITICAL FORENSIC ARTIFACT**
  - Inspect for malicious variables:
    - **LD_PRELOAD** - Shared library injection
    - **LD_LIBRARY_PATH** - Library search path manipulation
    - **SSH_AUTH_SOCK** - SSH agent hijacking
    - **HISTFILE=/dev/null** - Anti-forensics
    - Unusual PATH modifications
  - Review for credentials or API keys (poor security practice but common)
- **Analysis:**
  ```bash
  cat /proc/[pid]/environ | tr '\0' '\n' | grep -E 'LD_|PATH|SSH_|HIST'
  ```

#### exe

- **Location:** `/proc/[pid]/exe`
- **Summary:** Symlink to the executable binary being run.
- **DFIR Focus:**
  - **PRIMARY TRIAGE ARTIFACT**
  - Confirm whether it points to a valid file
  - Deleted or replaced executables are high-risk indicators
  - Shows "(deleted)" if binary removed from disk (common malware technique)
  - Compare against expected paths for process name
- **Common checks:**
  ```bash
  readlink /proc/[pid]/exe
  ls -la /proc/[pid]/exe
  ```

#### fd/

- **Location:** `/proc/[pid]/fd/`
- **Summary:** Directory of file descriptors opened by the process (symlinks to actual resources).
- **DFIR Focus:**
  - **CRITICAL FOR NETWORK/FILE ANALYSIS**
  - Examine for:
    - Deleted files still held open (data recovery opportunity)
    - Sockets (network connections)
    - Pipes (IPC channels)
    - Unusual devices
  - Files deleted from disk but still accessible here
- **Common enumeration:**
  ```bash
  ls -la /proc/[pid]/fd/
  # Look for "(deleted)" entries
  ls -la /proc/[pid]/fd/ | grep deleted
  ```

#### fdinfo/

- **Location:** `/proc/[pid]/fdinfo/`
- **Summary:** Provides detailed information about each open file descriptor.
- **DFIR Focus:**
  - Correlate with `fd/` to determine how descriptors are used
  - Shows file position, flags, and mount ID
  - Useful for network socket details
- **Example:**
  ```bash
  cat /proc/[pid]/fdinfo/3
  # Shows: pos, flags, mnt_id for fd 3
  ```

#### gid_map

- **Location:** `/proc/[pid]/gid_map`
- **Summary:** Shows group ID mapping for user namespaces.
- **DFIR Focus:**
  - Check for namespace isolation used by containers
  - Privilege escalation exploits manipulate GID mappings
  - Look for unexpected mappings (e.g., 0→1000 mapping root to user)
- **Related to:** Container forensics, CVE-2016-3134 class vulnerabilities

#### io

- **Location:** `/proc/[pid]/io`
- **Summary:** Displays I/O statistics (bytes read/written, syscalls).
- **DFIR Focus:**
  - Identify high I/O activity from unexpected processes
  - Data theft indicators: high read_bytes from sensitive directories
  - Keylogging indicators: constant write activity
  - Exfiltration indicators: disproportionate write_bytes
- **Metrics:**
  ```
  rchar:  characters read
  wchar:  characters written
  read_bytes:  bytes read from storage
  write_bytes: bytes written to storage
  ```

#### limits

- **Location:** `/proc/[pid]/limits`
- **Summary:** Shows resource limits (ulimits) applied to the process.
- **DFIR Focus:**
  - Altered limits (e.g., core dumps disabled) indicate anti-forensics measures
  - Check for:
    - `Max core file size: 0` (prevents core dumps)
    - `Max open files` (unusually high may indicate scanning/exploitation)
    - `Max processes` (privilege/DoS implications)
- **Example:**
  ```bash
  cat /proc/[pid]/limits
  ```

#### loginuid

- **Location:** `/proc/[pid]/loginuid`
- **Summary:** Contains the login UID tied to auditd (immutable after setting).
- **DFIR Focus:**
  - Verify whether attackers reset or anonymised this to hide session ownership
  - Value of 4294967295 (unset) or unexpected UID indicates manipulation
  - Critical for audit trail correlation
- **Expected:** Should match actual login UID for session

#### map_files/

- **Location:** `/proc/[pid]/map_files/`
- **Summary:** Contains symlinks to file-backed memory regions (address-range named).
- **DFIR Focus:**
  - Look for deleted files or suspicious libraries mapped into memory
  - Recovery of deleted executables still in memory
  - Identify injected libraries
- **Requires:** CAP_SYS_ADMIN or same UID
- **Example:**
  ```bash
  ls -la /proc/[pid]/map_files/
  # Shows: 7f1234000-7f1235000 -> /lib/x86_64-linux-gnu/libc.so.6
  ```

#### maps

- **Location:** `/proc/[pid]/maps`
- **Summary:** Displays memory regions and permissions of the process.
- **DFIR Focus:**
  - **CRITICAL FOR MEMORY FORENSICS**
  - Identify:
    - Injected libraries (unexpected .so files)
    - Writable/executable regions (rwx permissions - RED FLAG)
    - Code caves or gaps used for shellcode
    - Anonymous executable pages (heap spraying, JIT)
    - Deleted library mappings
- **Analysis:**
  ```bash
  cat /proc/[pid]/maps | grep -E '(rwx|---x.*\(deleted\))'
  ```

#### mem

- **Location:** `/proc/[pid]/mem`
- **Summary:** Pseudo-file to access the process's memory (requires ptrace permissions).
- **DFIR Focus:**
  - Can be dumped for live-memory analysis
  - YARA scanning of process memory
  - Extract strings for credentials or indicators
  - Requires careful handling (active process memory)
- **Tools:** gcore, volatility, or custom scripts with /proc/[pid]/maps

#### mountinfo

- **Location:** `/proc/[pid]/mountinfo`
- **Summary:** Shows detailed mount information for the process's namespace.
- **DFIR Focus:**
  - Detect hidden mounts or chroot environments used for persistence
  - Identify mount namespaces (containerization)
  - Look for overlay filesystems or bind mounts
- **More detailed than:** `/proc/[pid]/mounts`

#### mounts

- **Location:** `/proc/[pid]/mounts`
- **Summary:** Simplified list of mounted filesystems visible to the process.
- **DFIR Focus:**
  - Cross-check against `/proc/mounts` for namespace manipulation
  - Identify process-specific mount namespaces
  - Look for tmpfs mounts in unusual locations

#### mountstats

- **Location:** `/proc/[pid]/mountstats`
- **Summary:** Provides per-mount I/O statistics.
- **DFIR Focus:** May reveal abnormal activity against specific mounts (e.g., data staging areas on tmpfs).

#### net/

- **Location:** `/proc/[pid]/net/`
- **Summary:** Network-related information (sockets, connections, routing, stats).
- **DFIR Focus:**
  - **CRITICAL FOR NETWORK FORENSICS**
  - Investigate for:
    - Unusual connections (`tcp`, `udp`, `unix`)
    - Listening ports tied to the process
    - Raw sockets (packet crafting)
  - Process-specific view vs. system-wide `/proc/net/`

#### ns/

- **Location:** `/proc/[pid]/ns/`
- **Summary:** Contains namespace symlinks (mnt, pid, net, user, uts, ipc, cgroup, time).
- **DFIR Focus:**
  - **CRITICAL FOR CONTAINER FORENSICS**
  - Identify isolated namespaces common in:
    - Container escapes
    - Rootkit techniques
    - Privilege escalation
  - Compare namespace IDs between processes to identify isolation
- **Example:**
  ```bash
  ls -la /proc/[pid]/ns/
  # Different inode numbers = different namespaces
  ```

#### numa_maps

- **Location:** `/proc/[pid]/numa_maps`
- **Summary:** Shows NUMA (Non-Uniform Memory Access) memory allocation for the process.
- **DFIR Focus:** Rarely relevant; anomalies may signal attempts to manipulate memory locality for evasion.

#### oom_adj / oom_score / oom_score_adj

- **Location:** `/proc/[pid]/oom_adj` (deprecated), `/proc/[pid]/oom_score_adj` (modern)
- **Summary:** Controls Out-of-Memory killer behavior.
- **DFIR Focus:**
  - Low values prevent termination during memory pressure
  - Malware sets negative values for persistence
  - Value of -1000 makes process immune to OOM killer
- **Detection:**
  ```bash
  cat /proc/[pid]/oom_score_adj
  # Suspicious: -1000 or large negative values
  ```

#### pagemap

- **Location:** `/proc/[pid]/pagemap`
- **Summary:** Shows virtual-to-physical page mappings (binary format).
- **DFIR Focus:**
  - Use for deep memory analysis
  - Detect shared pages between suspicious processes (Rowhammer, side channels)
  - Requires root privileges
- **Advanced:** Typically used with specialized memory forensics tools

#### patch_state

- **Location:** `/proc/[pid]/patch_state`
- **Summary:** Reports live kernel patching state for the process.
- **DFIR Focus:** Can indicate presence of kernel live patching - verify legitimacy (kpatch, livepatch).

#### personality

- **Location:** `/proc/[pid]/personality`
- **Summary:** Displays process execution domain flags (hexadecimal bitmask).
- **DFIR Focus:**
  - Non-default flags may reveal abnormal execution contexts
  - Exploitation indicators (ADDR_NO_RANDOMIZE disables ASLR)
- **Common flags:**
  - 0x0: Default (PER_LINUX)
  - 0x40000: ADDR_NO_RANDOMIZE

#### projid_map

- **Location:** `/proc/[pid]/projid_map`
- **Summary:** Project ID mapping (used by some namespace-aware filesystems like XFS).
- **DFIR Focus:** Identify privilege or filesystem mapping manipulation.

#### root

- **Location:** `/proc/[pid]/root`
- **Summary:** Symlink to the process's root directory (may differ under chroot).
- **DFIR Focus:**
  - Detect chrooted environments or deleted paths
  - Look for processes with root different from system root
  - Indicator of sandboxing or containerization
- **Check:**
  ```bash
  readlink /proc/[pid]/root
  # Expected: / (for non-chrooted processes)
  ```

#### sched / schedstat

- **Location:** `/proc/[pid]/sched`, `/proc/[pid]/schedstat`
- **Summary:** Detailed process scheduling stats and performance metrics.
- **DFIR Focus:**
  - Compare CPU usage with process type
  - Anomalies may indicate crypto-miner or CPU abuse
  - Detect processes with excessive runtime vs. visibility in userland
  - Scheduling policy manipulation

#### sessionid

- **Location:** `/proc/[pid]/sessionid`
- **Summary:** Kernel session ID associated with the process (for audit).
- **DFIR Focus:**
  - Link related processes in attack chain
  - Identify detached sessions or session hijacking
  - Correlate with audit logs

#### setgroups

- **Location:** `/proc/[pid]/setgroups`
- **Summary:** Controls ability to call `setgroups()` in user namespaces.
- **DFIR Focus:**
  - Used by privilege-escalation exploits to manipulate group privileges
  - Check for "deny" vs "allow"
- **Context:** CVE-2014-8989 and related namespace vulnerabilities

#### smaps / smaps_rollup

- **Location:** `/proc/[pid]/smaps`, `/proc/[pid]/smaps_rollup`
- **Summary:** Provides detailed memory mapping stats (RSS, swap, private/shared).
- **DFIR Focus:**
  - Identify injected code regions or memory leaks
  - Detailed breakdown of memory usage per mapping
  - Look for:
    - Large anonymous pages (heap spraying)
    - Excessive private memory
    - Unusual swap usage
- **smaps_rollup:** Aggregated view (faster for total footprint)

#### stack

- **Location:** `/proc/[pid]/stack`
- **Summary:** Shows the process's kernel stack trace (kernel function calls).
- **DFIR Focus:**
  - Check for evidence of injected threads or kernel exploitation
  - Identify unusual system calls or wait states
  - Requires root privileges

#### stat / statm

- **Location:** `/proc/[pid]/stat`, `/proc/[pid]/statm`
- **Summary:** Process statistics (single-line format) and memory usage.
- **DFIR Focus:**
  - **stat:** PID, comm, state, PPID, CPU time, threads, nice value
  - **statm:** Memory pages (size, resident, shared, text, data)
  - Identify:
    - Zombie processes (state Z)
    - Abnormal CPU usage
    - Unusual memory footprint
- **Parsing:** Field-based (space-separated)

#### status

- **Location:** `/proc/[pid]/status`
- **Summary:** Human-readable summary of process information.
- **DFIR Focus:**
  - **HIGHLY RECOMMENDED FOR TRIAGE**
  - Review:
    - **UID/GID:** Privilege anomalies
    - **CapEff/CapPrm:** Capability analysis (root-equivalent capabilities)
    - **State:** D (uninterruptible sleep) may indicate rootkit
    - **VmSize/VmRSS:** Memory consumption
    - **Threads:** Thread count
- **Example:**
  ```bash
  cat /proc/[pid]/status | grep -E '^(Name|Uid|Gid|Cap|State)'
  ```

#### syscall

- **Location:** `/proc/[pid]/syscall`
- **Summary:** Shows the current system call number and arguments.
- **DFIR Focus:**
  - Use for real-time process inspection during suspicious activity
  - Identify processes stuck in specific syscalls
  - Requires CONFIG_HAVE_ARCH_TRACEHOOK kernel option

#### task/

- **Location:** `/proc/[pid]/task/`
- **Summary:** Contains subdirectories for each thread (tasks) belonging to the process.
- **DFIR Focus:**
  - **CRITICAL:** Inspect for hidden or injected threads under a legitimate process
  - Each thread has its own `/proc/[pid]/task/[tid]/` directory with similar structure
  - Compare thread count with expected behavior
- **Enumeration:**
  ```bash
  ls /proc/[pid]/task/
  # Number of directories = number of threads
  ```

#### timens_offsets

- **Location:** `/proc/[pid]/timens_offsets`
- **Summary:** Displays time namespace offsets.
- **DFIR Focus:**
  - Attackers may manipulate time namespaces to evade timestamp correlation
  - Confuse log analysis and timeline reconstruction
- **Modern feature:** Requires kernel 5.6+

#### timers

- **Location:** `/proc/[pid]/timers`
- **Summary:** Lists active kernel timers associated with the process.
- **DFIR Focus:**
  - Identify persistent background actions
  - Detect anti-analysis timing tricks
  - Periodic callbacks used by malware

#### timerslack_ns

- **Location:** `/proc/[pid]/timerslack_ns`
- **Summary:** Defines allowed timer slack (precision) in nanoseconds.
- **DFIR Focus:** Modified values could indicate timing manipulation or anti-debugging techniques.

#### uid_map

- **Location:** `/proc/[pid]/uid_map`
- **Summary:** Shows user ID mappings for user namespaces.
- **DFIR Focus:**
  - **CRITICAL FOR PRIVILEGE ESCALATION DETECTION**
  - Check for user namespace abuse to bypass privilege boundaries
  - Look for mappings like `0 1000 1` (mapping UID 0 to unprivileged user)
- **Context:** Container breakouts, CVE-2018-18955 class issues

#### wchan

- **Location:** `/proc/[pid]/wchan`
- **Summary:** Displays the kernel function the process is waiting on (if sleeping).
- **DFIR Focus:**
  - Identify sleeping or hung processes
  - Suspicious kernel waits may indicate rootkit or interception
  - Shows kernel symbol name or 0 if running

### Kernel Tunables (/proc/sys) (Detailed)

The quick reference table above provides overview-level coverage of `/proc/sys/` categories. Due to the extensive nature of kernel tunables, detailed security-focused analysis is provided in dedicated documents:

**Comprehensive Security Analysis:**
- **[../sys/kernel_security_parameters.md](../sys/kernel_security_parameters.md)**
  - Complete forensic reference for `/proc/sys/kernel/` security parameters
  - Covers: ASLR, module loading, core dumps, ptrace, capabilities, namespaces
  - Attack scenarios, detection strategies, and hardening guidance

- **[../sys/network_security_parameters.md](../sys/network_security_parameters.md)**
  - Complete forensic reference for `/proc/sys/net/` network security parameters
  - Covers: IP forwarding, reverse path filtering, ICMP, TCP hardening, ARP security
  - Network pivoting detection, lateral movement indicators

**High-Priority Kernel Tunables for DFIR:**

| Parameter | Normal | Suspicious | Impact |
|-----------|--------|------------|---------|
| `/proc/sys/kernel/core_pattern` | `core` or `/var/lib/systemd/coredump/core.%P.%u` | Pipe to suspicious script | Persistence, privilege escalation |
| `/proc/sys/kernel/randomize_va_space` | `2` (full ASLR) | `0` or `1` (weakened ASLR) | Exploit prerequisite |
| `/proc/sys/kernel/modules_disabled` | `1` (after boot) | `0` (always loadable) | Rootkit installation possible |
| `/proc/sys/net/ipv4/ip_forward` | `0` (not a router) | `1` (forwarding enabled) | Network pivoting/MITM |
| `/proc/sys/kernel/kptr_restrict` | `1` or `2` | `0` (addresses exposed) | KASLR bypass preparation |
| `/proc/sys/kernel/dmesg_restrict` | `1` (restricted) | `0` (unrestricted) | Information disclosure |
| `/proc/sys/kernel/yama/ptrace_scope` | `1` (restricted ptrace) | `0` (unrestricted) | Process injection enabled |
| `/proc/sys/kernel/unprivileged_userns_clone` | `0` (disabled) | `1` (enabled) | Container escape vectors |
| `/proc/sys/net/ipv4/conf/*/rp_filter` | `1` or `2` (strict) | `0` (disabled) | IP spoofing enabled |
| `/proc/sys/fs/suid_dumpable` | `0` (disabled) | `2` (enabled) | Information disclosure |

**Quick Triage Commands:**
```bash
# Collect all kernel security parameters
sysctl -a | grep -E 'kernel\.(randomize|kptr|dmesg|modules|yama|unprivileged|core_pattern)' > kernel_params.txt

# Collect network security parameters
sysctl -a | grep -E 'net\.ipv4\.(ip_forward|conf.*\.rp_filter)' > network_params.txt

# Check for dangerous core_pattern abuse
cat /proc/sys/kernel/core_pattern
# RED FLAG: Pipe symbol (|) followed by suspicious path

# Check ASLR status
cat /proc/sys/kernel/randomize_va_space
# Expected: 2

# Check module loading controls
cat /proc/sys/kernel/modules_disabled
# Expected: 1 (on production systems after boot)

# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward
# Expected: 0 (unless system is router)
```

---

## Practical DFIR Guidance

### Most Critical Artifacts for Incident Response

When performing live triage on a Linux system, prioritize these `/proc` artifacts:

**Priority 1: Essential Process Forensics**
1. `/proc/[pid]/exe` - Verify binary existence (deleted = high suspicion)
2. `/proc/[pid]/cmdline` - Inspect command arguments
3. `/proc/[pid]/environ` - Check for LD_PRELOAD, suspicious environment
4. `/proc/[pid]/cwd` - Identify execution location
5. `/proc/[pid]/fd/` - Enumerate open files, sockets, deleted files
6. `/proc/[pid]/maps` - Identify memory injections, rwx regions
7. `/proc/[pid]/status` - Review UIDs, capabilities, memory usage

**Priority 2: System-Wide Indicators**
1. `/proc/modules` - Loaded kernel modules (rootkit check)
2. `/proc/mounts` - Active filesystems (hidden mounts)
3. `/proc/net/tcp` and `/proc/net/udp` - Network connections
4. `/proc/sys/kernel/core_pattern` - Persistence mechanism check
5. `/proc/sys/net/ipv4/ip_forward` - Network pivoting indicator
6. `/proc/kallsyms` - Kernel symbol table (baseline comparison)

**Priority 3: Advanced Forensics**
1. `/proc/[pid]/task/` - Thread enumeration (hidden threads)
2. `/proc/[pid]/ns/` - Namespace isolation detection
3. `/proc/[pid]/net/` - Process-specific network view
4. `/proc/sys/kernel/yama/ptrace_scope` - Ptrace restrictions
5. `/proc/sys/kernel/modules_disabled` - Module loading controls

### Baseline Collection Strategy

Establish baselines during normal operations for comparison during IR:

```bash
#!/bin/bash
# Baseline collection script
BASELINE_DIR="/opt/ir_baselines/$(date +%Y%m%d)"
mkdir -p "$BASELINE_DIR"

# System-wide snapshots
cp /proc/modules "$BASELINE_DIR/modules.txt"
cp /proc/mounts "$BASELINE_DIR/mounts.txt"
cp /proc/kallsyms "$BASELINE_DIR/kallsyms.txt"
sysctl -a > "$BASELINE_DIR/sysctl_all.txt"

# Network state
cp /proc/net/tcp "$BASELINE_DIR/net_tcp.txt"
cp /proc/net/udp "$BASELINE_DIR/net_udp.txt"
cp /proc/net/unix "$BASELINE_DIR/net_unix.txt"

# Security parameters
sysctl -a | grep -E 'kernel\.(randomize|kptr|dmesg|modules|yama)' > "$BASELINE_DIR/kernel_security.txt"
sysctl -a | grep -E 'net\.ipv4\.(ip_forward|conf.*rp_filter)' > "$BASELINE_DIR/network_security.txt"

echo "Baseline collected in $BASELINE_DIR"
```

### Common Attack Patterns and /proc Indicators

| Attack Type | Key /proc Indicators | What to Check |
|-------------|---------------------|---------------|
| **Process Injection** | `/proc/[pid]/maps`, `/proc/[pid]/mem`, `/proc/[pid]/task/` | Look for rwx memory regions, unexpected threads, injected libraries |
| **Rootkit** | `/proc/modules`, `/proc/kallsyms`, `/proc/sys/kernel/modules_disabled` | Compare module list against baseline, check for symbol hiding |
| **Privilege Escalation** | `/proc/[pid]/status` (CapEff), `/proc/sys/kernel/yama/ptrace_scope` | Verify capabilities match expected, check for weakened ptrace |
| **Persistence** | `/proc/sys/kernel/core_pattern`, `/proc/[pid]/cwd` (deleted binaries) | Check for pipe to script, execution from /tmp or deleted paths |
| **Network Pivoting** | `/proc/sys/net/ipv4/ip_forward`, iptables, `/proc/net/tcp` | IP forwarding enabled on non-router, suspicious connections |
| **Anti-Forensics** | `/proc/[pid]/environ` (HISTFILE=/dev/null), `/proc/[pid]/limits` (core=0) | Environment manipulation, disabled core dumps |
| **Container Escape** | `/proc/[pid]/ns/`, `/proc/[pid]/cgroup`, `/proc/[pid]/mountinfo` | Different namespaces, unexpected mounts, cgroup anomalies |
| **LD_PRELOAD Injection** | `/proc/[pid]/environ`, `/proc/[pid]/maps`, `/proc/[pid]/map_files/` | LD_PRELOAD variable set, unexpected .so mappings |
| **Crypto Mining** | `/proc/loadavg`, `/proc/[pid]/io`, `/proc/[pid]/stat` | Sustained high load, high CPU time, disk I/O patterns |

### Important Forensic Considerations

**Volatility and Snapshot Timing**
- `/proc` is **live and volatile** - contents change continuously and disappear on reboot
- Capture snapshots early in investigation (`tar`, `rsync`, or dedicated /proc parsers)
- Document collection time for timeline correlation
- Re-collect periodically to detect changes

**Rootkit Falsification**
- Sophisticated rootkits can falsify `/proc` contents (LKM rootkits, eBPF-based)
- Always cross-check with:
  - Memory forensics (dump and analyze kernel memory)
  - Disk-based artifacts (logs, configuration files)
  - Known-good forensic tools from trusted media
- Consider using kernel modules that bypass VFS hooks

**Permissions and Access**
- Many `/proc` entries require root or specific capabilities
- Some files (e.g., `/proc/[pid]/mem`) require ptrace permissions
- Different kernel versions and configurations affect available files
- SELinux/AppArmor may restrict access even for root

**Kernel Version Dependencies**
- Available `/proc` files vary significantly by kernel version
- Modern features (namespaces, cgroups v2, time namespaces) require recent kernels
- Always document kernel version: `uname -r`
- Check kernel config: `cat /proc/config.gz | gunzip` (if available)

---

## Glossary

**ASLR (Address Space Layout Randomization)** - Security feature that randomizes memory addresses to make exploitation harder.

**Capabilities** - Fine-grained privileges that divide root power into distinct units (CAP_NET_ADMIN, CAP_SYS_MODULE, etc.).

**Cgroup (Control Group)** - Linux kernel feature to limit, account for, and isolate resource usage of process groups.

**ELF (Executable and Linkable Format)** - Standard binary format for executables, libraries, and core dumps on Linux.

**KASLR (Kernel Address Space Layout Randomization)** - Randomizes kernel memory addresses to prevent kernel exploits.

**LSM (Linux Security Module)** - Framework for security modules like SELinux, AppArmor, and Smack.

**Namespace** - Linux kernel feature that isolates processes into separate instances of global resources (PID, network, mounts, etc.).

**OOM (Out-Of-Memory)** - Kernel mechanism that terminates processes when system runs out of memory.

**Ptrace** - System call that allows one process to observe and control another (used by debuggers and malware).

**SELinux (Security-Enhanced Linux)** - Mandatory Access Control (MAC) security mechanism using security contexts.

**Sysctl** - Interface to examine and modify kernel parameters at runtime (`/proc/sys/` and `sysctl` command).

**UID/GID** - User ID and Group ID, numeric identifiers for users and groups.

**VMA (Virtual Memory Area)** - Memory region with specific permissions and backing (file, anonymous, shared).

---

## Related Documentation

**Detailed Kernel Tunable References:**
- [../sys/kernel_security_parameters.md](../sys/kernel_security_parameters.md) - Deep dive: `/proc/sys/kernel/` security parameters
- [../sys/network_security_parameters.md](../sys/network_security_parameters.md) - Deep dive: `/proc/sys/net/` network parameters
- [../sys/README.md](../sys/README.md) - Navigation guide for kernel tunables

**Related Forensic Topics:**
- [../eBPF_RootKits_Summary.md](../eBPF_RootKits_Summary.md) - Modern eBPF-based rootkit techniques
- [../Manual_EXT4_FileCarving.md](../Manual_EXT4_FileCarving.md) - EXT4 filesystem forensics

**Part of FOR577 Additional Information**
These materials support **SANS FOR577: Linux Incident Response and Threat Hunting**.
For comprehensive Linux IR training, visit [https://sans.org/for577](https://sans.org/for577)

---

**Document Version:** 1.0
**Last Updated:** 2025
**Maintained by:** FOR577 Instruction Team
