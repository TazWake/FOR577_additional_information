# Quick Start Guide - Find What You Need Fast

## Purpose

This guide helps you quickly find the right document based on **what you're trying to accomplish** during an incident response or forensic investigation.

**For document relationships and hierarchy**, see [NAVIGATION.md](NAVIGATION.md).

---

## Common IR Tasks

### Process Analysis

| What You Need | Go Here | Key Sections |
|--------------|---------|--------------|
| Inspect suspicious process | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | "Per-Process Directories (Detailed)" |
| Check process command line | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | cmdline, comm, exe |
| Analyze process memory | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | maps, smaps, mem |
| Find process network connections | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | net/, fd/ |
| Check for process injection | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | maps (rwx regions), task/ |
| Identify hidden threads | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | task/ |
| Check process capabilities | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | status (CapEff, CapPrm) |
| Detect process masquerading | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | comm vs cmdline comparison |

---

### System Security Audit

| What You Need | Go Here | Key Sections |
|--------------|---------|--------------|
| Check ASLR status | [sys/kernel_security_parameters.md](sys/kernel_security_parameters.md) | randomize_va_space |
| Verify kernel module loading | [sys/kernel_security_parameters.md](sys/kernel_security_parameters.md) | modules_disabled |
| Detect IP forwarding (pivoting) | [sys/network_security_parameters.md](sys/network_security_parameters.md) | ip_forward |
| Check core dump configuration | [sys/kernel_security_parameters.md](sys/kernel_security_parameters.md) | core_pattern |
| Audit ptrace restrictions | [sys/kernel_security_parameters.md](sys/kernel_security_parameters.md) | yama/ptrace_scope |
| Review network security posture | [sys/network_security_parameters.md](sys/network_security_parameters.md) | Full document |
| Check for weakened security | [sys/kernel_security_parameters.md](sys/kernel_security_parameters.md) | kptr_restrict, dmesg_restrict |

---

### Rootkit Detection

| What You Need | Go Here | Key Sections |
|--------------|---------|--------------|
| Check loaded kernel modules | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | /proc/modules, /proc/kallsyms |
| Understand eBPF rootkits | [eBPF_RootKits_Summary.md](eBPF_RootKits_Summary.md) | Full document |
| Detect execution hijacking | [binfmt_misc-abuse-review.md](binfmt_misc-abuse-review.md) | Full document |
| Verify kernel symbol table | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | /proc/kallsyms |
| Check for hidden processes | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | Compare /proc vs ps output |

---

### File Recovery

| Scenario | Document | When to Use |
|----------|----------|-------------|
| **I know the inode number** | [EXT4_BasicFileRecovery.md](EXT4_BasicFileRecovery.md) | Simple recovery, known inode, mounted filesystem |
| **File was deleted** | [EXT4_DeletedFileCarving.md](EXT4_DeletedFileCarving.md) | Need to find deleted files, journal analysis |
| **Multi-partition disk image** | [EXT4_AdvancedForensics.md](EXT4_AdvancedForensics.md) | GPT/MBR images, offset calculations needed |
| **Corrupted filesystem** | [EXT4_AdvancedForensics.md](EXT4_AdvancedForensics.md) | debugfs failing, need manual parsing |
| **XFS filesystem** | [Manual_XFS_File_Extraction_CheatSheet.md](Manual_XFS_File_Extraction_CheatSheet.md) | XFS-specific recovery |

---

### Network Forensics

| What You Need | Go Here | Key Sections |
|--------------|---------|--------------|
| List active network connections | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | /proc/net/tcp, /proc/net/udp |
| Detect network pivoting | [sys/network_security_parameters.md](sys/network_security_parameters.md) | ip_forward, iptables NAT |
| Check reverse path filtering | [sys/network_security_parameters.md](sys/network_security_parameters.md) | rp_filter |
| Identify listening services | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | /proc/net/tcp (state=0A) |
| Find process-specific connections | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | /proc/[pid]/net/ |

---

### Persistence Mechanisms

| What You Need | Go Here | Key Sections |
|--------------|---------|--------------|
| Check core_pattern abuse | [sys/kernel_security_parameters.md](sys/kernel_security_parameters.md) | core_pattern |
| Detect modprobe hijacking | [sys/kernel_security_parameters.md](sys/kernel_security_parameters.md) | modprobe |
| Check for immutable files | [EXT4_AdvancedForensics.md](EXT4_AdvancedForensics.md) | lsattr, Extended Attributes |
| Identify kernel execution hooks | [binfmt_misc-abuse-review.md](binfmt_misc-abuse-review.md) | Full document |
| Find hidden scheduled tasks | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | /proc/[pid]/timer_list |

---

### Container and Namespace Forensics

| What You Need | Go Here | Key Sections |
|--------------|---------|--------------|
| Detect namespace isolation | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | /proc/[pid]/ns/ |
| Check cgroup membership | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | /proc/[pid]/cgroup |
| Find container escapes | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | ns/, mountinfo |
| Audit user namespaces | [sys/kernel_security_parameters.md](sys/kernel_security_parameters.md) | unprivileged_userns_clone |
| Check UID/GID mappings | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | /proc/[pid]/uid_map, gid_map |

---

### Memory Analysis

| What You Need | Go Here | Key Sections |
|--------------|---------|--------------|
| Identify injected code | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | /proc/[pid]/maps (rwx regions) |
| Dump process memory | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | /proc/[pid]/mem |
| Check memory mappings | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | /proc/[pid]/smaps |
| Find deleted libraries | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | /proc/[pid]/map_files/ |
| Analyze shared memory | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | /proc/[pid]/pagemap |

---

### Privilege Escalation Investigation

| What You Need | Go Here | Key Sections |
|--------------|---------|--------------|
| Check process capabilities | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | /proc/[pid]/status (Cap*) |
| Verify ASLR enabled | [sys/kernel_security_parameters.md](sys/kernel_security_parameters.md) | randomize_va_space |
| Check setuid/setgid abuse | [EXT4_AdvancedForensics.md](EXT4_AdvancedForensics.md) | File attributes |
| Audit ptrace usage | [sys/kernel_security_parameters.md](sys/kernel_security_parameters.md) | yama/ptrace_scope |
| Check namespace abuse | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | uid_map, gid_map, setgroups |

---

### Lateral Movement Detection

| What You Need | Go Here | Key Sections |
|--------------|---------|--------------|
| Detect SSH tunneling | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | /proc/[pid]/fd/ (sockets) |
| Check IP forwarding | [sys/network_security_parameters.md](sys/network_security_parameters.md) | ip_forward |
| Find network pivoting | [sys/network_security_parameters.md](sys/network_security_parameters.md) | Full document |
| Identify proxy processes | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | Network connections + cmdline |

---

### Anti-Forensics Detection

| What You Need | Go Here | Key Sections |
|--------------|---------|--------------|
| Check for disabled core dumps | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | /proc/[pid]/limits |
| Detect HISTFILE manipulation | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | /proc/[pid]/environ |
| Find timestamp manipulation | [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) | /proc/[pid]/timens_offsets |
| Check for log clearing | [sys/kernel_security_parameters.md](sys/kernel_security_parameters.md) | dmesg_restrict |
| Detect secure deletion | [EXT4_AdvancedForensics.md](EXT4_AdvancedForensics.md) | File attributes (s flag) |

---

## By Investigation Phase

### Phase 1: Initial Triage

**First 30 minutes of IR:**

1. **System Overview**
   - [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) - /proc/version, /proc/uptime, /proc/loadavg

2. **Running Processes**
   - [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) - Enumerate /proc/[pid]/ directories

3. **Network Connections**
   - [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) - /proc/net/tcp, /proc/net/udp

4. **Loaded Modules**
   - [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) - /proc/modules

5. **Active Mounts**
   - [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) - /proc/mounts

### Phase 2: Threat Hunting

**Focused investigation of suspicious indicators:**

1. **Process Analysis**
   - [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) - Detailed per-process analysis

2. **Rootkit Checks**
   - [eBPF_RootKits_Summary.md](eBPF_RootKits_Summary.md)
   - [binfmt_misc-abuse-review.md](binfmt_misc-abuse-review.md)

3. **Security Parameter Audit**
   - [sys/kernel_security_parameters.md](sys/kernel_security_parameters.md)
   - [sys/network_security_parameters.md](sys/network_security_parameters.md)

### Phase 3: Evidence Collection

**Preserving data for analysis:**

1. **File Recovery**
   - [EXT4_BasicFileRecovery.md](EXT4_BasicFileRecovery.md) - Quick recovery
   - [EXT4_DeletedFileCarving.md](EXT4_DeletedFileCarving.md) - Deleted files
   - [EXT4_AdvancedForensics.md](EXT4_AdvancedForensics.md) - Complex scenarios

2. **Memory Dumps**
   - [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) - /proc/[pid]/mem, /proc/kcore

### Phase 4: Deep Dive Analysis

**Advanced forensic techniques:**

1. **Manual Filesystem Analysis**
   - [EXT4_AdvancedForensics.md](EXT4_AdvancedForensics.md)
   - [Manual_XFS_File_Extraction_CheatSheet.md](Manual_XFS_File_Extraction_CheatSheet.md)

2. **Kernel-Level Threat Analysis**
   - [eBPF_RootKits_Summary.md](eBPF_RootKits_Summary.md)
   - [sys/kernel_security_parameters.md](sys/kernel_security_parameters.md)

---

## By Threat Type

### Malware Investigation

**Priority reading order:**
1. [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) - Process forensics
2. [sys/kernel_security_parameters.md](sys/kernel_security_parameters.md) - Persistence checks
3. [EXT4_DeletedFileCarving.md](EXT4_DeletedFileCarving.md) - Recover deleted samples

### APT / Advanced Threats

**Priority reading order:**
1. [eBPF_RootKits_Summary.md](eBPF_RootKits_Summary.md) - Sophisticated rootkits
2. [binfmt_misc-abuse-review.md](binfmt_misc-abuse-review.md) - Execution hijacking
3. [sys/network_security_parameters.md](sys/network_security_parameters.md) - Lateral movement

### Insider Threat

**Priority reading order:**
1. [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) - User activity tracking
2. [EXT4_DeletedFileCarving.md](EXT4_DeletedFileCarving.md) - Recover deleted evidence
3. [sys/kernel_security_parameters.md](sys/kernel_security_parameters.md) - Anti-forensics detection

### Crypto-Mining

**Priority reading order:**
1. [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) - /proc/loadavg, CPU usage
2. [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) - /proc/[pid]/stat, sched
3. [sys/kernel_security_parameters.md](sys/kernel_security_parameters.md) - Persistence mechanisms

---

## Tool-Specific Guidance

### Using debugfs
→ [EXT4_BasicFileRecovery.md](EXT4_BasicFileRecovery.md) - debugfs commands
→ [EXT4_DeletedFileCarving.md](EXT4_DeletedFileCarving.md) - Journal analysis with logdump

### Using dumpe2fs
→ [EXT4_BasicFileRecovery.md](EXT4_BasicFileRecovery.md) - Filesystem geometry
→ [EXT4_AdvancedForensics.md](EXT4_AdvancedForensics.md) - Manual offset calculations

### Using xxd/hexdump
→ [EXT4_AdvancedForensics.md](EXT4_AdvancedForensics.md) - Manual hex carving

### Using extundelete
→ [EXT4_DeletedFileCarving.md](EXT4_DeletedFileCarving.md) - Automated recovery

### Monitoring with Sysmon
→ [alphas/Sysmon_Linux_Config.xml](alphas/Sysmon_Linux_Config.xml) - Configuration template

### Timeline analysis with Plaso
→ [alphas/filter_linux_ir.yaml](alphas/filter_linux_ir.yaml) - Filter template

---

## Learning Path for Students

### Beginner (New to Linux Forensics)

1. **Start here:** [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) - "Quick Reference" sections
2. **Then:** [EXT4_BasicFileRecovery.md](EXT4_BasicFileRecovery.md) - Simple file recovery
3. **Practice:** Recover files from test images

### Intermediate (Some Linux Experience)

1. [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) - "Detailed References" sections
2. [EXT4_DeletedFileCarving.md](EXT4_DeletedFileCarving.md) - Deleted file techniques
3. [sys/kernel_security_parameters.md](sys/kernel_security_parameters.md) - Security auditing
4. **Practice:** Analyze suspicious processes, recover deleted files

### Advanced (Expert-Level)

1. [EXT4_AdvancedForensics.md](EXT4_AdvancedForensics.md) - Manual carving techniques
2. [eBPF_RootKits_Summary.md](eBPF_RootKits_Summary.md) - Modern rootkit analysis
3. [Manual_XFS_File_Extraction_CheatSheet.md](Manual_XFS_File_Extraction_CheatSheet.md) - XFS forensics
4. **Practice:** Manual extent tree parsing, multi-partition carving

---

## Quick Reference Cards

### Essential /proc Files

```
/proc/[pid]/exe       - Binary path (deleted = suspicious)
/proc/[pid]/cmdline   - Command arguments
/proc/[pid]/environ   - Environment (check LD_PRELOAD)
/proc/[pid]/fd/       - Open files and sockets
/proc/[pid]/maps      - Memory regions (check rwx)
/proc/modules         - Loaded kernel modules
/proc/net/tcp         - TCP connections
/proc/sys/kernel/core_pattern - Persistence check
```

### Essential Commands

```bash
# Process forensics
cat /proc/[pid]/cmdline | tr '\0' ' '
ls -la /proc/[pid]/exe
ls -la /proc/[pid]/fd/

# Filesystem recovery
debugfs -R "stat <inode>" /dev/loop0p1
debugfs -R "dump <inode> file.bin" /dev/loop0p1

# Security audit
cat /proc/sys/kernel/randomize_va_space
cat /proc/sys/net/ipv4/ip_forward
sysctl -a | grep -E 'kernel\.(randomize|modules|yama)'
```

---

## Still Can't Find What You Need?

1. **Check [NAVIGATION.md](NAVIGATION.md)** for document relationships
2. **Review [README.md](README.md)** for repository overview
3. **Search within documents** using Ctrl+F for keywords
4. **Check sys/README.md** for kernel tunable-specific navigation

---

**Part of FOR577 Additional Information**
These materials support **SANS FOR577: Linux Incident Response and Threat Hunting**.

For comprehensive Linux IR training, visit [https://sans.org/for577](https://sans.org/for577)

---

**Document Version:** 1.0
**Last Updated:** 2025
**Maintained by:** FOR577 Instruction Team
