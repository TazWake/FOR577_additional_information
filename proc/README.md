# Linux /proc Filesystem - Detailed Reference Documentation

This directory contains expanded forensic reference materials for the Linux `/proc` pseudo-filesystem, broken down by functional category for easier navigation and deep-dive analysis.

## Contents

### [individual_proc_folders.md](individual_proc_folders.md)
Comprehensive reference for **per-process directories** (`/proc/[pid]/`).

Each running process on a Linux system has a corresponding directory at `/proc/[pid]/` containing detailed runtime information. This document provides:
- Detailed descriptions of each file/directory within `/proc/[pid]/`
- DFIR-focused guidance for each artifact
- Indicators of compromise to look for
- Common attack techniques visible in process directories

**Use this when:**
- Investigating suspicious processes during live response
- Analyzing process memory, file descriptors, or execution context
- Looking for process masquerading, injection, or privilege escalation
- Understanding container isolation or namespace manipulation

**Key artifacts covered:**
- `cmdline`, `comm`, `exe` - Process identity and masquerading detection
- `environ` - Environment variable hijacking (LD_PRELOAD, etc.)
- `fd/`, `fdinfo/` - Open file descriptors and network sockets
- `maps`, `smaps` - Memory layout and code injection detection
- `ns/` - Namespace isolation (containers, rootkits)
- `status` - UIDs, GIDs, capabilities (privilege analysis)

### [proc_sys_contents.md](proc_sys_contents.md)
Comprehensive reference for **kernel tunables** (`/proc/sys/`).

The `/proc/sys/` tree holds kernel parameters configurable at runtime via sysctl. Changes here can significantly alter system security, stability, or behavior. This document provides:
- Detailed coverage of security-relevant kernel parameters
- Default vs. suspicious configuration values
- Attack techniques that modify kernel tunables
- Hardening recommendations and detection guidance

**Use this when:**
- Auditing system security configuration
- Investigating privilege escalation or kernel exploitation
- Analyzing persistence mechanisms (core_pattern, kernel module settings)
- Understanding network security posture (ip_forward, TCP settings)
- Detecting anti-forensics techniques (disabled core dumps, etc.)

**Key areas covered:**
- `/proc/sys/kernel/` - Core kernel behavior, ASLR, ptrace, modules
- `/proc/sys/net/` - Network stack configuration and security
- `/proc/sys/fs/` - Filesystem security (SUID, symlinks, quotas)
- `/proc/sys/vm/` - Virtual memory management and swap
- `/proc/sys/user/` - User namespace limits

## How This Relates to Other Documentation

These detailed references complement the main handbook:

**[../Overview_of_Proc.md](../Overview_of_Proc.md)**
- Master reference handbook covering all three /proc areas
- Includes system-wide /proc entries (top-level files like `/proc/modules`, `/proc/mounts`)
- Best for quick reference and understanding the complete /proc landscape
- Contains practical DFIR notes and recommended baseline checks

**This directory (proc/)**
- Expanded, detailed breakdowns for specific /proc categories
- Better for deep-dive analysis and comprehensive artifact review
- More extensive DFIR guidance for each individual entry
- Ideal when investigating specific process or kernel configuration issues

## Recommended Reading Order

### For New Linux IR Practitioners
1. Start with [../Overview_of_Proc.md](../Overview_of_Proc.md) to get the big picture
2. Refer to these detailed documents when investigating specific artifacts

### For Experienced Analysts
Use these detailed references as quick lookups during live response:
- Process acting suspicious? → [individual_proc_folders.md](individual_proc_folders.md)
- System configuration issues? → [proc_sys_contents.md](proc_sys_contents.md)

### For Threat Hunters
Review both documents to:
- Build detection rules targeting specific /proc artifacts
- Understand baseline vs. anomalous configurations
- Identify persistence and anti-forensics techniques

## Using During Incident Response

### Live Response Workflow
```bash
# Investigate suspicious process 1234
cd /proc/1234

# Check execution context
ls -la exe           # References: individual_proc_folders.md - exe
cat cmdline          # References: individual_proc_folders.md - cmdline
cat environ          # References: individual_proc_folders.md - environ

# Check open files and network
ls -la fd/           # References: individual_proc_folders.md - fd
cat net/tcp          # References: individual_proc_folders.md - net

# Check memory layout
cat maps             # References: individual_proc_folders.md - maps
cat status           # References: individual_proc_folders.md - status
```

### Security Audit Workflow
```bash
# Check kernel security settings
cat /proc/sys/kernel/randomize_va_space    # References: proc_sys_contents.md
cat /proc/sys/kernel/core_pattern          # References: proc_sys_contents.md
cat /proc/sys/net/ipv4/ip_forward          # References: proc_sys_contents.md
```

## Notes

- `/proc` is **volatile** - contents change continuously with system state
- Always capture snapshots for repeatable analysis
- On compromised systems, `/proc` may be partially falsified by rootkits
- Cross-validate /proc data with memory dumps and disk forensics
- Not all entries exist on every system (kernel version and config dependent)

## Part of FOR577 Additional Information

These materials support **SANS FOR577: Linux Incident Response and Threat Hunting**. For more information about the course, visit [https://sans.org/for577](https://sans.org/for577)
