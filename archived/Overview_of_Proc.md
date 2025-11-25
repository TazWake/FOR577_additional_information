# Linux /proc Forensics Reference Handbook

## Digital Forensics & Incident Response Edition

This handbook provides a detailed reference to the Linux `/proc` filesystem — one of the most valuable sources of live forensic data available to analysts.  
It is divided into three main sections:

1. [/proc Overview](#1-proc-directory-overview)
2. [/proc/[pid]/ Process Directories](#2-procpid-process-directories)
3. [/proc/sys Kernel Tunables](#3-procsys-kernel-tunables)

---

## Table of Contents

1. [Overview](#1-proc-directory-overview)
   - [System-Wide Files and Directories](#system-wide-files-and-directories)
2. [Per-Process Directories](#2-procpid-process-directories)
3. [Kernel Tunables](#3-procsys-kernel-tunables)
4. [DFIR Practical Notes](#4-dfir-practical-notes)
5. [Recommended Baseline Checks](#5-recommended-baseline-checks)

---

## 1. /proc Directory Overview

The `/proc` filesystem is a pseudo-filesystem that exposes kernel and process information. It acts as a window into live system activity — reading from `/proc` does not alter system state.

### System-Wide Files and Directories

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

---

## 2. /proc/[pid]/ Process Directories

Each process running on the system has a corresponding directory `/proc/[pid]/`, containing detailed runtime information.

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
| **net/** | Network connections and stats. | Detect active sockets or backdoors. |
| **ns/** | Namespace references. | Identify isolation or container escapes. |
| **oom_adj** / **oom_score_adj** | OOM behaviour tuning. | Prevents termination of malicious tasks. |
| **pagemap** | Virtual-to-physical mapping. | Identify shared memory between processes. |
| **personality** | Process execution domain flags. | Abnormal flags = exploitation. |
| **root** | Process root directory. | Detect chrooted or deleted roots. |
| **sched** / **schedstat** | CPU scheduling data. | Identify CPU abuse or stealth tasks. |
| **sessionid** | Process session identifier. | Group related attack processes. |
| **smaps** / **smaps_rollup** | Memory allocation details. | Locate injected regions or leaks. |
| **stack** | Kernel stack trace. | Detect injected threads or kernel calls. |
| **stat** / **statm** | Process statistics. | Identify zombies or abnormal CPU use. |
| **status** | Readable summary (UIDs, GIDs, state). | Validate privileges and capabilities. |
| **syscall** | Current system call and args. | Live inspection during compromise. |
| **task/** | Thread list. | Identify hidden or injected threads. |
| **timers** / **timer_slack_ns** | Timer configuration. | Identify timing tricks or anti-debugging. |
| **uid_map** | User ID namespace mapping. | Used in containerisation or privilege abuse. |
| **wchan** | Kernel wait channel. | Detect processes waiting in unusual states. |

---

## 3. /proc/sys Kernel Tunables

`/proc/sys/` holds kernel parameters configurable at runtime. Changes here can significantly alter system security or stability.

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

---

## 4. DFIR Practical Notes

- `/proc` is live and volatile — contents change continuously. Capture snapshots (`tar`, `rsync`, or `procfs` parsers) for repeatable analysis.  
- **Most important forensic targets:**  
  `/proc/[pid]/cmdline`, `/proc/[pid]/exe`, `/proc/[pid]/maps`, `/proc/modules`, `/proc/mounts`, `/proc/net/tcp`, `/proc/sys/kernel/core_pattern`.
- Use `find /proc -type l -ls` to identify deleted file references still held open.
- Combine `/proc` data with `/sys`, `/etc`, and `auditd` logs for correlation.
- On compromised systems, `/proc` may be partially falsified — always cross-check with memory or disk images.

---

## 5. Recommended Baseline Checks

| Area | Normal | Suspicious |
|-------|---------|-------------|
| `/proc/modules` | Only signed vendor modules. | Unknown names or missing files. |
| `/proc/sys/kernel/core_pattern` | `core` or empty. | Redirected to a binary/script. |
| `/proc/sys/net/ipv4/ip_forward` | `0` | `1` indicates packet forwarding. |
| `/proc/[pid]/exe` | Points to valid binary. | `(deleted)` path shown. |
| `/proc/[pid]/environ` | Normal user vars. | LD_PRELOAD or LD_LIBRARY_PATH injection. |
| `/proc/mounts` | Matches `/etc/fstab`. | Extra overlay or tmpfs mounts. |
| `/proc/net/tcp` | Legitimate ports. | Listening on non-standard or high-numbered ports. |
