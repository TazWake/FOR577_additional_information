# Linux /proc/[pid]/ Directory Reference

This document provides a summary of each file or folder within `/proc/[pid]/`, describing its purpose and forensic value during digital forensics and incident response investigations.

---

## arch_status

- **Summary:** Contains architecture-specific process state information (e.g., for ARM or x86).
- **DFIR Focus:** Check for unusual architecture flags or execution modes (e.g., hardware-assisted code execution anomalies).

## attr

- **Summary:** Holds security attributes used by SELinux and related LSMs (e.g., current, exec, fscreate).
- **DFIR Focus:** Examine for manipulated SELinux contexts that might hide processes or files.

## autogroup

- **Summary:** Shows scheduling group information for processes under automatic task grouping.
- **DFIR Focus:** Identify performance manipulation (e.g., CPU scheduling bias used to prioritise malicious tasks).

## auxv

- **Summary:** Lists ELF auxiliary vector data passed to the process at startup.
- **DFIR Focus:** Review for abnormal entries that could indicate exploitation or memory corruption attempts.

## cgroup

- **Summary:** Displays control group membership for the process.
- **DFIR Focus:** Determine if malware isolates itself within unexpected cgroups (useful in container forensics).

## clear_refs

- **Summary:** Interface to clear referenced memory bits for the process.
- **DFIR Focus:** Check for tampering attempts; attackers may reset this to manipulate memory analysis tools.

## cmdline

- **Summary:** Shows the command-line arguments used to start the process.
- **DFIR Focus:** Inspect for suspicious parameters, encoded commands, or script execution.

## comm

- **Summary:** Contains the process’s short name (comm field in task_struct).
- **DFIR Focus:** Validate against `/proc/[pid]/cmdline` for mismatches (common indicator of process masquerading).

## coredump_filter

- **Summary:** Specifies which memory mappings are included in a core dump.
- **DFIR Focus:** Look for modified filters designed to exclude incriminating data from dumps.

## cpu_resctrl_groups

- **Summary:** Displays CPU resource control group information.
- **DFIR Focus:** Rarely relevant; anomalies may hint at performance tuning or sandbox evasion.

## cpuset

- **Summary:** Indicates which CPUs the process is allowed to execute on.
- **DFIR Focus:** Restriction to specific cores could suggest stealth tactics (avoiding monitoring CPUs).

## cwd

- **Summary:** Symlink to the current working directory.
- **DFIR Focus:** Useful for locating execution context—check for deleted or unexpected paths.

## environ

- **Summary:** Lists the process’s environment variables.
- **DFIR Focus:** Inspect for malicious variables (LD_PRELOAD, LD_LIBRARY_PATH, SSH_AUTH_SOCK hijacking).

## exe

- **Summary:** Symlink to the executable binary being run.
- **DFIR Focus:** Confirm whether it points to a valid file; deleted or replaced executables are high-risk indicators.

## fd

- **Summary:** Directory of file descriptors opened by the process.
- **DFIR Focus:** Examine for deleted files, sockets, or pipes suggesting data exfiltration or covert communication.

## fdinfo

- **Summary:** Provides detailed information about each open file descriptor.
- **DFIR Focus:** Correlate with `fd/` to determine how descriptors are used (e.g., network vs file I/O).

## gid_map

- **Summary:** Shows group ID mapping for user namespaces.
- **DFIR Focus:** Check for namespace isolation used by containers or privilege escalation exploits.

## io

- **Summary:** Displays I/O statistics (bytes read/written).
- **DFIR Focus:** Identify high I/O activity from unexpected processes (e.g., data theft or keylogging).

## limits

- **Summary:** Shows resource limits (ulimits) applied to the process.
- **DFIR Focus:** Altered limits (e.g., core dumps disabled) can indicate anti-forensics measures.

## loginuid

- **Summary:** Contains the login UID tied to auditd.
- **DFIR Focus:** Verify whether attackers reset or anonymised this to hide session ownership.

## map_files

- **Summary:** Contains mappings of file-backed memory regions.
- **DFIR Focus:** Look for deleted files or suspicious libraries mapped into memory.

## maps

- **Summary:** Displays memory regions and permissions of the process.
- **DFIR Focus:** Identify injected libraries, writable/executable regions, or code caves.

## mem

- **Summary:** Pseudo-file to access the process’s memory.
- **DFIR Focus:** Can be dumped for live-memory analysis or YARA scanning.

## mountinfo

- **Summary:** Shows detailed mount information for the process’s namespace.
- **DFIR Focus:** Detect hidden mounts or chroot environments used for persistence.

## mounts

- **Summary:** Simplified list of mounted filesystems visible to the process.
- **DFIR Focus:** Cross-check against `/proc/mounts` for namespace manipulation.

## mountstats

- **Summary:** Provides per-mount I/O statistics.
- **DFIR Focus:** May reveal abnormal activity against specific mounts (e.g., data staging areas).

## net

- **Summary:** Network-related information (e.g., sockets, connections).
- **DFIR Focus:** Investigate for unusual connections or listening ports tied to the process.

## ns

- **Summary:** Contains namespace symlinks (mnt, pid, net, user, uts, etc.).
- **DFIR Focus:** Identify isolated namespaces, common in container escapes or rootkit techniques.

## numa_maps

- **Summary:** Shows NUMA memory allocation for the process.
- **DFIR Focus:** Rarely relevant; anomalies may signal attempts to manipulate memory locality for evasion.

## oom_adj

- **Summary:** Deprecated interface for OOM (Out-of-Memory) adjustment.
- **DFIR Focus:** Low values prevent termination—could be used to make malicious processes persistent.

## oom_score

- **Summary:** Displays the kernel’s OOM score for the process.
- **DFIR Focus:** Cross-reference with `oom_adj` to see if attackers reduce risk of termination.

## oom_score_adj

- **Summary:** Modern interface replacing `oom_adj`.
- **DFIR Focus:** Again, look for artificially low scores indicating persistence tactics.

## pagemap

- **Summary:** Shows virtual-to-physical page mappings.
- **DFIR Focus:** Use for deep memory analysis or detecting shared pages between suspicious processes.

## patch_state

- **Summary:** Reports live kernel patching state for the process.
- **DFIR Focus:** Can indicate presence of kernel live patching—verify legitimacy.

## personality

- **Summary:** Displays process execution domain flags.
- **DFIR Focus:** Non-default flags may reveal abnormal execution contexts or exploit behaviour.

## projid_map

- **Summary:** Project ID mapping (used by some namespace-aware filesystems).
- **DFIR Focus:** Identify privilege or filesystem mapping manipulation.

## root

- **Summary:** Symlink to the process’s root directory (may differ under chroot).
- **DFIR Focus:** Detect chrooted environments or deleted paths.

## sched

- **Summary:** Detailed process scheduling stats.
- **DFIR Focus:** Compare CPU usage with process type; anomalies may indicate miner or CPU abuse.

## schedstat

- **Summary:** Summary of process scheduling performance.
- **DFIR Focus:** Detect processes with excessive runtime vs visibility in userland.

## sessionid

- **Summary:** Kernel session ID associated with the process.
- **DFIR Focus:** Link related processes or identify detached sessions.

## setgroups

- **Summary:** Controls ability to call `setgroups()` in user namespaces.
- **DFIR Focus:** Used by privilege-escalation exploits to manipulate group privileges.

## smaps

- **Summary:** Provides detailed memory mapping stats (including RSS, swap).
- **DFIR Focus:** Identify injected code regions or memory leaks tied to malicious activity.

## smaps_rollup

- **Summary:** Aggregated view of memory statistics.
- **DFIR Focus:** Useful for detecting total footprint of suspicious memory activity.

## stack

- **Summary:** Shows the process’s kernel stack trace.
- **DFIR Focus:** Check for evidence of injected threads or kernel exploitation.

## stat

- **Summary:** Displays various process statistics (PID, state, CPU time, etc.).
- **DFIR Focus:** Compare runtime and CPU stats to detect rogue or zombie processes.

## statm

- **Summary:** Memory usage metrics for the process.
- **DFIR Focus:** Unusually high memory may suggest data staging or injection.

## status

- **Summary:** Human-readable summary of process information.
- **DFIR Focus:** Review UIDs, GIDs, and capabilities for privilege anomalies.

## syscall

- **Summary:** Shows the current system call and arguments.
- **DFIR Focus:** Use for real-time process inspection during suspicious activity.

## task

- **Summary:** Contains threads (tasks) belonging to the process.
- **DFIR Focus:** Inspect for hidden or injected threads under a legitimate process.

## timens_offsets

- **Summary:** Displays time namespace offsets.
- **DFIR Focus:** Attackers may manipulate time namespaces to evade timestamp correlation.

## timers

- **Summary:** Lists active kernel timers associated with the process.
- **DFIR Focus:** Identify persistent background actions or anti-analysis timing tricks.

## timerslack_ns

- **Summary:** Defines allowed timer slack (precision).
- **DFIR Focus:** Modified values could indicate timing manipulation or anti-debugging.

## uid_map

- **Summary:** Shows user ID mappings for user namespaces.
- **DFIR Focus:** Check for user namespace abuse to bypass privilege boundaries.

## wchan

- **Summary:** Displays the kernel function the process is waiting on.
- **DFIR Focus:** Identify sleeping or hung processes, or suspicious kernel waits.
**Note:**  
Not all entries will appear or be populated on every system. Permissions and kernel configuration influence what can be read from `/proc/[pid]/`.
