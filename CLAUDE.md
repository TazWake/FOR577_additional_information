# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This repository contains supplementary educational materials and reference documentation for SANS FOR577 (Linux Incident Response and Threat Hunting). The content is focused on providing students with additional technical detail, configuration examples, and forensic reference materials beyond the core course content.

## Repository Structure

- **alphas/**: Experimental and untested materials including:
  - `Sysmon_Linux_Config.xml`: Incident response-focused Sysmon for Linux configuration targeting high-risk execution from volatile directories (/dev/shm, /tmp, /var/tmp)
  - `filter_windows.yaml`: Plaso timeline filter for Linux IR (note: filename says "windows" but content is Linux-focused)
  - `tools/self-check/`: Minimal IR trust-check binary (statically-linked assembly, <16KB)

- **proc/**: Detailed /proc filesystem reference documentation broken down by category:
  - `individual_proc_folders.md`: Per-process directory reference (/proc/[pid]/) with DFIR guidance
  - `proc_sys_contents.md`: Kernel tunables reference (/proc/sys/) with security implications

- **Root-level documentation**:
  - `eBPF_RootKits_Summary.md`: Technical overview of eBPF-based rootkits (BPFDoor, LinkPro, ebpfkit) and their detection challenges
  - `Overview_of_Proc.md`: Comprehensive forensic reference handbook for the Linux /proc filesystem (master document combining system-wide, per-process, and kernel tunable sections)
  - `Manual_EXT4_Extraction_CheatSheet.md`: Step-by-step guide for manual file extraction from EXT4 filesystems using inode parsing and extent mapping
  - `Manual_XFS_File_Extraction_CheatSheet.md`: Manual file extraction from XFS filesystems via allocation group navigation and inode B+tree traversal

## Common Commands

### Building self-check IR Tool
The self-check tool is a minimal trust beacon for IR engagements (alphas/tools/self-check/):

```bash
# Navigate to tool directory
cd alphas/tools/self-check/

# Build using automated script
./build.sh

# Manual build (if needed)
nasm -felf64 src/self-check.asm -o self-check.o
ld -static -nostdlib -o self-check self-check.o
strip self-check

# Verify static linking
ldd self-check  # Should show "not a dynamic executable"

# Test execution
./self-check
```

The tool reports process identity (PID, PPID, UID/EUID, GID/EGID), capabilities, and sandbox status without relying on libc.

## Important Context

### Educational and Testing Environment
All materials in this repository are designed for:
- Educational purposes (SANS FOR577 course support)
- Security research and defensive security
- Authorized penetration testing and incident response scenarios
- CTF and lab environments

### Content Status
- **Alpha folder**: Explicitly untested and experimental. Materials require validation and may need modification before use in production.
- **Root documentation**: Reference materials providing technical depth for IR practitioners.

## Working with Configuration Files

### Sysmon for Linux Configuration
The Sysmon config (`alphas/Sysmon_Linux_Config.xml`) is designed around specific threat models:
- Focuses on execution from volatile/temporary directories
- Targets MITRE ATT&CK techniques: T1055 (Process Injection), T1204 (User Execution)
- Uses schema version 4.82
- Intentionally incomplete coverage (not a catch-all configuration)

Key design principles:
- High-fidelity, low-noise alerts on known-bad behaviors
- Explicit monitoring of /dev/shm, /tmp, /var/tmp execution
- SSH configuration tampering detection
- Network connection filtering to reduce volume

### Plaso Filter Configuration
The filter file (`alphas/filter_windows.yaml`) targets Linux IR artifacts:
- Authentication logs (wtmp, btmp, utmp)
- Systemd journal files
- Shell history files
- SSH configuration and authorized_keys
- Cron jobs and systemd services
- Temporary/volatile storage areas
- Excludes high-volume, low-signal directories (/usr, /var/lib, /proc, /sys)

## Technical Focus Areas

### eBPF Rootkits
The eBPF summary covers sophisticated kernel-level threats:
- BPFDoor (passive backdoor, China-based APT attribution)
- LinkPro (AWS-targeting, trigger-based activation)
- ebpfkit (proof-of-concept, open-source blueprint)
- Detection challenges and EDR evasion techniques

### Filesystem Forensics
The manual extraction cheat sheets provide low-level filesystem recovery techniques when automated tools fail:

**EXT4** (`Manual_EXT4_Extraction_CheatSheet.md`):
- Manual inode-to-data mapping without automated forensic tools
- Superblock parsing and filesystem parameter extraction
- Group descriptor table navigation
- Extent tree parsing and physical block location
- Direct data extraction using dd and hex editors
- Critical for Ubuntu/Debian systems (default filesystem)

**XFS** (`Manual_XFS_File_Extraction_CheatSheet.md`):
- Allocation group (AG) structure and navigation
- Inode B+tree traversal for locating inode chunks
- Support for extent-based, B-tree, and local-format files
- XFS v5 specific considerations
- Important for RHEL/CentOS systems (default filesystem)
- Note: XFS does not journal file content, making deleted file recovery more difficult

### /proc Filesystem Forensics
The /proc reference documentation is organized across multiple files:

**Main Reference**: `Overview_of_Proc.md` provides a complete forensic reference handbook with three main sections:
1. System-wide files and directories (/proc top-level entries)
2. Per-process directories (/proc/[pid]/)
3. Kernel tunables (/proc/sys/)

**Detailed References** in `proc/` directory:
- `individual_proc_folders.md`: Expanded coverage of per-process forensic artifacts
- `proc_sys_contents.md`: Detailed breakdown of kernel tunables with security implications

Each entry includes DFIR-focused guidance on what to check for signs of compromise, privilege escalation, persistence mechanisms, and anti-forensics techniques.

## Architecture and Content Organization

### Documentation Hierarchy
The repository uses a layered documentation approach:

1. **Overview documents** (root level): Quick reference handbooks covering complete topic areas
   - `Overview_of_Proc.md`: Complete /proc filesystem reference with all three sections (system-wide, per-process, kernel tunables)
   - `eBPF_RootKits_Summary.md`: Comprehensive eBPF rootkit threat overview

2. **Detailed references** (proc/ directory): Deep-dive breakdowns for specific categories
   - `individual_proc_folders.md`: Expanded per-process artifact analysis
   - `proc_sys_contents.md`: Detailed kernel tunable security implications

This organization allows users to start with overview documents for quick reference, then drill down into detailed references when investigating specific artifacts.

### Alpha Content Design Philosophy
Materials in alphas/ follow threat-informed design principles:
- **High-fidelity, low-noise**: Explicit rules for known-bad behaviors rather than comprehensive coverage
- **MITRE ATT&CK aligned**: Configurations target specific techniques (T1055, T1204, etc.)
- **IR-optimized**: Generates actionable alerts during active investigations
- **Intentionally incomplete**: Templates requiring customization, not turnkey solutions

## Note on Malware Analysis
This repository contains documentation about malware techniques (eBPF rootkits) and detection methods. When working with these materials:
- Analysis and documentation of malware behavior is appropriate
- Improving or augmenting malicious code is prohibited
- Focus remains on defensive security and incident response
