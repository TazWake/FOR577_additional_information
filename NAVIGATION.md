# FOR577 Additional Information - Navigation Guide

## Purpose

This guide helps you navigate the FOR577 additional information repository by explaining how documents relate to each other and which resources to consult for specific tasks.

**New to this repository?** Start with [QUICK_START.md](QUICK_START.md) for task-based navigation.

---

## Document Organization

### Repository Structure

```
FOR577_additional_information/
├── README.md                              # Main repository overview
├── NAVIGATION.md                          # This file - document relationships
├── QUICK_START.md                         # Task-to-document mapping
│
├── proc/                                  # /proc filesystem forensics
│   └── PROC_REFERENCE_GUIDE.md           # Complete unified /proc reference
│
├── sys/                                   # Kernel tunable security analysis
│   ├── README.md                          # sys/ navigation guide
│   ├── kernel_security_parameters.md      # /proc/sys/kernel/ deep dive
│   └── network_security_parameters.md     # /proc/sys/net/ deep dive
│
├── EXT4_BasicFileRecovery.md             # EXT4: Quick file recovery (known inode)
├── EXT4_DeletedFileCarving.md            # EXT4: Deleted file recovery
├── EXT4_AdvancedForensics.md             # EXT4: Multi-partition & manual carving
├── Manual_XFS_File_Extraction_CheatSheet.md  # XFS manual file recovery
│
├── eBPF_RootKits_Summary.md              # eBPF-based rootkit analysis
├── binfmt_misc-abuse-review.md           # Kernel execution hijacking
│
└── alphas/                                # Experimental/untested materials
    ├── Sysmon_Linux_Config.xml            # Sysmon for Linux IR configuration
    ├── filter_linux_ir.yaml               # Plaso timeline filter for Linux IR
    └── tools/self-check/                  # Minimal IR trust-check binary
```

---

## Documentation Hierarchy

### Linux /proc Filesystem Forensics

**Primary Reference:**
- **[proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md)** - Complete /proc filesystem DFIR reference
  - Quick reference tables for rapid lookup
  - Detailed analysis of system-wide files
  - Detailed analysis of per-process artifacts
  - Links to kernel tunable deep dives

**Related Deep Dives:**
- **[sys/kernel_security_parameters.md](sys/kernel_security_parameters.md)** - Security-focused analysis of `/proc/sys/kernel/`
- **[sys/network_security_parameters.md](sys/network_security_parameters.md)** - Security-focused analysis of `/proc/sys/net/`
- **[sys/README.md](sys/README.md)** - Navigation guide for kernel tunables

**Reading Order:**
1. Start with [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) for foundational knowledge
2. Use quick reference tables during live IR
3. Consult detailed sections for specific artifacts
4. Use sys/ documents for targeted security parameter analysis

---

### EXT4 Filesystem Forensics

**Scenario-Based Guides (Choose Based on Your Situation):**

#### Scenario 1: Basic File Recovery
**You have an inode number and need to recover a file quickly.**

→ **[EXT4_BasicFileRecovery.md](EXT4_BasicFileRecovery.md)**
- Filesystem identification and mounting
- Using debugfs to recover files
- Inode metadata analysis
- Single-partition scenarios
- Prerequisites: inode number, mounted filesystem or loop device

#### Scenario 2: Deleted File Recovery
**You need to find and recover deleted files.**

→ **[EXT4_DeletedFileCarving.md](EXT4_DeletedFileCarving.md)**
- Journal analysis for deletion events
- Directory enumeration (including deleted entries)
- Inode table searching
- Block-to-inode mapping
- Automated tools (extundelete)
- Prerequisites: Basic understanding of EXT4, no inode number yet

#### Scenario 3: Advanced/Complex Recovery
**You're working with multi-partition images, corrupted filesystems, or need manual parsing.**

→ **[EXT4_AdvancedForensics.md](EXT4_AdvancedForensics.md)**
- Multi-partition disk images (GPT/MBR)
- Partition offset calculations
- Manual extent tree parsing
- Raw hex carving with xxd
- Complex fragmentation scenarios
- Prerequisites: Expert-level knowledge, tools unavailable/failing

**Progressive Learning Path:**
```
Basic Recovery → Deleted Files → Advanced Techniques
     ↓                ↓                 ↓
  Known inode    Unknown inode    Manual parsing
  Single part.   Journal use      Multi-partition
  debugfs only   Dir enumeration  Extent trees
```

---

### XFS Filesystem Forensics

**Primary Reference:**
- **[Manual_XFS_File_Extraction_CheatSheet.md](Manual_XFS_File_Extraction_CheatSheet.md)**
  - XFS allocation group navigation
  - Manual inode B+tree traversal
  - Support for extent-based and B-tree files
  - XFS v5 considerations

**Note:** XFS does not journal file content, making deleted file recovery significantly harder than EXT4.

---

### Rootkit and Advanced Threat Analysis

#### eBPF-Based Rootkits
**[eBPF_RootKits_Summary.md](eBPF_RootKits_Summary.md)**
- Technical overview of BPFDoor, LinkPro, ebpfkit
- eBPF rootkit capabilities and limitations
- Detection challenges and EDR evasion
- Recommended detection strategies

**Use when:**
- Investigating sophisticated kernel-level compromises
- Understanding eBPF-based persistence
- Responding to APT-level threats

#### Kernel Execution Hijacking
**[binfmt_misc-abuse-review.md](binfmt_misc-abuse-review.md)**
- binfmt_misc abuse for execution redirection
- Persistence via kernel execution hooks
- Detection and mitigation strategies

**Use when:**
- Investigating unusual process execution patterns
- Looking for kernel-level persistence mechanisms
- Understanding execution interception techniques

---

## Cross-Document Relationships

### /proc References Point To:
- **proc/PROC_REFERENCE_GUIDE.md** → **sys/kernel_security_parameters.md** (for `/proc/sys/kernel/` details)
- **proc/PROC_REFERENCE_GUIDE.md** → **sys/network_security_parameters.md** (for `/proc/sys/net/` details)

### EXT4 Guides Point To:
- **EXT4_BasicFileRecovery.md** → **EXT4_DeletedFileCarving.md** (for deleted file recovery)
- **EXT4_BasicFileRecovery.md** → **EXT4_AdvancedForensics.md** (for complex scenarios)
- **EXT4_DeletedFileCarving.md** → **EXT4_AdvancedForensics.md** (for manual techniques)
- All EXT4 guides → **Manual_XFS_File_Extraction_CheatSheet.md** (for XFS equivalent)

### Rootkit/Threat Documents Point To:
- **eBPF_RootKits_Summary.md** → **proc/PROC_REFERENCE_GUIDE.md** (for `/proc/modules`, `/proc/kallsyms` analysis)
- **binfmt_misc-abuse-review.md** → **sys/kernel_security_parameters.md** (for kernel security parameters)

---

## Choosing the Right Document

### "I need to..."

**...investigate a suspicious process**
→ [proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md) - See "Per-Process Directories (Detailed)"

**...check kernel security parameters**
→ [sys/kernel_security_parameters.md](sys/kernel_security_parameters.md)

**...detect network pivoting or lateral movement**
→ [sys/network_security_parameters.md](sys/network_security_parameters.md)

**...recover a specific file (I know the inode)**
→ [EXT4_BasicFileRecovery.md](EXT4_BasicFileRecovery.md)

**...find and recover deleted files**
→ [EXT4_DeletedFileCarving.md](EXT4_DeletedFileCarving.md)

**...manually carve files from a multi-partition disk image**
→ [EXT4_AdvancedForensics.md](EXT4_AdvancedForensics.md)

**...recover files from XFS filesystem**
→ [Manual_XFS_File_Extraction_CheatSheet.md](Manual_XFS_File_Extraction_CheatSheet.md)

**...understand eBPF rootkits**
→ [eBPF_RootKits_Summary.md](eBPF_RootKits_Summary.md)

**...detect kernel execution hijacking**
→ [binfmt_misc-abuse-review.md](binfmt_misc-abuse-review.md)

---

## Experimental Materials (alphas/)

**Important:** Materials in `alphas/` are **explicitly untested** and require validation before operational use.

### Sysmon for Linux Configuration
**[alphas/Sysmon_Linux_Config.xml](alphas/Sysmon_Linux_Config.xml)**
- Incident response-focused Sysmon configuration
- Targets high-risk execution from volatile directories
- MITRE ATT&CK aligned (T1055, T1204)
- **Status:** Untested, requires customization for your environment

### Plaso Timeline Filter
**[alphas/filter_linux_ir.yaml](alphas/filter_linux_ir.yaml)**
- Linux IR artifact filter for Plaso/log2timeline
- Targets authentication logs, shell history, SSH configs
- Excludes high-volume low-signal directories
- **Status:** Untested template, customize for your cases

### Self-Check IR Tool
**[alphas/tools/self-check/](alphas/tools/self-check/)**
- Minimal trust beacon for IR engagements (<16KB, statically linked)
- Reports process identity without relying on libc
- Assembly-based for minimal attack surface
- **Status:** Proof of concept, validate before operational use

**Use case:** When you need to verify a process's identity during IR on a potentially compromised system where you can't trust standard tools.

---

## Document Versioning and Updates

All documents include version information at the bottom:
- **Document Version:** Current version number
- **Last Updated:** Most recent update date
- **Maintained by:** FOR577 Instruction Team

**Archived Documents:**
Older versions of restructured documents are preserved in `archived/` directory for reference but should not be used for current work.

---

## Getting Help

**For questions about:**
- **Document content:** Contact FOR577 instruction team
- **Tool usage:** Refer to tool-specific man pages and documentation
- **SANS FOR577 course:** Visit https://sans.org/for577

**Contributing:**
If you identify errors, have suggestions for improvements, or want to contribute materials, contact the FOR577 instruction team.

---

## Visual Navigation Map

```
┌─────────────────────────────────────────────────────────────────┐
│                    FOR577 Additional Information                 │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
   ┌────▼────┐         ┌──────▼──────┐      ┌──────▼──────┐
   │  /proc  │         │ Filesystems │      │   Threats   │
   │ Forensics│        │  Forensics  │      │  & Rootkits │
   └────┬────┘         └──────┬──────┘      └──────┬──────┘
        │                     │                     │
   ┌────▼──────────────┐      │              ┌──────▼────────┐
   │ PROC_REFERENCE_   │      │              │eBPF_RootKits_ │
   │ GUIDE.md          │      │              │Summary.md     │
   └────┬──────────────┘      │              └───────────────┘
        │                     │              ┌───────────────┐
   ┌────▼───────────────┐     │              │binfmt_misc-   │
   │sys/               │     │              │abuse-review.md│
   │├─kernel_security  │     │              └───────────────┘
   │└─network_security │     │
   └───────────────────┘     │
                        ┌────▼─────────────────┐
                        │ EXT4 (Scenario-Based)│
                        ├──────────────────────┤
                        │ 1. BasicFileRecovery │
                        │ 2. DeletedFileCarving│
                        │ 3. AdvancedForensics │
                        └──────────────────────┘
                        ┌──────────────────────┐
                        │ Manual_XFS_File_     │
                        │ Extraction_...md     │
                        └──────────────────────┘
```

---

**Part of FOR577 Additional Information**
These materials support **SANS FOR577: Linux Incident Response and Threat Hunting**.

For comprehensive Linux IR training, visit [https://sans.org/for577](https://sans.org/for577)

---

**Document Version:** 1.0
**Last Updated:** 2025
**Maintained by:** FOR577 Instruction Team
