# FOR577 Additional Information

Supplementary educational materials and reference documentation for **SANS FOR577: Linux Incident Response and Threat Hunting**.

This repository provides students and Linux IR practitioners with additional technical detail, configuration examples, and forensic reference materials that extend beyond the core course content.

## Quick Navigation

**New to this repository?**
- **[QUICK_START.md](QUICK_START.md)** - Find documents by task (process analysis, file recovery, rootkit detection, etc.)
- **[NAVIGATION.md](NAVIGATION.md)** - Understand document relationships and hierarchy

## Contents

### Reference Documentation

#### Linux /proc Filesystem Forensics
Comprehensive forensic reference materials for the Linux pseudo-filesystem:

- **[proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md)** - Complete unified /proc filesystem DFIR reference:
  - Quick reference tables for rapid lookup during live IR
  - Detailed system-wide files and directories analysis
  - Detailed per-process artifacts (/proc/[pid]/) with DFIR guidance
  - Kernel tunables (/proc/sys/) quick reference with links to detailed analysis
  - Practical IR guidance and common attack patterns
  - Comprehensive glossary of technical terms

- **[sys/](sys/)** - Deep-dive security analysis of kernel tunables:
  - [kernel_security_parameters.md](sys/kernel_security_parameters.md) - `/proc/sys/kernel/` forensic reference (ASLR, module loading, core dumps, ptrace)
  - [network_security_parameters.md](sys/network_security_parameters.md) - `/proc/sys/net/` forensic reference (IP forwarding, RP filtering, TCP hardening)
  - [README.md](sys/README.md) - Navigation guide for kernel tunable documentation

#### EXT4 Filesystem Forensics - Scenario-Based Guides
Choose the guide that matches your situation:

- **[EXT4_BasicFileRecovery.md](EXT4_BasicFileRecovery.md)** - Quick file recovery when you know the inode number:
  - Filesystem identification and geometry extraction
  - Using debugfs for inode inspection and file recovery
  - Single-partition scenarios with mounted filesystems or loop devices
  - **Use when:** You have an inode number and need straightforward recovery

- **[EXT4_DeletedFileCarving.md](EXT4_DeletedFileCarving.md)** - Recovering deleted files:
  - Journal analysis for deletion events and metadata recovery
  - Directory enumeration including deleted entries
  - Inode table searching and block-to-inode mapping
  - Automated recovery with extundelete
  - **Use when:** Files were deleted and you need to locate and recover them

- **[EXT4_AdvancedForensics.md](EXT4_AdvancedForensics.md)** - Complex recovery scenarios:
  - Multi-partition disk images (GPT/MBR with partition offset calculations)
  - Manual extent tree parsing and interpretation
  - Raw hex carving with xxd and dd
  - Corrupted filesystem recovery when tools fail
  - **Use when:** Working with complex images, corrupted filesystems, or need manual parsing

#### XFS Filesystem Forensics
- **[Manual_XFS_File_Extraction_CheatSheet.md](Manual_XFS_File_Extraction_CheatSheet.md)** - Manual file extraction from XFS filesystems:
  - XFS allocation group (AG) structure and navigation
  - Inode B+tree traversal and chunk location
  - Extent-based, B-tree, and local-format file extraction
  - XFS v5 forensic considerations and recovery limitations
  - Critical for systems using XFS (RHEL/CentOS default)

#### eBPF Rootkits and Advanced Threats
- **[eBPF_RootKits_Summary.md](eBPF_RootKits_Summary.md)** - Technical overview of eBPF-based rootkits including:
  - BPFDoor (passive backdoor, APT attribution)
  - LinkPro (AWS-targeting, trigger-based activation)
  - ebpfkit (open-source proof-of-concept)
  - Detection challenges and EDR evasion techniques

- **[binfmt_misc-abuse-review.md](binfmt_misc-abuse-review.md)** - In-depth analysis of kernel execution hijacking via binfmt_misc (Shadow SUID technique):
  - Privilege escalation without SUID binaries via kernel hooks
  - Binary format handler abuse and credential inheritance ('C' flag)
  - Proxy execution and forensic evasion mechanisms
  - Detection engineering strategies and artifact matrix
  - Critical for understanding advanced persistence and PrivEsc techniques
  - Based on research by Stephan Berger (@malmoeb)

### Experimental Configuration Files (Alpha)

The **[alphas/](alphas/)** directory contains **untested and experimental** configurations designed as starting points for security professionals:

- **[Sysmon_Linux_Config.xml](alphas/Sysmon_Linux_Config.xml)** - Incident response-focused Sysmon for Linux configuration
  - Targets high-risk execution from volatile directories (/dev/shm, /tmp, /var/tmp)
  - Focuses on MITRE ATT&CK techniques: T1055 (Process Injection), T1204 (User Execution)
  - High-fidelity, low-noise alert design
  - Schema version 4.82

- **[filter_linux_ir.yaml](alphas/filter_linux_ir.yaml)** - Plaso timeline filter for Linux IR
  - Targets authentication logs, systemd journals, shell history, SSH config
  - Excludes high-volume, low-signal directories
  - Template requires customization for specific cases

- **[tools/self-check/](alphas/tools/self-check/)** - Minimal IR trust-check binary
  - Statically-linked x86-64 assembly binary (<16KB)
  - Reports process identity (PID, PPID, UID/EUID, GID/EGID)
  - Shows capability sets and sandbox status (seccomp, NoNewPrivs)
  - No external dependencies (uses raw syscalls only)
  - Ideal for verifying execution context on potentially compromised systems

## Using This Repository

### For SANS FOR577 Students
These materials complement your course workbook and provide:
- Quick reference guides for live forensic analysis
- Configuration templates to customize for your environment
- Technical deep-dives on advanced threat techniques

### For IR Practitioners
Use these resources to:
- Build baseline knowledge of Linux forensic artifacts
- Understand modern rootkit techniques (eBPF) and kernel-level persistence mechanisms (binfmt_misc abuse)
- Create or refine detection and monitoring configurations
- Reference during incident response engagements

### Building the self-check Tool

The self-check utility is a minimal trust beacon for incident response:

```bash
# Navigate to the tool directory
cd alphas/tools/self-check/

# Build using the provided script
./build.sh

# Or build manually
nasm -felf64 src/self-check.asm -o self-check.o
ld -static -nostdlib -o self-check self-check.o
strip self-check

# Verify it's statically linked
ldd self-check  # Should output: "not a dynamic executable"

# Test execution
./self-check
```

**Use cases:**
- Verify execution context before deploying forensic tools
- Detect container escapes by comparing capabilities inside/outside containers
- Identify privilege restrictions (seccomp, NoNewPrivs)
- Baseline environment during initial triage on unknown systems

See the [detailed README](alphas/tools/self-check/README.md) for deployment techniques, use cases, and interpretation guidance.

### Getting Started

#### For Quick Task-Based Navigation
**Start here:** [QUICK_START.md](QUICK_START.md) - Find the right document based on what you're trying to accomplish (process analysis, file recovery, rootkit detection, etc.)

#### For Learning the Repository Structure
1. **Read [NAVIGATION.md](NAVIGATION.md)** to understand how documents relate to each other
2. **Review the Quick Navigation** section above for task-specific guidance

#### Recommended Reading Order for New Users
1. **Start with the /proc reference** ([proc/PROC_REFERENCE_GUIDE.md](proc/PROC_REFERENCE_GUIDE.md)) for essential Linux forensic knowledge:
   - Use quick reference tables during live IR
   - Read detailed sections for specific artifacts
   - Consult sys/ documents for kernel security parameter deep-dives

2. **Learn filesystem recovery** progressively:
   - Start with [EXT4_BasicFileRecovery.md](EXT4_BasicFileRecovery.md) for fundamentals
   - Progress to [EXT4_DeletedFileCarving.md](EXT4_DeletedFileCarving.md) for deleted files
   - Advance to [EXT4_AdvancedForensics.md](EXT4_AdvancedForensics.md) for complex scenarios
   - Explore [Manual_XFS_File_Extraction_CheatSheet.md](Manual_XFS_File_Extraction_CheatSheet.md) for XFS systems

3. **Understand advanced kernel-level threats**:
   - [eBPF_RootKits_Summary.md](eBPF_RootKits_Summary.md) - eBPF-based rootkits and detection challenges
   - [binfmt_misc-abuse-review.md](binfmt_misc-abuse-review.md) - Shadow SUID technique and kernel execution hijacking

4. **Build practical IR tools**:
   - [alphas/tools/self-check/](alphas/tools/self-check/) - Minimal IR trust-check binary
   - Customize alpha configurations for your environment (test thoroughly first)

## Important Notes

### Educational and Authorized Use Only
All materials in this repository are designed for:
- Educational purposes (SANS FOR577 course support)
- Security research and defensive security
- Authorized penetration testing and incident response scenarios
- CTF and lab environments

### Content Status and Disclaimer

**⚠️ All content is experimental and untested**

- **Alpha folder materials**: Explicitly untested and require validation before production use
- **No warranty or support**: These materials are provided as-is without guarantees of correctness or fitness for purpose
- **Test before deploying**: Always validate configurations in a lab environment first

The author and SANS Institute provide no warranty, express or implied, and accept no liability for any damages resulting from use of these materials.

## Contributing

Have improvements, corrections, or additional materials? Contributions that support the educational mission of FOR577 are welcome. Please ensure all contributed content maintains the educational and defensive security focus.

## License

See [LICENSE](LICENSE) for full details.

## About SANS FOR577

**SANS FOR577: Linux Incident Response and Threat Hunting** provides comprehensive training in Linux forensics, incident response, and threat hunting. Learn more at [https://sans.org/for577](https://sans.org/for577)
