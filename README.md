# FOR577 Additional Information

Supplementary educational materials and reference documentation for **SANS FOR577: Linux Incident Response and Threat Hunting**.

This repository provides students and Linux IR practitioners with additional technical detail, configuration examples, and forensic reference materials that extend beyond the core course content.

## Contents

### Reference Documentation

#### Linux /proc Filesystem Forensics
Comprehensive forensic reference materials for the Linux pseudo-filesystem:

- **[Overview_of_Proc.md](Overview_of_Proc.md)** - Complete forensic reference handbook covering:
  - System-wide /proc entries with DFIR focus
  - Per-process directories (/proc/[pid]/)
  - Kernel tunables (/proc/sys/)
  - Baseline checks and practical IR guidance

- **[proc/](proc/)** - Detailed breakdowns for deep-dive analysis:
  - `individual_proc_folders.md` - Expanded per-process artifact reference
  - `proc_sys_contents.md` - Kernel tunable security implications

#### eBPF Rootkits and Advanced Threats
- **[eBPF_RootKits_Summary.md](eBPF_RootKits_Summary.md)** - Technical overview of eBPF-based rootkits including:
  - BPFDoor (passive backdoor, APT attribution)
  - LinkPro (AWS-targeting, trigger-based activation)
  - ebpfkit (open-source proof-of-concept)
  - Detection challenges and EDR evasion techniques

### Experimental Configuration Files (Alpha)

The **[alphas/](alphas/)** directory contains **untested and experimental** configurations designed as starting points for security professionals:

- **[Sysmon_Linux_Config.xml](alphas/Sysmon_Linux_Config.xml)** - Incident response-focused Sysmon for Linux configuration
  - Targets high-risk execution from volatile directories (/dev/shm, /tmp, /var/tmp)
  - Focuses on MITRE ATT&CK techniques: T1055 (Process Injection), T1204 (User Execution)
  - High-fidelity, low-noise alert design
  - Schema version 4.82

- **[filter_windows.yaml](alphas/filter_windows.yaml)** - Plaso timeline filter for Linux IR
  - Note: Filename says "windows" but content is Linux-focused
  - Targets authentication logs, systemd journals, shell history, SSH config
  - Excludes high-volume, low-signal directories

## Using This Repository

### For SANS FOR577 Students
These materials complement your course workbook and provide:
- Quick reference guides for live forensic analysis
- Configuration templates to customize for your environment
- Technical deep-dives on advanced threat techniques

### For IR Practitioners
Use these resources to:
- Build baseline knowledge of Linux forensic artifacts
- Understand modern rootkit techniques (eBPF)
- Create or refine detection and monitoring configurations
- Reference during incident response engagements

### Getting Started

1. **Start with the /proc handbook** ([Overview_of_Proc.md](Overview_of_Proc.md)) for essential Linux forensic knowledge
2. **Review eBPF threats** ([eBPF_RootKits_Summary.md](eBPF_RootKits_Summary.md)) to understand advanced adversary techniques
3. **Customize alpha configs** as needed for your environment (test thoroughly first)

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
