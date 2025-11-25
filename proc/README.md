# Linux /proc Filesystem - Forensic Reference Documentation

This directory contains the unified forensic reference guide for the Linux `/proc` pseudo-filesystem.

## Contents

### [PROC_REFERENCE_GUIDE.md](PROC_REFERENCE_GUIDE.md)
**Complete unified /proc filesystem DFIR reference**

This is the primary reference document for all `/proc` filesystem forensics. It provides both quick-reference tables and detailed analysis in a single, well-organized document.

**Structure:**
- **Quick Reference Tables** - Rapid lookup for system-wide files, per-process artifacts, and kernel tunables
- **Detailed System-Wide Files** - In-depth analysis of top-level `/proc` entries
- **Detailed Per-Process Directories** - Comprehensive coverage of `/proc/[pid]/` artifacts
- **Kernel Tunables Overview** - Quick reference for `/proc/sys/` with links to detailed analysis
- **Practical DFIR Guidance** - Common attack patterns, baseline checks, and triage workflows
- **Glossary** - Technical terms explained for clarity

**When to use this guide:**
- During live incident response for quick artifact lookup
- When investigating suspicious processes
- For understanding kernel security parameters
- As a comprehensive reference during forensic analysis
- For training and learning Linux forensics

**Key Features:**
- Combines breadth (all major `/proc` artifacts) with depth (detailed forensic guidance)
- DFIR-focused: Every entry includes "DFIR Focus" guidance
- Practical examples and command references throughout
- Cross-references to detailed kernel tunable analysis in [../sys/](../sys/)

## How This Relates to Other Documentation

### For Detailed Kernel Tunable Analysis
The `/proc/sys/` section in PROC_REFERENCE_GUIDE.md provides quick reference tables. For deep-dive security analysis of kernel tunables, see:

- **[../sys/kernel_security_parameters.md](../sys/kernel_security_parameters.md)** - Complete forensic reference for `/proc/sys/kernel/`
  - ASLR, module loading, core dumps, ptrace restrictions
  - Attack scenarios and hardening guidance
  - Detection strategies for privilege escalation

- **[../sys/network_security_parameters.md](../sys/network_security_parameters.md)** - Complete forensic reference for `/proc/sys/net/`
  - IP forwarding, reverse path filtering, TCP hardening
  - Network pivoting and lateral movement detection
  - Attack scenarios and hardening guidance

- **[../sys/README.md](../sys/README.md)** - Navigation guide for kernel tunable documentation

### Repository Navigation
- **[../QUICK_START.md](../QUICK_START.md)** - Find documents by task (process analysis, network forensics, rootkit detection)
- **[../NAVIGATION.md](../NAVIGATION.md)** - Understand document relationships across the repository

## Recommended Reading Order

### For New Linux IR Practitioners
1. **Start here:** [PROC_REFERENCE_GUIDE.md](PROC_REFERENCE_GUIDE.md) - Read the overview and skim the quick reference tables
2. **During IR:** Use quick reference tables for rapid artifact lookup
3. **For specific investigations:** Read detailed sections relevant to your case
4. **For kernel security:** Consult [../sys/](../sys/) documents for detailed tunable analysis

### For Experienced Analysts
Use [PROC_REFERENCE_GUIDE.md](PROC_REFERENCE_GUIDE.md) as your primary reference:
- **Quick triage:** Scan quick reference tables
- **Process investigation:** Jump to "Per-Process Directories (Detailed)" section
- **Security audit:** Review "Kernel Tunables Quick Reference" then consult [../sys/](../sys/) for details
- **Attack pattern recognition:** Review "Practical DFIR Guidance" section

### For Threat Hunters
1. Study [PROC_REFERENCE_GUIDE.md](PROC_REFERENCE_GUIDE.md) to understand baseline vs. anomalous /proc artifacts
2. Review [../sys/kernel_security_parameters.md](../sys/kernel_security_parameters.md) for privilege escalation indicators
3. Review [../sys/network_security_parameters.md](../sys/network_security_parameters.md) for lateral movement indicators
4. Build detection rules targeting specific artifacts identified in the guides

## Using During Incident Response

### Live Response Workflow Example

```bash
# Investigate suspicious process 1234
cd /proc/1234

# Check execution context (Reference: PROC_REFERENCE_GUIDE.md - exe, cmdline, environ)
ls -la exe           # Verify binary exists (deleted = suspicious)
cat cmdline          # Check command arguments
cat environ | tr '\0' '\n' | grep -E 'LD_|PATH'  # Look for LD_PRELOAD hijacking

# Check open files and network (Reference: PROC_REFERENCE_GUIDE.md - fd/, net/)
ls -la fd/           # Identify open files, sockets, deleted files
ls -la fd/ | grep deleted
cat net/tcp          # Network connections

# Check memory layout (Reference: PROC_REFERENCE_GUIDE.md - maps, status)
cat maps | grep rwx  # Look for writable+executable regions (injection)
cat status | grep -E '^(Name|Uid|Gid|Cap)'  # Check privileges and capabilities
```

### Security Audit Workflow Example

```bash
# Check critical kernel security settings
# Reference: PROC_REFERENCE_GUIDE.md - Kernel Tunables section
# Detailed analysis: ../sys/kernel_security_parameters.md

cat /proc/sys/kernel/randomize_va_space    # Should be 2 (full ASLR)
cat /proc/sys/kernel/modules_disabled      # Should be 1 (after boot)
cat /proc/sys/kernel/core_pattern          # Check for suspicious pipe to script
cat /proc/sys/net/ipv4/ip_forward          # Should be 0 (unless router)
cat /proc/sys/kernel/yama/ptrace_scope     # Should be 1+ (restricted)

# Full security baseline collection
sysctl -a | grep -E 'kernel\.(randomize|kptr|dmesg|modules|yama)' > kernel_baseline.txt
sysctl -a | grep -E 'net\.ipv4\.(ip_forward|conf.*rp_filter)' > network_baseline.txt
```

## Important Notes

### Volatility
- `/proc` is **live and volatile** - contents change continuously with system state
- Always capture snapshots (`tar`, `rsync`, or specialized tools) for repeatable analysis
- Document collection time for timeline correlation

### Rootkit Considerations
- Sophisticated rootkits can falsify `/proc` contents (LKM rootkits, eBPF-based)
- Cross-validate with:
  - Memory forensics (kernel memory dumps)
  - Disk-based artifacts (logs, configs)
  - Known-good forensic tools from trusted media

### Kernel Version Dependencies
- Available `/proc` files vary by kernel version
- Modern features (namespaces, cgroups v2, time namespaces) require recent kernels
- Always document kernel version: `uname -r`
- Check kernel config if available: `cat /proc/config.gz | gunzip`

## Archived Materials

Previous versions of /proc documentation have been consolidated into PROC_REFERENCE_GUIDE.md. Archived documents are preserved in `../archived/` for reference but should not be used for current work.

## Part of FOR577 Additional Information

These materials support **SANS FOR577: Linux Incident Response and Threat Hunting**.
For comprehensive Linux IR training, visit [https://sans.org/for577](https://sans.org/for577)
