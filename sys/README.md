# Linux /proc/sys Kernel Tunables - Detailed Security Reference

This directory contains forensic and incident response focused documentation for `/proc/sys/` kernel tunables, organized by security domain for rapid threat assessment and configuration auditing.

## Contents

### [kernel_security_parameters.md](kernel_security_parameters.md)
Comprehensive forensic reference for **security-critical kernel parameters** (`/proc/sys/kernel/`).

The `/proc/sys/kernel/` tree contains runtime-configurable kernel behavior parameters. Malicious modification of these settings enables privilege escalation, persistence, anti-forensics, and rootkit installation. This document provides:
- Detailed forensic analysis of each security-relevant parameter
- Secure baseline values vs. compromised indicators
- Attack techniques that manipulate specific kernel tunables
- Detection and hardening guidance for IR practitioners

**Use this when:**
- Auditing system hardening posture (ASLR, module loading, ptrace restrictions)
- Investigating privilege escalation or kernel exploitation attempts
- Detecting persistence mechanisms (core_pattern abuse, modprobe hijacking)
- Analyzing anti-forensics techniques (kptr_restrict, dmesg_restrict)
- Validating secure boot and kernel lockdown status

**Key areas covered:**
- **Exploit Mitigation:** `randomize_va_space`, `kptr_restrict`, `dmesg_restrict`
- **Module Security:** `modules_disabled`, `kexec_load_disabled`
- **Core Dumps:** `core_pattern`, `core_pipe_limit`, `core_uses_pid`
- **Ptrace/Debugging:** `yama/ptrace_scope`, `perf_event_paranoid`
- **Namespaces:** `unprivileged_userns_clone`, namespace limits

### [network_security_parameters.md](network_security_parameters.md)
Comprehensive forensic reference for **network security kernel parameters** (`/proc/sys/net/`).

The `/proc/sys/net/` tree controls all aspects of the Linux network stack behavior. Attackers modify these settings to enable packet forwarding (pivoting), disable security features (RP filtering), or facilitate covert channels. This document provides:
- Forensic analysis of network stack security parameters
- Baseline secure configurations vs. attacker modifications
- Network-based attack techniques visible through kernel tunables
- Detection strategies for network persistence and pivoting

**Use this when:**
- Investigating network pivoting or man-in-the-middle attacks
- Detecting systems configured as covert gateways or proxies
- Analyzing DoS attack vectors or SYN flood defenses
- Auditing firewall and packet filtering bypass attempts
- Identifying ICMP-based covert channels or reconnaissance

**Key areas covered:**
- **IP Forwarding:** `ipv4/ip_forward`, `ipv6/conf/all/forwarding`
- **Source Validation:** `ipv4/conf/*/rp_filter` (reverse path filtering)
- **ICMP Security:** `icmp_echo_ignore_all`, `icmp_ignore_bogus_error_responses`
- **TCP Hardening:** `tcp_syncookies`, `tcp_timestamps`, `tcp_sack`
- **ARP Security:** `arp_ignore`, `arp_announce`, `arp_filter`

## How This Relates to Other Documentation

These detailed security references complement existing /proc documentation:

**[../proc/PROC_REFERENCE_GUIDE.md](../proc/PROC_REFERENCE_GUIDE.md)**
- Complete unified /proc filesystem forensic reference
- Includes quick reference table for /proc/sys/ categories
- Best starting point for understanding /proc filesystem forensics
- Contains practical baseline checks and triage guidance
- Links to this directory (sys/) for detailed kernel tunable analysis

**This directory (sys/)**
- Security-focused deep-dives into high-risk kernel tunables
- Organized by attack surface (kernel security, network security)
- Extensive DFIR guidance with attack scenarios and detection strategies
- Detailed forensic indicators and hardening recommendations
- Ideal for targeted threat hunting and incident investigation

## Recommended Reading Order

### For New Linux IR Practitioners
1. Start with [../proc/PROC_REFERENCE_GUIDE.md](../proc/PROC_REFERENCE_GUIDE.md) for foundational /proc knowledge
2. Use the quick reference tables for rapid lookup during live IR
3. Consult these security-focused documents for detailed kernel tunable analysis during active investigations

### For Security Auditors
1. Begin with [kernel_security_parameters.md](kernel_security_parameters.md) for hardening assessment
2. Follow with [network_security_parameters.md](network_security_parameters.md) for network security posture
3. Cross-reference [../proc/PROC_REFERENCE_GUIDE.md](../proc/PROC_REFERENCE_GUIDE.md) for additional /proc context

### For Threat Hunters and Incident Responders
Use these documents as quick references during live response:
- Suspected privilege escalation? → [kernel_security_parameters.md](kernel_security_parameters.md)
- Network pivoting or lateral movement? → [network_security_parameters.md](network_security_parameters.md)
- Need /proc artifact context? → [../proc/PROC_REFERENCE_GUIDE.md](../proc/PROC_REFERENCE_GUIDE.md)

## Using During Incident Response

### Security Baseline Collection
```bash
# Collect all kernel security parameters
sysctl -a | grep -E 'kernel\.(randomize|kptr|dmesg|modules|yama|unprivileged)' > kernel_security.txt

# Collect network security parameters
sysctl -a | grep -E 'net\.ipv4\.(ip_forward|conf.*\.rp_filter|icmp_|tcp_syn)' > network_security.txt

# Review against known-good baseline
diff kernel_security.txt /path/to/baseline/kernel_security.txt
```

### Targeted Threat Hunting
```bash
# Check for ASLR disabled (common exploit prerequisite)
cat /proc/sys/kernel/randomize_va_space
# Expected: 2 (full randomization)
# Suspicious: 0 (disabled) or 1 (partial)

# Check for unrestricted kernel module loading
cat /proc/sys/kernel/modules_disabled
# Expected: 1 (loading disabled after boot)
# Suspicious: 0 (modules can still be loaded)

# Check for IP forwarding (network pivoting)
cat /proc/sys/net/ipv4/ip_forward
# Expected: 0 (not a router)
# Suspicious: 1 (forwarding enabled on non-router system)

# Check for abused core_pattern (persistence)
cat /proc/sys/kernel/core_pattern
# Expected: "core" or "|/path/to/legitimate/handler"
# Suspicious: Pipe to unexpected script or network location
```

### Configuration Auditing Workflow
```bash
# Generate comprehensive sysctl snapshot
sysctl -a > /tmp/sysctl_snapshot.txt

# Extract security-critical settings
grep -E 'kernel\.(randomize|modules|kptr|dmesg|yama|perf|core_pattern|unprivileged)' /tmp/sysctl_snapshot.txt
grep -E 'net\.ipv4\.(ip_forward|conf.*rp_filter|icmp|tcp_syn)' /tmp/sysctl_snapshot.txt
grep -E 'net\.ipv6\.conf\..*\.(forwarding|accept_ra)' /tmp/sysctl_snapshot.txt

# Compare against CIS benchmarks or organizational baselines
# References: kernel_security_parameters.md, network_security_parameters.md
```

## Detection Engineering Focus

### High-Value Monitoring Targets

**Critical for privilege escalation detection:**
- `/proc/sys/kernel/modprobe` - Modprobe path hijacking
- `/proc/sys/kernel/core_pattern` - Core dump handler abuse
- `/proc/sys/kernel/randomize_va_space` - ASLR disabling
- `/proc/sys/kernel/yama/ptrace_scope` - Ptrace restriction weakening

**Critical for network attack detection:**
- `/proc/sys/net/ipv4/ip_forward` - Enabling packet forwarding
- `/proc/sys/net/ipv4/conf/*/rp_filter` - Disabling source validation
- `/proc/sys/net/ipv4/icmp_echo_ignore_all` - ICMP reconnaissance

**Recommended monitoring strategy:**
- Implement file integrity monitoring (FIM) on sysctl.conf and sysctl.d/ directories
- Use auditd to track write() syscalls targeting /proc/sys/ paths
- Establish baseline snapshots and alert on deviations
- Correlate sysctl changes with privilege escalation or lateral movement TTPs

## Important Forensic Considerations

### Volatility and Persistence
- `/proc/sys/` entries are **volatile** - changes disappear on reboot
- Attackers must establish persistence via:
  - `/etc/sysctl.conf` or `/etc/sysctl.d/*.conf` (persistent across reboots)
  - Init scripts or systemd units executing `sysctl -w`
  - Cron jobs or at jobs modifying settings post-boot
- Always check both runtime values (/proc/sys/) and persistence mechanisms (sysctl configs)

### Rootkit Considerations
- Sophisticated rootkits can falsify `/proc/sys/` contents
- Cross-validate with:
  - Memory forensics (verify actual kernel data structures)
  - Boot-time forensic collection (before rootkit initialization)
  - Known-good forensic tools from trusted media

### Kernel Version Dependencies
- Available parameters vary significantly by kernel version
- Security features (lockdown, yama) may not exist on older kernels
- Always document kernel version (`uname -r`) with sysctl snapshots

## Part of FOR577 Additional Information

These materials support **SANS FOR577: Linux Incident Response and Threat Hunting**. For comprehensive Linux IR training, visit [https://sans.org/for577](https://sans.org/for577)

## See Also

- **[../proc/PROC_REFERENCE_GUIDE.md](../proc/PROC_REFERENCE_GUIDE.md)** - Complete /proc filesystem forensic reference
- **[../eBPF_RootKits_Summary.md](../eBPF_RootKits_Summary.md)** - Modern rootkit techniques
- **[../binfmt_misc-abuse-review.md](../binfmt_misc-abuse-review.md)** - Kernel execution hijacking via binfmt_misc
- **[../QUICK_START.md](../QUICK_START.md)** - Task-based navigation for quick reference
- **[../NAVIGATION.md](../NAVIGATION.md)** - Document relationships and hierarchy
