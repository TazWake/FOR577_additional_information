# Alpha Content - Experimental Configurations

**⚠️ WARNING: All content in this directory is UNTESTED and EXPERIMENTAL**

This folder contains prototype detection and analysis configurations designed as starting points for security professionals. These materials have **not been validated in production environments** and should be treated as templates requiring customization and thorough testing.

## Important Usage Guidelines

### Before Using Any Alpha Content

1. **Test in isolated lab environments first** - Never deploy directly to production
2. **Validate configuration syntax and compatibility** with your specific distribution and version
3. **Review and customize for your environment** - These are templates, not turnkey solutions
4. **Monitor performance impact** - Some configurations may generate high event volumes
5. **Establish baseline behavior** before incident response scenarios

### Expected Limitations

- Configurations may have syntax errors or incompatibilities
- Event volumes may be too high or too low for your environment
- Detection rules may produce false positives or miss certain variants
- Performance impact has not been measured
- Documentation may be incomplete or contain inaccuracies

You should **not** expect these materials to work perfectly without modification.

## Contents

### [Sysmon_Linux_Config.xml](Sysmon_Linux_Config.xml)

**Incident Response-Focused Sysmon for Linux Configuration**

A detection configuration for Microsoft's Sysmon for Linux, designed around real-world attack patterns observed in Linux compromises.

#### Purpose
Generate high-fidelity telemetry for Linux incident response by focusing on known-bad behaviors rather than attempting comprehensive coverage.

#### Design Philosophy
- **High-fidelity, low-noise**: Explicit rules for known-bad behaviors
- **Threat-informed**: Based on MITRE ATT&CK techniques and real-world attacks
- **IR-optimized**: Generates actionable alerts during active investigations

#### Key Focus Areas
- **Volatile directory execution**: Monitors /dev/shm, /tmp, /var/tmp for binary execution
- **Process injection**: Detects T1055 (Process Injection) indicators
- **User execution**: Tracks T1204 (User Execution) from suspicious locations
- **SSH tampering**: Monitors configuration changes to SSH daemon
- **Network connections**: Filters high-volume traffic while preserving suspicious activity

#### Technical Details
- **Schema version**: 4.82
- **Hash algorithm**: SHA256 (for IOC hunting and file integrity)
- **Target distributions**: RHEL 7+, Ubuntu 18.04+, and derivatives
- **Date created**: November 8, 2025

#### Event IDs Configured
- **Event ID 1**: Process Creation (with volatile directory focus)
- **Event ID 3**: Network Connection (filtered for noise reduction)
- **Event ID 11**: File Create (SSH config tampering detection)

#### Known Limitations
- **Not comprehensive coverage** - Intentionally focuses on high-risk areas
- **May miss sophisticated attacks** using alternative techniques
- **Network filtering may be too aggressive** for some environments
- **Requires tuning** for package managers and legitimate automation

#### How to Use

```bash
# 1. Install Sysmon for Linux
# Download from: https://github.com/Sysinternals/SysmonForLinux

# 2. Validate configuration syntax
sysmon -c Sysmon_Linux_Config.xml -accepteula -i --dry-run

# 3. Test in lab environment first
sysmon -c Sysmon_Linux_Config.xml -accepteula -i

# 4. Monitor event volume
journalctl -u sysmon -f

# 5. Review and tune based on your environment
# Add exclusions for known-good automation
# Adjust network connection filters
# Customize file monitoring paths
```

#### Customization Recommendations

**For your environment**, consider adding:
- Exclusions for automated deployment tools (Ansible, Puppet, etc.)
- Additional monitored paths specific to your infrastructure
- Custom network port filters based on your application stack
- File integrity monitoring for critical configuration files

**Performance tuning**:
- Start with this config and measure event volume
- Add exclusions for high-volume, low-signal events
- Balance coverage vs. storage/analysis capacity

#### References
- [Sysmon for Linux Documentation](https://github.com/Sysinternals/SysmonForLinux)
- [MITRE ATT&CK T1055](https://attack.mitre.org/techniques/T1055/) - Process Injection
- [MITRE ATT&CK T1204](https://attack.mitre.org/techniques/T1204/) - User Execution

---

### [filter_windows.yaml](filter_windows.yaml)

**Plaso Timeline Filter for Linux Incident Response**

A log2timeline/Plaso filter configuration designed to accelerate timeline generation during Linux IR by focusing on high-value forensic artifacts while excluding low-signal noise.

**Note**: Despite the filename containing "windows", this filter is **Linux-focused**. The filename is a legacy artifact.

#### Purpose
Speed up Plaso timeline generation for Linux incident response by including only forensically relevant artifacts and excluding high-volume, low-signal directories.

#### Design Philosophy
- **Include high-value IR artifacts**: Authentication logs, shell history, persistence locations
- **Exclude noise**: System directories with high file counts and low forensic value
- **MITRE ATT&CK informed**: Targets common Linux persistence and execution techniques

#### Included Artifact Categories

**Authentication and Session Logs**:
- wtmp, btmp, utmp (login records)
- lastlog (last login tracking)
- auth.log, secure (authentication events)

**System and Application Logs**:
- syslog, messages, kern.log
- Apache/httpd, nginx web server logs
- Mail logs

**Systemd Journal**:
- Persistent journal files (`/var/log/journal/`)
- Runtime journal files (`/run/log/journal/`)

**Shell History**:
- bash_history, zsh_history (all users including root)

**Persistence Mechanisms**:
- SSH configuration and authorized_keys
- Cron jobs and systemd services
- Init scripts and systemd unit files

**Volatile/Temporary Storage**:
- /tmp, /var/tmp, /dev/shm (common malware staging areas)

#### Excluded Directories

High-volume, low-signal locations excluded to improve performance:
- `/usr` - System binaries (usually not modified in compromises)
- `/var/lib` - Package manager databases
- `/proc`, `/sys` - Pseudo-filesystems (not persistently stored)
- Application cache directories

#### How to Use

```bash
# 1. Install Plaso (log2timeline)
# Ubuntu/Debian: apt install plaso-tools
# Or use docker: docker pull log2timeline/plaso

# 2. Create timeline with filter
log2timeline.py \
  --filter-file filter_windows.yaml \
  --storage-file timeline.plaso \
  /path/to/evidence/mount

# 3. Generate output in preferred format
psort.py -o l2tcsv -w timeline.csv timeline.plaso

# 4. Analyze in timeline analysis tool
# - Import into Excel, Timesketch, or other tools
# - Focus on high-value artifacts captured by filter
```

#### Customization Recommendations

**Add to include list**:
- Application-specific logs for services in your environment
- Custom application paths
- Non-standard persistence locations
- Database audit logs if relevant

**Adjust exclude list**:
- Remove exclusions if you suspect tampering in system directories
- Add exclusions for very large directories specific to your setup
- Balance between coverage and processing time

**Environment-specific tuning**:
- Web servers: Expand web log coverage
- Database servers: Add database-specific logs
- Containers: Include Docker/Kubernetes config paths

#### Performance Considerations

- Filtering can reduce timeline generation time by 50-80%
- Trade-off: May miss evidence in excluded areas
- For comprehensive forensics, run without filter first, then use filter for rapid triage

#### Known Limitations

- **May miss evidence in excluded directories** - If attackers modify /usr binaries, exclusions will skip them
- **Requires YAML syntax validation** - Syntax errors will cause Plaso to fail
- **Not tested across all Plaso versions** - Validate compatibility with your version

#### References
- [Plaso Documentation](https://plaso.readthedocs.io/)
- [Log2timeline Filter File Format](https://plaso.readthedocs.io/en/latest/sources/user/Users-Guide.html#filter-files)

---

### [tools/self-check/](tools/self-check/)

**Minimal IR Trust-Check Binary**

A statically-linked assembly binary designed as a trust beacon for incident response engagements on potentially compromised Linux systems.

#### Purpose
Provide a minimal, dependency-free utility that reports process execution context without relying on libc or external libraries that may be backdoored by rootkits.

#### Design Philosophy
- **No external dependencies**: Uses raw syscalls only, completely statically linked
- **Minimal attack surface**: ~8.7KB binary written in x86-64 assembly
- **Trust verification**: Reports execution context that's harder for userland rootkits to falsify
- **IR-optimized**: Designed for deployment to potentially hostile systems

#### What It Reports
The tool outputs a single line of key=value pairs showing:
- **Process identity**: PID, PPID, UID, EUID, GID, EGID
- **Capability sets**: Effective and permitted capabilities (hexadecimal)
- **Sandbox status**: Seccomp mode (0=disabled, 1=strict, 2=filter)
- **Privilege restrictions**: NoNewPrivs flag (0=disabled, 1=enabled)

**Example output:**
```
pid=12345 ppid=12344 uid=1000 euid=1000 gid=1000 egid=1000 cap_eff=0x0 cap_prm=0x0 seccomp=0 nonewprivs=0
```

#### Key Use Cases
- **Container escape detection**: Compare capabilities inside/outside containers
- **Privilege escalation analysis**: Identify unexpected EUID changes or capabilities
- **Sandbox verification**: Check if seccomp/NoNewPrivs are active
- **Initial triage baseline**: Quick environment check before deploying complex forensic tools
- **Rootkit evasion**: Small binary with raw syscalls may bypass LD_PRELOAD hooks

#### Technical Details
- **Architecture**: x86-64 Linux
- **Binary size**: <16KB (~8.7KB stripped)
- **Linking**: Statically linked, no dynamic dependencies
- **Language**: NASM assembly
- **Syscalls used**: getpid, getppid, getuid, geteuid, getgid, getegid, open, read, write, exit

#### How to Build

```bash
# Navigate to tool directory
cd tools/self-check/

# Build using automated script (recommended)
./build.sh

# Or build manually
nasm -felf64 src/self-check.asm -o self-check.o
ld -static -nostdlib -o self-check self-check.o
strip self-check

# Verify static linking
ldd self-check
# Expected output: "not a dynamic executable"

# Test execution
./self-check
```

**Prerequisites:**
- NASM assembler (2.14+)
- GNU ld linker
- x86-64 Linux system

#### Deployment to Target Systems

**Option 1: Direct copy**
```bash
scp self-check incident-responder@target:/tmp/
ssh incident-responder@target
chmod +x /tmp/self-check
/tmp/self-check
```

**Option 2: Base64 encoding** (for copy-paste deployment)
```bash
# On IR workstation
base64 self-check > self-check.b64

# On target (paste base64 content, then):
base64 -d > /tmp/self-check
chmod +x /tmp/self-check
/tmp/self-check
```

**Option 3: Integrity verification**
```bash
# Generate checksum before transfer
sha256sum self-check > self-check.sha256

# Verify on target after transfer
sha256sum -c self-check.sha256
```

#### Interpreting Output

**Capability values** (hexadecimal bitmask):
- `0x0` - No capabilities (normal unprivileged process)
- `0x3fffffffff` - All capabilities (root-equivalent on Linux 5.x)
- `0xa80425fb` - Docker default capability set
- Other values - Partial capability sets (use `capsh --decode` to interpret)

**Seccomp modes:**
- `0` - Disabled (no syscall filtering)
- `1` - Strict mode (only read, write, exit, sigreturn allowed)
- `2` - Filter mode (custom BPF filter, common in containers)

**Red flags to investigate:**
- Non-root user with `cap_eff != 0x0` (unexpected capabilities)
- `uid != euid` when not running SUID binary (possible privilege escalation)
- Root process with `seccomp != 0` outside containers (unusual)
- Container with `cap_eff=0x3fffffffff` (full capabilities in container)

#### Known Limitations

**What self-check does NOT detect:**
- Namespace isolation (use `/proc/self/ns/*` or `lsns`)
- Cgroups configuration (use `/proc/self/cgroup`)
- SELinux/AppArmor context (use `id -Z` or `/proc/self/attr/current`)
- Resource limits (use `prlimit`)
- File capabilities on the binary itself (use `getcap`)
- Capability bounding set or ambient set

**Security considerations:**
- Kernel-level rootkits can still intercept syscalls
- `/proc` filesystem itself can be manipulated
- Results should be cross-validated with other techniques
- Not a silver bullet, but raises the bar for rootkit authors

#### Full Documentation

See the [detailed README](tools/self-check/README.md) for:
- Complete deployment techniques
- IR workflow integration examples
- Detailed use case scenarios
- Capability interpretation guide
- Troubleshooting procedures
- Forensic workflow examples

---

## Testing Recommendations

### Lab Environment Setup

1. **Create isolated test VMs**:
   - Match your production distribution and version
   - Install Sysmon for Linux or Plaso as needed
   - Take snapshots before testing

2. **Generate test data**:
   - Simulate benign activity (package updates, normal operations)
   - Simulate suspicious activity (execution from /tmp, SSH config changes)
   - Measure event volumes and performance impact

3. **Validate functionality**:
   - Confirm configurations load without errors
   - Verify expected events are captured
   - Check for false positives in normal operations

### Validation Checklist

- [ ] Configuration syntax validated
- [ ] Successfully loads in target tool (Sysmon/Plaso)
- [ ] Events generated for test scenarios
- [ ] Event volume measured and acceptable
- [ ] Performance impact assessed
- [ ] False positive rate evaluated
- [ ] Tuned for environment-specific exclusions
- [ ] Documentation updated with local customizations

## Getting Help

### If Configurations Don't Work

1. **Check syntax and compatibility** - Validate against official documentation
2. **Review tool logs** - Look for error messages indicating issues
3. **Test incrementally** - Start with minimal config, add sections gradually
4. **Consult official documentation** for Sysmon or Plaso

### Resources

- **Sysmon for Linux**: https://github.com/Sysinternals/SysmonForLinux
- **Plaso Project**: https://github.com/log2timeline/plaso
- **SANS FOR577**: https://sans.org/for577

## Disclaimer

These configurations are provided **as-is without warranty**. The author and SANS Institute accept no liability for any issues arising from their use, including but not limited to:
- System performance degradation
- Missed detections or false positives
- Compatibility issues
- Data loss or corruption

**Always test thoroughly in non-production environments before deployment.**

## Part of FOR577 Additional Information

These materials support **SANS FOR577: Linux Incident Response and Threat Hunting**. They are intended as educational resources and starting points for building custom detection and analysis capabilities.
