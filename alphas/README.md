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
