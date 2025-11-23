# /proc/sys/net/ Network Security Parameters - Forensic Reference

This document provides comprehensive forensic analysis of security-critical network kernel tunables in `/proc/sys/net/`, focusing on parameters most frequently abused by attackers for network pivoting, lateral movement, reconnaissance, and covert channels.

---

## IP Forwarding and Routing

### net.ipv4.ip_forward

**Location:** `/proc/sys/net/ipv4/ip_forward`

**Purpose:** Controls IPv4 packet forwarding (routing capability).

**Values:**
- `0` - Forwarding disabled (host mode) **[SECURE DEFAULT]**
- `1` - Forwarding enabled (router mode)

**DFIR Focus:**

**Secure Baseline:** `0` (for workstations, servers, non-router systems)

**Attack Indicators:**
- Value `1` on non-router systems indicates network pivoting or MITM positioning
- Enables the compromised system to act as a gateway for lateral movement
- Critical indicator for:
  - **Network Pivoting (MITRE T1090.001):** Route traffic through compromised host
  - **Man-in-the-Middle Attacks:** Position system between network segments
  - **Proxy/Relay Configuration:** Facilitate command-and-control traffic routing
  - **Data Exfiltration Routing:** Route sensitive data through compromised system

**Detection Strategy:**
```bash
# Check IPv4 forwarding status
cat /proc/sys/net/ipv4/ip_forward

# Check IPv6 forwarding (often overlooked)
cat /proc/sys/net/ipv6/conf/all/forwarding

# Review routing table for suspicious routes
ip route show
route -n

# Check for iptables NAT rules (common with pivoting)
iptables -t nat -L -n -v
```

**Attack Scenario - Network Pivoting:**
1. Attacker compromises DMZ web server
2. Enables IP forwarding: `echo 1 > /proc/sys/net/ipv4/ip_forward`
3. Configures iptables NAT rules to route traffic
4. Uses compromised host as pivot to reach internal network
5. Lateral movement to internal targets becomes possible

**Incident Response Guidance:**
- If value is 1 on non-router systems, immediately investigate:
  - Firewall/iptables rules for NAT configurations
  - Network connections for proxied traffic patterns
  - Recent SSH tunnels or VPN connections
  - Unusual traffic volume or destination patterns
- Check persistence mechanisms (sysctl.conf, init scripts)
- Review network flow data for traffic routing through the host
- Examine for concurrent SSH tunneling or port forwarding

**Correlation Indicators:**
- IP forwarding + iptables MASQUERADE rules = active pivoting
- IP forwarding + SSH tunnels = SSH-based pivoting
- IP forwarding + VPN software = VPN relay
- IP forwarding + unexpected traffic volume = active data exfiltration routing

**Hardening:**
```bash
# Disable IP forwarding
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv6.conf.all.forwarding=0

# Make persistent
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.d/99-security.conf
echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.d/99-security.conf
```

---

### net.ipv6.conf.all.forwarding

**Location:** `/proc/sys/net/ipv6/conf/all/forwarding`

**Purpose:** Controls IPv6 packet forwarding.

**DFIR Focus:**

**Secure Baseline:** `0`

**Attack Indicators:**
- IPv6 forwarding often overlooked by defenders
- Enables IPv6-based network pivoting even when IPv4 monitoring is in place
- Critical for detection of IPv6 tunneling attacks (6to4, Teredo, etc.)

**Detection Strategy:**
```bash
# Check all IPv6 forwarding settings
sysctl -a | grep -E 'ipv6.*forwarding'

# Check IPv6 routing table
ip -6 route show
```

---

### net.ipv4.conf.all.send_redirects

**Location:** `/proc/sys/net/ipv4/conf/all/send_redirects`

**Purpose:** Controls whether the system sends ICMP redirect messages.

**Values:**
- `0` - Do not send redirects **[SECURE]**
- `1` - Send redirects **[DEFAULT]**

**DFIR Focus:**

**Secure Baseline:** `0`

**Attack Indicators:**
- Enabled redirects can facilitate MITM attacks
- Attackers can abuse redirects to manipulate routing decisions
- Information disclosure about network topology

**Hardening:**
```bash
# Disable sending ICMP redirects
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
```

---

### net.ipv4.conf.all.accept_redirects

**Location:** `/proc/sys/net/ipv4/conf/all/accept_redirects`

**Purpose:** Controls whether the system accepts ICMP redirect messages.

**Values:**
- `0` - Do not accept redirects **[SECURE]**
- `1` - Accept redirects **[DEFAULT]**

**DFIR Focus:**

**Secure Baseline:** `0`

**Attack Indicators:**
- Accepting redirects enables routing manipulation attacks
- Attacker can redirect traffic through malicious gateway
- Facilitates MITM and traffic interception

**Detection Strategy:**
```bash
# Check redirect acceptance
cat /proc/sys/net/ipv4/conf/all/accept_redirects
cat /proc/sys/net/ipv6/conf/all/accept_redirects

# Monitor for ICMP redirects in traffic
tcpdump -i any icmp and 'icmp[0] == 5'
```

**Hardening:**
```bash
# Disable accepting ICMP redirects (IPv4 and IPv6)
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
```

---

### net.ipv4.conf.all.secure_redirects

**Location:** `/proc/sys/net/ipv4/conf.all.secure_redirects`

**Purpose:** Accept ICMP redirects only from gateways in the default gateway list.

**DFIR Focus:** Even with this enabled, disabling all redirects (`accept_redirects=0`) is more secure. This setting provides partial mitigation only.

---

## Source Address Validation (Reverse Path Filtering)

### net.ipv4.conf.all.rp_filter

**Location:** `/proc/sys/net/ipv4/conf/all/rp_filter`

**Purpose:** Controls reverse path filtering (source address validation).

**Values:**
- `0` - No source validation **[INSECURE]**
- `1` - Strict mode: packet must be routable back via incoming interface **[SECURE]**
- `2` - Loose mode: packet source must be routable via any interface

**DFIR Focus:**

**Secure Baseline:** `1` (strict mode)

**Attack Indicators:**
- Value `0` disables source address validation, enabling:
  - **IP Spoofing:** Send packets with forged source addresses
  - **DDoS Amplification:** Participate in reflection attacks
  - **Covert Channels:** Receive responses to spoofed packets
  - **Anti-Forensics:** Obscure true source of malicious traffic

**Detection Strategy:**
```bash
# Check RP filter for all interfaces
sysctl -a | grep 'rp_filter'

# Per-interface check
for iface in /proc/sys/net/ipv4/conf/*; do
    echo "$iface: $(cat $iface/rp_filter)"
done
```

**Attack Scenario - IP Spoofing:**
1. Attacker disables RP filter: `echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter`
2. Sends packets with forged source addresses
3. Evades IP-based filtering and logging
4. Facilitates DDoS reflection attacks using compromised host

**Incident Response Guidance:**
- Value `0` on any interface is high-severity finding
- Review network logs for unusual source addresses
- Check for DDoS amplification tool presence
- Examine firewall logs for spoofed packet detection
- Correlate with bandwidth spikes or outbound attack traffic

**Hardening:**
```bash
# Enable strict reverse path filtering
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
```

---

### net.ipv4.conf.all.log_martians

**Location:** `/proc/sys/net/ipv4/conf/all/log_martians`

**Purpose:** Log packets with impossible (martian) source addresses.

**Values:**
- `0` - Do not log martians **[DEFAULT]**
- `1` - Log martian packets **[SECURE]**

**DFIR Focus:**

**Secure Baseline:** `1` (enable logging)

**Attack Indicators:**
- Martian packets indicate spoofing or network misconfiguration
- Logging provides forensic evidence of spoofing attempts

**Detection Strategy:**
```bash
# Enable martian logging
sysctl -w net.ipv4.conf.all.log_martians=1

# Review kernel logs for martians
journalctl -k | grep -i martian
dmesg | grep -i martian
```

**Hardening:**
```bash
# Enable martian packet logging
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
```

---

## ICMP Security

### net.ipv4.icmp_echo_ignore_all

**Location:** `/proc/sys/net/ipv4/icmp_echo_ignore_all`

**Purpose:** Ignore all ICMP echo requests (ping).

**Values:**
- `0` - Respond to pings **[DEFAULT]**
- `1` - Ignore all pings

**DFIR Focus:**

**Secure Baseline:** `0` or `1` (depends on operational requirements)

**Attack Indicators:**
- Value `1` may indicate anti-reconnaissance hardening (legitimate)
- Value `1` may also indicate attacker attempting to hide compromised host
- Sudden change from 0 to 1 during incident suggests attacker stealth measures

**Detection Strategy:**
```bash
# Check ICMP echo settings
cat /proc/sys/net/ipv4/icmp_echo_ignore_all
cat /proc/sys/net/ipv6/icmp/echo_ignore_all
```

**Incident Response Guidance:**
- If value changed during suspected incident, indicates attacker stealth
- May be part of anti-forensics or persistence hardening
- Legitimate for high-security environments

---

### net.ipv4.icmp_ignore_bogus_error_responses

**Location:** `/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses`

**Purpose:** Ignore malformed ICMP error messages.

**Values:**
- `0` - Process bogus ICMP errors **[INSECURE]**
- `1` - Ignore bogus ICMP errors **[SECURE DEFAULT]**

**DFIR Focus:**

**Secure Baseline:** `1`

**Attack Indicators:**
- Value `0` enables certain ICMP-based DoS attacks
- Rare to see modified; investigation warranted if changed

---

### net.ipv4.icmp_echo_ignore_broadcasts

**Location:** `/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts`

**Purpose:** Ignore broadcast ICMP echo requests (prevents Smurf attacks).

**Values:**
- `0` - Respond to broadcast pings **[INSECURE]**
- `1` - Ignore broadcast pings **[SECURE DEFAULT]**

**DFIR Focus:**

**Secure Baseline:** `1`

**Attack Indicators:**
- Value `0` enables participation in Smurf DDoS amplification attacks
- Rarely modified; highly suspicious if set to 0

---

## TCP Security and Hardening

### net.ipv4.tcp_syncookies

**Location:** `/proc/sys/net/ipv4/tcp_syncookies`

**Purpose:** Enable TCP SYN cookies to protect against SYN flood attacks.

**Values:**
- `0` - SYN cookies disabled **[INSECURE]**
- `1` - SYN cookies enabled **[SECURE DEFAULT]**

**DFIR Focus:**

**Secure Baseline:** `1`

**Attack Indicators:**
- Value `0` disables SYN flood protection
- May indicate attacker disabling DoS protections to facilitate attack
- Suspicious if disabled during or before DoS events

**Detection Strategy:**
```bash
# Check SYN cookie status
cat /proc/sys/net/ipv4/tcp_syncookies

# Monitor for SYN flood symptoms
netstat -an | grep SYN_RECV | wc -l  # High count indicates potential SYN flood
ss -tan state syn-recv | wc -l
```

**Incident Response Guidance:**
- If disabled, investigate for DoS attack preparation or ongoing attack
- Review network connections for SYN_RECV state accumulation
- Check firewall logs for high SYN packet rates
- Examine for attacker disabling defenses before launching DoS

**Hardening:**
```bash
# Enable SYN cookies
sysctl -w net.ipv4.tcp_syncookies=1
```

---

### net.ipv4.tcp_timestamps

**Location:** `/proc/sys/net/ipv4/tcp_timestamps`

**Purpose:** Enable TCP timestamps (RFC 1323).

**Values:**
- `0` - Timestamps disabled
- `1` - Timestamps enabled **[DEFAULT]**

**DFIR Focus:**

**Attack Indicators:**
- Disabled timestamps hinder forensic timeline reconstruction
- May indicate anti-forensics measures
- Legitimate for privacy-focused environments
- Enabled timestamps provide forensic value but enable fingerprinting

**Trade-off:**
- **Forensic Value:** Timestamps aid in connection timeline analysis
- **Privacy/Security Risk:** Timestamps leak system uptime, enable OS fingerprinting

**Detection Strategy:**
```bash
# Check timestamp setting
cat /proc/sys/net/ipv4/tcp_timestamps

# Capture packets to verify timestamp behavior
tcpdump -i any -c 10 'tcp[tcpflags] & tcp-syn != 0' -vv
```

---

### net.ipv4.tcp_sack

**Location:** `/proc/sys/net/ipv4/tcp_sack`

**Purpose:** Enable TCP Selective Acknowledgement (SACK).

**Values:**
- `0` - SACK disabled
- `1` - SACK enabled **[DEFAULT]**

**DFIR Focus:**

**Attack Indicators:**
- SACK vulnerabilities (SACK Panic, SACK Slowness) exploited via CVE-2019-11477/78/79
- Disabled SACK may indicate mitigation against SACK exploits
- Also reduces performance; legitimate in hardened environments

---

### net.ipv4.tcp_max_syn_backlog

**Location:** `/proc/sys/net/ipv4/tcp_max_syn_backlog`

**Purpose:** Maximum number of queued connection requests (SYN_RECV state).

**Default Value:** Varies by system (typically 512-2048)

**DFIR Focus:**

**Attack Indicators:**
- Very low values may indicate DoS by limiting connection capacity
- Very high values may be legitimate tuning for high-traffic servers
- Sudden changes correlate with DoS attack mitigation or facilitation

**Detection Strategy:**
```bash
# Check SYN backlog setting
cat /proc/sys/net/ipv4/tcp_max_syn_backlog

# Monitor SYN_RECV connections
ss -tan state syn-recv | wc -l
```

---

### net.ipv4.tcp_synack_retries

**Location:** `/proc/sys/net/ipv4/tcp_synack_retries`

**Purpose:** Number of SYN-ACK retries before giving up on a connection.

**Default Value:** 5

**DFIR Focus:**

**Attack Indicators:**
- Lowered value (e.g., 1-2) may speed up port scanning detection but reduce legitimate connection reliability
- Raised value increases resource consumption under SYN flood

---

## ARP Security

### net.ipv4.conf.all.arp_ignore

**Location:** `/proc/sys/net/ipv4/conf/all/arp_ignore`

**Purpose:** Controls response behavior to ARP requests.

**Values:**
- `0` - Reply to any ARP request **[DEFAULT]**
- `1` - Reply only if target IP is local address on incoming interface **[SECURE]**
- `2` - Reply only if target IP and source IP are in same subnet

**DFIR Focus:**

**Secure Baseline:** `1` or `2`

**Attack Indicators:**
- Default value `0` enables ARP-based network mapping
- Changing to `1` provides anti-reconnaissance hardening
- May indicate attacker or defender hardening activities

---

### net.ipv4.conf.all.arp_announce

**Location:** `/proc/sys/net/ipv4/conf/all/arp_announce`

**Purpose:** Controls source IP selection in ARP requests.

**Values:**
- `0` - Use any local address **[DEFAULT]**
- `1` - Avoid using addresses not in target subnet
- `2` - Always use best local address for target **[SECURE]**

**DFIR Focus:**

**Secure Baseline:** `2` (prevents ARP information leakage)

**Attack Indicators:**
- Default behavior may leak information about multiple IPs on interface
- Changing to `2` indicates security hardening

---

### net.ipv4.conf.all.arp_filter

**Location:** `/proc/sys/net/ipv4/conf/all/arp_filter`

**Purpose:** Enable ARP filtering (respond only on appropriate interface).

**Values:**
- `0` - No filtering **[DEFAULT]**
- `1` - Enable filtering **[SECURE]**

**DFIR Focus:**

**Secure Baseline:** `1`

**Attack Indicators:**
- Disabled filtering may enable ARP spoofing attacks
- Enabling improves security in multi-homed systems

---

## IPv6 Security

### net.ipv6.conf.all.accept_ra

**Location:** `/proc/sys/net/ipv6/conf/all/accept_ra`

**Purpose:** Accept IPv6 Router Advertisements.

**Values:**
- `0` - Do not accept **[SECURE for servers]**
- `1` - Accept if forwarding is disabled **[DEFAULT]**
- `2` - Always accept

**DFIR Focus:**

**Secure Baseline:** `0` (servers, non-DHCP clients)

**Attack Indicators:**
- Accepting RA enables rogue IPv6 router attacks
- Attacker can send malicious RAs to hijack IPv6 traffic
- Critical for detecting IPv6-based MITM attacks

**Detection Strategy:**
```bash
# Check RA acceptance
sysctl -a | grep 'accept_ra'

# Monitor for IPv6 RAs on network
tcpdump -i any -vv 'icmp6 and ip6[40] == 134'
```

**Attack Scenario - Rogue IPv6 Router:**
1. Attacker on local network sends malicious Router Advertisements
2. Victim system accepts RA (if `accept_ra=1` or `2`)
3. Victim configures attacker's system as default gateway
4. Traffic routed through attacker for MITM

**Hardening:**
```bash
# Disable RA acceptance (for servers)
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
```

---

### net.ipv6.conf.all.accept_source_route

**Location:** `/proc/sys/net/ipv6/conf/all/accept_source_route`

**Purpose:** Accept IPv6 source-routed packets.

**Values:**
- `0` - Do not accept **[SECURE DEFAULT]**
- `1` - Accept source routing

**DFIR Focus:**

**Secure Baseline:** `0`

**Attack Indicators:**
- Source routing enables packet routing manipulation
- Can bypass firewall rules and network segmentation
- Accepting source-routed packets is almost always unnecessary and dangerous

**Hardening:**
```bash
# Disable source routing (IPv4 and IPv6)
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv6.conf.all.accept_source_route=0
```

---

### net.ipv6.conf.all.disable_ipv6

**Location:** `/proc/sys/net/ipv6/conf/all/disable_ipv6`

**Purpose:** Completely disable IPv6.

**Values:**
- `0` - IPv6 enabled **[DEFAULT]**
- `1` - IPv6 disabled

**DFIR Focus:**

**Attack Indicators:**
- IPv6 often overlooked in monitoring and security controls
- Attackers abuse IPv6 for covert channels when IPv4 is monitored
- Disabling IPv6 (value `1`) reduces attack surface if not needed

**Detection Strategy:**
```bash
# Check IPv6 status
cat /proc/sys/net/ipv6/conf/all/disable_ipv6

# Verify no IPv6 traffic
ss -6 -tuln  # Should show no IPv6 listeners if disabled
ip -6 addr show  # Should show no IPv6 addresses if disabled
```

**Hardening (if IPv6 not needed):**
```bash
# Disable IPv6 entirely
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
```

---

## Network Performance and Resource Limits

### net.core.somaxconn

**Location:** `/proc/sys/net/core/somaxconn`

**Purpose:** Maximum length of listen queue for accepting new connections.

**Default Value:** 128 or 4096 (varies by distribution)

**DFIR Focus:**

**Attack Indicators:**
- Extremely low values enable DoS by limiting connection acceptance
- Extremely high values may indicate preparation for high-volume C2 or proxy operation
- Sudden changes correlate with operational environment modifications

---

### net.core.netdev_max_backlog

**Location:** `/proc/sys/net/core/netdev_max_backlog`

**Purpose:** Maximum number of packets queued on input side when interface receives faster than kernel can process.

**DFIR Focus:**

**Attack Indicators:**
- Very high values may indicate preparation for high-volume attack traffic handling
- Very low values may facilitate DoS through packet dropping

---

## Incident Response Checklist

### Rapid Network Security Triage
```bash
# Critical network pivoting indicators
echo "=== IP Forwarding Status ==="
cat /proc/sys/net/ipv4/ip_forward
cat /proc/sys/net/ipv6/conf/all/forwarding

# Source address validation
echo "=== Reverse Path Filtering ==="
sysctl -a | grep 'rp_filter' | grep -v '= 1'  # Show any not set to strict

# ICMP security
echo "=== ICMP Configuration ==="
cat /proc/sys/net/ipv4/icmp_echo_ignore_all
cat /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses

# TCP hardening
echo "=== TCP Security ==="
cat /proc/sys/net/ipv4/tcp_syncookies
cat /proc/sys/net/ipv4/tcp_timestamps

# IPv6 router advertisement security
echo "=== IPv6 RA Acceptance ==="
sysctl -a | grep 'accept_ra' | grep -v '= 0'  # Show any accepting RAs

# Comprehensive snapshot
echo "=== Full Network Sysctl Snapshot ==="
sysctl -a | grep -E '^net\.' > /tmp/network_sysctl_audit.txt
```

### Pivoting Detection Workflow
```bash
# Check for enabled IP forwarding + suspicious network activity
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" == "1" ]; then
    echo "IP forwarding ENABLED - checking for pivot indicators:"

    # Check iptables NAT rules
    iptables -t nat -L -n -v

    # Check for SSH tunnels
    ss -tuln | grep -E ':(22|443|8080)'
    ps aux | grep -E 'ssh.*-[LRD]'

    # Check for unusual traffic patterns
    iftop -t -s 10  # Or alternative: vnstat, iptraf-ng

    # Review routing table
    ip route show
    ip -6 route show
fi
```

### Network Attack Surface Assessment
```bash
# Generate security baseline
sysctl -a | grep -E 'net\.ipv4\.(ip_forward|conf.*rp_filter|icmp_|tcp_syn)' > /tmp/net_security.txt
sysctl -a | grep -E 'net\.ipv6\.(conf.*forwarding|conf.*accept_ra)' >> /tmp/net_security.txt

# Compare against known-good baseline
diff /path/to/baseline/net_security.txt /tmp/net_security.txt
```

---

## Attack Scenario Matrix

| Attack Type | Modified Parameter | Indicator Value | Follow-up Investigation |
|-------------|-------------------|----------------|-------------------------|
| Network Pivoting | `ipv4.ip_forward` | 1 | NAT rules, routing table, traffic analysis |
| IP Spoofing | `ipv4.conf.*.rp_filter` | 0 | Network logs, spoofed sources, DDoS tools |
| MITM (IPv4) | `ipv4.conf.*.accept_redirects` | 1 | ICMP redirects, routing manipulation |
| MITM (IPv6) | `ipv6.conf.*.accept_ra` | 1 or 2 | Rogue RA detection, IPv6 gateway validation |
| SYN Flood DoS | `ipv4.tcp_syncookies` | 0 | Connection state analysis, SYN_RECV count |
| Anti-Reconnaissance | `ipv4.icmp_echo_ignore_all` | 1 | Timeline of change, stealth indicators |
| DDoS Amplification | `ipv4.conf.*.rp_filter` | 0 | Outbound reflection traffic, amplification tools |
| Source Routing Abuse | `ipv4.conf.*.accept_source_route` | 1 | Packet captures, routing anomalies |

---

## Persistence Check

```bash
# Check sysctl persistence files
cat /etc/sysctl.conf | grep -E '^net\.'
ls -la /etc/sysctl.d/
grep -r '^net\.' /etc/sysctl.d/

# Check init scripts
grep -r 'sysctl.*net\.' /etc/rc.local /etc/init.d/ /etc/systemd/system/

# Check for runtime modifications
journalctl | grep -i sysctl | grep 'net\.'
ausearch -m SYSCALL -sc sysctl -i | grep 'net\.'
```

---

## Correlation with Other Indicators

### IP Forwarding + Indicators = Active Pivoting
```bash
# If ip_forward=1, check for:
# 1. NAT/MASQUERADE rules
iptables -t nat -L -n -v | grep -E '(MASQUERADE|DNAT|SNAT)'

# 2. SSH tunnels
ps aux | grep -E 'ssh.*-[LRD]'
ss -tuln | grep :22

# 3. Proxy software
ps aux | grep -E '(socat|proxychains|redsocks|dante)'

# 4. Port forwards
cat /proc/net/tcp | awk '$4 ~ /0A$/'  # LISTEN state
```

### RP Filter Disabled + Indicators = Spoofing/Amplification
```bash
# If rp_filter=0, check for:
# 1. DDoS tools
find / -type f -name "*flood*" -o -name "*ddos*" 2>/dev/null
ps aux | grep -E '(hping|nmap.*-S)'

# 2. Unusual outbound traffic
iftop -t -s 10
nethogs -t

# 3. Amplification service abuse
ss -ulnp | grep -E ':(53|123|389|1900)'  # DNS, NTP, LDAP, SSDP
```

---

## References

- Linux Kernel Documentation: `/Documentation/networking/ip-sysctl.txt`
- CIS Benchmarks for Linux (Network Configuration sections)
- MITRE ATT&CK: T1090 (Proxy), T1557 (MITM), T1498 (Network DoS)
- RFC 3704: Ingress Filtering for Multihomed Networks (RP filtering)

---

**Part of FOR577 Additional Information**
These materials support SANS FOR577: Linux Incident Response and Threat Hunting.
Visit [https://sans.org/for577](https://sans.org/for577) for comprehensive Linux IR training.
