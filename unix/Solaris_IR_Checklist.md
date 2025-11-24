# Live Forensic Triage: Oracle Solaris
**Date:** _______________  
**Case Number:** _______________  
**Examiner:** _______________  
**Target Host:** _______________  

## ⚠️ Critical Protocols
1.  **Do not write to the local disk.** Redirect all output to an external USB mount or a remote collection server (using `netcat`).
2.  **Execute from a trusted path.** If possible, mount a CD/USB with static binaries. If using native binaries, use absolute paths (e.g., `/usr/bin/ls`).
3.  **Privilege:** Execute as `root` or via `pfexec` (Solaris RBAC).

---

## Phase 1: System Identification & Time
*Establishes the baseline and time skew.*

- [ ] `date -u` (Current UTC time)
- [ ] `uname -a` (Kernel and system version)
- [ ] `showrev -a` (Detailed patch and revision info)
- [ ] `hostid` (Unique system identifier)
- [ ] `uptime` (How long has the system been running?)
- [ ] `zonename` (Am I in the Global Zone or a Local Zone Container?)
- [ ] `zoneadm list -cv` (List all zones/containers running on this host)

## Phase 2: Network Connections (Volatile)
*Capture active connections before they close.*

- [ ] `netstat -an -f inet` (Show all active TCP/UDP IPv4 connections)
- [ ] `netstat -an -f inet6` (Show all active TCP/UDP IPv6 connections)
- [ ] `netstat -rn` (Routing table - check for strange gateways)
- [ ] `arp -a` (ARP cache - check for spoofing/promiscuous nodes)
- [ ] `ifconfig -a` (Interface configurations - check for PROMISC mode)
- [ ] `ndd /dev/ip ip_forwarding` (Check if packet forwarding is enabled)

## Phase 3: Process State
*Identify malware, backdoors, or suspicious daemons.*

- [ ] `ps -ef` (Standard process list)
- [ ] `ps -eZ` (Process list with Zone IDs - crucial for Solaris containers)
- [ ] `/usr/ucb/ps -auxww` (Wide format to see full command line arguments)
- [ ] `ptree` (Process tree - visualize parent/child relationships)
- [ ] `crontab -l` (Check scheduled tasks for persistence)
- [ ] `cat /var/spool/cron/crontabs/*` (Check all user crontabs)

## Phase 4: Open Files & Maps
*Link processes to files on disk.*

- [ ] `fuser -u [suspicious_file]` (See what process is holding a file open)
- [ ] `pfiles [PID]` (List all file descriptors for a specific PID - Solaris alternative to lsof)
- [ ] `lsof -n -P` (If installed - list open files)

## Phase 5: Users & Login History
*Who is on the box and who was here recently?*

- [ ] `w` (Who is currently logged in and what are they doing?)
- [ ] `last -n 100` (Last 100 logins)
- [ ] `lastb` (Failed login attempts - requires auditing enabled)
- [ ] `logins -x` (List system users and their status)
- [ ] `cat /etc/passwd` & `cat /etc/shadow` (Acquire for password cracking offline)

## Phase 6: System Auditing (BSM)
*Solaris specific binary logs.*

- [ ] Check if audit is running: `auditconfig -getcond`
- [ ] Locate audit trails: `ls -lat /var/audit/`
- [ ] **Action:** Copy the binary audit files from `/var/audit/` to external evidence drive. (Do not try to parse on the live victim machine).
