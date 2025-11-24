# Live Forensic Triage: IBM AIX
**Date:** _______________  
**Case Number:** _______________  
**Examiner:** _______________  
**Target Host:** _______________  

## ⚠️ Critical Protocols
1.  **Do not write to the local disk.** Redirect all output to an external USB mount or remote collection server.
2.  **Object Data Manager (ODM):** AIX relies heavily on the ODM. Standard Unix commands may not show everything.
3.  **Shell:** Use ksh (KornShell) or standard sh if bash is not available.

---

## Phase 1: System Identification & Time
*Establishes the baseline.*

- [ ] `date -u` (Current UTC time)
- [ ] `oslevel -s` (Exact AIX technology level and service pack)
- [ ] `uname -aL` (System info including LPAR number)
- [ ] `prtconf` (System configuration details)
- [ ] `uptime` (System uptime)

## Phase 2: Network Connections
*Capture active connections.*

- [ ] `netstat -an` (Active connections)
- [ ] `netstat -rn` (Routing table)
- [ ] `arp -an` (ARP cache)
- [ ] `lsdev -Cc adapter` (List network adapters)
- [ ] `entstat -d ent0` (Detailed ethernet stats - check for promiscuous mode on specific adapters)
- [ ] `no -a` (Network options - check for ip_forwarding settings)

## Phase 3: Process State
*Identify suspicious activity.*

- [ ] `ps -ef` (Standard process list)
- [ ] `ps -T [PID]` (Process tree for specific PID)
- [ ] `proctree [PID]` (Print process tree - usually in /usr/proc/bin or /usr/sysv/bin)
- [ ] `svmon -P` (Memory usage by process - look for memory hogs/buffer overflows)

## Phase 4: Open Files (AIX Specifics)
*AIX handles open files differently.*

- [ ] `procfiles [PID]` (List file descriptors for a process - similar to Solaris pfiles)
- [ ] `fileplace -v [filename]` (Check physical placement of a file)
- [ ] `genkld` (List loaded kernel extensions - rootkits often hide here)

## Phase 5: Users & History
*User activity analysis.*

- [ ] `who -u` (Who is logged in)
- [ ] `last` (Login history)
- [ ] `failedlogin` (Check `/etc/security/failedlogin` - Note: This is a binary file)
    * *Command to read:* `who /etc/security/failedlogin`
- [ ] `lsuser -a ALL` (List all attributes of all users)
- [ ] `cat /etc/security/passwd` (AIX stores encrypted passwords here, NOT just /etc/shadow)
- [ ] `cat /etc/security/user` (User account attributes)

## Phase 6: AIX Auditing & Logs
*AIX Audit Subsystem.*

- [ ] Check audit status: `audit query`
- [ ] Locate config: `cat /etc/security/audit/config`
- [ ] Locate stream/bin logs: usually in `/audit/stream` or `/audit/bin`
- [ ] **Error Report:** `errpt -a` (Detailed system error log - Critical on AIX for finding crashes or hardware manipulation)
- [ ] **Action:** Copy the binary audit trails to external evidence drive.
