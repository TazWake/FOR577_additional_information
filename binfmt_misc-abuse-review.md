# Analysis of Kernel Execution Hijacking via binfmt\_misc: The Shadow SUID Technique

**Note**: [This has been created from the incredible work by Stephan Berger (@malmoeb). The original article is at [https://dfir.ch/posts/today_i_learned_binfmt_misc/], which should be considered the source of truth for this. Any errors, omissions, or mistakes in this post are absolutely the fault of this article. Please visit the original article and make sure you acknowledge the great work there when discussing this. ] **END**

## I. Foundational Principles: Linux Binary Execution and Execution Hooks

The Linux kernel relies on the Binary Format (binfmt) subsystem to determine the appropriate method for executing a file upon invocation of the execve() syscall. This architecture provides an internal framework for handling various file types. Traditionally, this subsystem is equipped to handle native formats like Executable and Linkable Format (ELF) files. However, modern systems require flexibility to handle scripts, emulation for foreign architectures (e.g., QEMU), or custom binary wrappers.

### I.A. The Binary Format (binfmt) Subsystem: Architecture and Hierarchy

The binfmt subsystem intercepts the execution flow at a crucial point within the kernel. When a user or application attempts to execute a file, the kernel processes the request and hands control to the binfmt handler list. This process determines whether the file is a standard ELF executable, a script requiring an interpreter specified by a shebang line, or another specialised format.

### I.B. Purpose of binfmt\_misc: Dynamic Execution Extension

The binfmt\_misc feature, or Binary Format Miscellaneous, serves as a dynamic extension to the core binfmt subsystem. It provides a means for system administrators or privileged users to register custom binary format handlers at runtime. This mechanism allows the kernel to recognise and execute file types that fall outside the typical definition of native Linux binaries, such as scripts or binaries for other architectures, effectively treating them as if they were native executables.

### I.C. Implementation Detail and Security Context

Configuration of binfmt\_misc is managed through a virtual filesystem, typically mounted at /proc/sys/fs/binfmt\_misc/. This location contains control files, including register and status, through which new binary format handlers are defined.

The placement of the binfmt\_misc mechanism-operating at the initial execution handling stage-is a crucial factor in its security implications. The execution flow is intercepted at the earliest possible stage, meaning the subsystem is responsible for *interpreting* the file format and *determining* the execution path. This architectural placement allows the adversary to substitute the intended execution path at a deep kernel hook level. Consequently, the exploitation occurs prior to most standard application-layer security checks or detection rules that activate only after the process has been launched or when inspecting standard ELF execution logs.

It must be recognised that the function of binfmt\_misc is primarily technical-handling file format interpretation. However, when abused, this technical capability transforms into a robust security enforcement bypass. Security personnel must therefore treat the configuration and monitoring of execution handlers with the same criticality reserved for managing SUID file permissions, recognising the feature's potential for policy abuse rather than viewing it merely as a benign configuration setting.

## II. Dissection of binfmt\_misc Configuration and the Shadow SUID Mechanism

The exploitation technique, dubbed "Shadow SUID," leverages specific configuration parameters within the binfmt\_misc registration mechanism to achieve persistence and privilege escalation without modifying the target binary or setting the SUID bit on the malicious payload itself.

### II.A. Handler Registration Syntax: Parameters for Precision Targeting

A binfmt\_misc rule is defined by a structured string that dictates how the kernel should recognise a file and what interpreter to use. The structure follows the template: `:name:type:offset:magic:mask:interpreter:flags`.

For the Shadow SUID attack, the adversary requires precision targeting. The primary attack vector relies on the M (magic byte) type, which allows the rule to match the specific header of a chosen SUID binary, such as a commonly available utility like chfn. By defining the magic and offset fields, the attacker ensures the rule is triggered only when the system attempts to load the targeted SUID executable. This technique allows the attacker to hijack the execution path without necessitating any alteration to the target SUID binary, which remains cryptographically intact.

The interpreter field specifies the path to the malicious executable (e.g., /dev/shm/malmoeb in the demonstrated examples) that the attacker intends to execute. Critically, this file does not need the SUID bit set on the filesystem.

### II.B. The Abuse of the 'C' (Credentials) Flag: The Core Mechanism

Under normal circumstances, when an interpreter is used (such as /bin/sh for a shell script), the interpreter runs using its own access rights, regardless of the permissions of the wrapper file.

The 'C' flag (credentials) is the critical override that enables the privilege escalation. When the 'C' flag is set in the rule definition, the kernel deviates from normal behaviour and is forced to look up and apply the access rights and credentials of the *original file* being executed (the SUID binary) to the specified malicious interpreter.

The privilege escalation pathway becomes evident when the original, targeted file is a SUID-root binary. Upon execution, the kernel, obeying the 'C' flag mandate, grants the attacker's specified interpreter root privileges (Effective User ID, EUID=0). This entire mechanism bypasses the traditional necessity of finding a vulnerability in the SUID binary itself or relying on standard filesystem SUID checks.

### II.C. The Adversarial Execution Flow: Proxying SUID Calls

The term Shadow SUID accurately describes the technique of using binfmt\_misc to hijack the execution of a trusted SUID binary, allowing the attacker's payload to run with elevated privileges.

The hijack loop is silent and rapid: an unprivileged user executes the target binary (e.g., typing chfn) $\\rightarrow$ the kernel identifies the magic bytes and matches the binfmt\_misc rule $\\rightarrow$ the kernel applies the root credentials of the original binary due to the 'C' flag $\\rightarrow$ the kernel executes the malicious interpreter (e.g., /dev/shm/malmoeb).

A fundamental realisation for DFIR teams is that the original SUID binary, such as chfn, is **never actually executed**; it serves only as a "proxy execution" trigger for the kernel hook.

The malicious interpreter payload often incorporates a stabilisation mechanism. Once executed with root privileges, the compiled code typically utilises functions like setresuid(id, id, id) to permanently set its real, effective, and saved user IDs to 0 (root). This ensures stability and allows the payload to successfully execute a privileged root shell, such as /bin/bash \-p.

This technique exploits a core kernel feature exactly as designed when the 'C' flag is active, meaning the attack is fundamentally a security policy failure rather than a classic software vulnerability (e.g., buffer overflow). Consequently, patching the kernel is not the path to defence; rather, highly stringent control must be exercised over processes allowed to register binfmt\_misc handlers. Furthermore, since the attack relies on targeting generic, ubiquitous SUID-root binaries, this threat demonstrates high portability across all major Linux distributions, establishing it as a foundational persistence and privilege escalation technique for advanced adversaries.

Table 1: binfmt\_misc Handler Field Breakdown and Security Impact

| Field | Description | Security Significance (Shadow SUID) |
| :---- | :---- | :---- |
| name | Handler identifier (Internal label) | Must be monitored for suspicious, non-standard names or collisions with legitimate handlers. |
| type | Matching type (M or E) | Attacker relies on M (magic) for reliable targeting of SUID binary headers. |
| magic/offset/mask | File signature definition | Specifies the exact bytes required to match the SUID target (e.g., chfn). |
| interpreter | Path to the executable payload | Points to the malicious payload, often found in volatile or writable locations (e.g., /dev/shm/) |
| flags | Execution modifiers | **CRITICAL:** The 'C' flag enables credential inheritance from the SUID target, facilitating PrivEsc. |

## III. Forensic Challenges and Advanced Evasion Mechanisms

The Shadow SUID technique is explicitly engineered for stealth, leveraging kernel architecture to actively frustrate traditional host-based forensic analysis and security tooling. It has been noted as a "perfect fit for staying under the radar" because the mechanism itself is "not really known, according to blog posts and articles on the topic," demonstrating low institutional awareness of this vector.

### III.A. The Evasion of SUID Enumeration

One of the most potent elements of evasion is the mechanism's design to circumvent standard security sweeps. The malicious interpreter binary, which ultimately executes the root payload, is specifically designed **not** to have the SUID bit set on the filesystem.

The consequence for digital forensics and incident response (DFIR) is profound: routine security checks or automated triage that search for suspicious SUID binaries using commands like find / \-perm /4000 will fail entirely to identify the attacker's payload. This neutralisation of a primary defensive and hunting mechanism forces investigators to pivot to more complex forms of analysis. The payload is therefore "very hard to find or notice".

### III.B. Execution Proxying and Trace Reduction

The core technical difficulty for security monitoring is that the original SUID binary is "never actually executed"; it serves solely as the trigger for the kernel hook, a "proxy execution".

Security tools, particularly Endpoint Detection and Response (EDR) systems and audit rules designed to alert on the execution of known SUID binaries (e.g., logging every execution of chfn), are rendered ineffective. The process tree, if observed, will show the execution of the malicious interpreter, not the targeted SUID file, leading to the silent bypassing of behavioural detection rules.

An expert noted that the execution chain, relying on built-in shell tools, the /proc filesystem, and hijacking the execution flow, results in "very limited traces to catch". This necessitates a reliance on comprehensive, expensive, and difficult-to-analyse real-time syscall logging, shifting the focus away from simple post-mortem disk analysis toward volatile memory and runtime analysis.

### III.C. Persistence and Volatility

The registered handler is inherently temporary. Since the registration occurs within the volatile /proc virtual filesystem, the handler will be "gone when the system reboots".

This volatility introduces a critical operational requirement for the attacker: they must deploy a separate, secondary persistence mechanism (e.g., cron jobs, systemd units, or initialisation scripts) to re-register the handler and reinstall the interpreter binary after every system reboot. This secondary persistence method provides a separate, and often easier, opportunity for detection by DFIR teams.

Because disk-based artifact analysis is deliberately neutered by the attack (due to the lack of the SUID flag and the proxy execution), DFIR triage must pivot to complex memory forensics and runtime analysis. Identification relies heavily on correlating syscall activity, specifically a write operation targeting /proc/sys/fs/binfmt\_misc/register-with runtime process metadata, such as observing a non-SUID binary running with an effective user ID of 0 (root). This requires a highly mature and capable DFIR program.

The temporal constraint is a crucial weakness for the adversary. If investigators can identify and eliminate the secondary persistence mechanism responsible for handler reinstallation, the attack is effectively neutralised upon the next reboot. This makes persistence monitoring a high-value defensive activity.

Table 2: Comparative Analysis: Traditional SUID Exploits vs. Shadow SUID

| Feature | Traditional SUID Exploits (e.g., Vulnerable Binary) | Shadow SUID (binfmt\_misc Abuse) |
| :---- | :---- | :---- |
| **Mechanism Category** | Memory corruption, logic bug, or environment variable exploitation. | Kernel feature policy abuse. |
| **Payload SUID Flag Required** | No. | **No** (Key to stealth). |
| **Execution Triggered** | Direct execution of the vulnerable SUID binary. | Execution is **proxied**; the SUID binary is never executed. |
| **Forensic Traceability** | Traceable via execution logs of the SUID binary, environment variables (LD\_PRELOAD), and crashing logs. | **Very limited traces** in execution flow; primary trace is the registration event. |
| **Persistence Reliance** | Often requires patching or runtime environment manipulation. | Relies on an external persistence mechanism for handler re-registration. |

## IV. Detection Engineering and Monitoring Strategies for Kernel Feature Abuse

Effective defence against Shadow SUID requires shifting detection focus from application execution analysis to kernel configuration plane monitoring and runtime credential checks. Traditional, application-centric EDR tools often struggle to correlate filesystem metadata (lack of SUID bit) with runtime context (EUID=0) accurately enough, making advanced kernel monitoring tooling (e.g., eBPF or sophisticated auditd configurations) essential.

### IV.A. Auditing the Configuration Plane: Registration Detection

The most reliable proactive detection opportunity is the handler registration event, which must occur with root access. Aggressive monitoring must be implemented for the write() syscall targeting the specific file path /proc/sys/fs/binfmt\_misc/register. This syscall event definitively marks the installation of the attack hook.

Security teams must develop tailored audit rules to specifically flag registration attempts where:

1. The flags field explicitly includes the character 'C'.  
2. The interpreter path points to unexpected, non-standard, or highly volatile and writable locations such as /dev/shm or /tmp.

Contextual auditing, enforced via Mandatory Access Control (MAC) policies (SELinux/AppArmor), should restrict processes authorised to modify binfmt\_misc settings. This strategy is critical because the attack is fundamentally a policy failure; prevention relies on restricting administrative access to the kernel configuration points.

### IV.B. Runtime Credential and Process Monitoring

The single most reliable indicator of a successful Shadow SUID exploitation is detecting an executable that **does not** possess the SUID bit running with an Effective User ID (EUID) of 0 (root).

EDR and monitoring logic must be sophisticated enough to trace the process lineage accurately. The challenge lies in correlating the initial execution attempt (e.g., a user invoking chfn) with the resulting process (the malicious interpreter), recognising the kernel-level execution hijack even when the process parentage appears benign or is obscured.

Furthermore, monitoring for the specific syscall sequence used by the payload is highly valuable. The immediate execution of the setresuid(0, 0, 0\) syscall confirms the interpreter's successful self-stabilisation into a persistent root shell, indicating a successful escalation of privileges.

### IV.C. Filesystem and Integrity Verification

While the payload location may be volatile, systematic verification remains necessary. Automated tools should regularly check the contents of /proc/sys/fs/binfmt\_misc/ for active handlers, specifically focusing on rules registered via magic bytes that intentionally match the headers of common SUID binaries.

File Integrity Monitoring (FIM) or specialised threat hunting should be deployed to monitor volatile directories (like /dev/shm) for unexpected file creation, particularly executables, as these temporary locations are frequently utilised by attackers to stage their interpreter payloads.

Table 3: DFIR Artifact Matrix for binfmt\_misc Attack Detection

| Artifact | Source/Location | Detection Value | Required Monitoring Strategy |
| :---- | :---- | :---- | :---- |
| Handler Registration Write | Audit Logs (Syscall write to /proc/sys/fs/binfmt\_misc/register) | High: Confirms installation of the hook (Requires root access). | Kernel Auditing (Auditd, eBPF) targeting specific write syscalls and path. |
| Malicious Interpreter Payload | Non-standard, writable locations (/dev/shm/, /tmp/) | Medium: Identifies the payload. | Filesystem Integrity Monitoring (FIM) focused on suspicious file creation in volatile areas. |
| Runtime Credential Anomaly | Process Metadata (/proc/\[pid\]/status EID/UID) | High: Definitive proof of privilege escalation by a non-SUID binary. | Real-time EDR monitoring for EUID/RUID mismatch on executables without SUID bit. |
| Secondary Persistence Trace | Cron tables, Systemd configurations, Shell history | Medium: Identifies the mechanism for persistence across reboots. | Traditional host monitoring and behavioural analysis. |

## V. Mitigation, Hardening, and Remediation Strategies

Neutralising the Shadow SUID threat requires a layered defensive posture focusing on prevention, immediate response, and long-term hardening of the policy layer.

### V.A. Configuration Hardening and Access Control

The principle of least privilege must be rigorously applied to kernel configuration interfaces. Robust Mandatory Access Control (MAC) policies (e.g., SELinux or AppArmor) must be implemented to strictly limit which system subjects can interact with the binfmt\_misc registration mechanism. Only trusted kernel management processes should hold the necessary capabilities, such as CAP\_SYS\_ADMIN, to write to this path. By restricting these privileges, unauthorised registration attempts are blocked, preventing the attack from ever being installed.

Organisations must also conduct a thorough operational assessment to determine if the binfmt\_misc feature can be safely disabled entirely. If custom execution wrappers or emulation layers are not critical to system function, disabling the feature via kernel boot parameters (binfmt\_misc=0) eliminates the attack vector completely, acknowledging the potential operational impact.

### V.B. Incident Response and Remediation Procedures

Upon confirmed detection, immediate action must focus on eliminating the kernel hook. The malicious handler must be immediately removed by writing the value \-1 to the appropriate handler file within the /proc/sys/fs/binfmt\_misc/ directory.

However, since the handler resides in a volatile virtual filesystem and is temporary, a controlled system reboot is considered the most effective and decisive means to eliminate the kernel hook and prevent immediate re-use.

Post-reboot, the DFIR investigation must shift entirely to the critical task of Root Cause Analysis (RCA): identifying and eradicating the initial root compromise vector and, crucially, the secondary persistence mechanism responsible for re-installing the handler and payload. The attacker's persistence Achilles heel-the requirement for an external, non-kernel mechanism to survive reboots-provides a high-value target for remediation.

### V.C. Long-Term Defensive Engineering Posture

Due to the reliance of this attack on low institutional knowledge, organisational threat awareness training is mandatory. Security operations centre (SOC) staff and DFIR analysts must be educated about advanced kernel abuse techniques that exploit core features, like Shadow SUID.

Furthermore, security engineering should integrate automated tooling that periodically verifies the specific SUID binaries most vulnerable to this targeting (e.g., chfn, passwd, etc.). This verification should ensure that the magic bytes of these binaries are not currently matched by any active, potentially malicious binfmt\_misc handler registered on the system.

## Conclusions

The Shadow SUID exploitation of the Linux kernel's binfmt\_misc subsystem represents a significant advancement in adversarial privilege escalation and persistence techniques, moving the battleground from application vulnerabilities to core operating system policy abuse. The analysis confirms that the user-proposed summary lacks the necessary technical detail, failing to highlight the critical role of the 'C' flag and the evasion through proxy execution.

The high stealth of this method stems directly from the kernel operating as designed: inheriting credentials when directed by the 'C' flag and executing the interpreter without the SUID binary ever launching. This places the attack outside the detection scope of conventional SUID enumeration and execution monitoring tools. Detection success hinges on robust, kernel-aware tooling capable of:

1. **Proactively** monitoring for the specific syscall operation that registers the handler (writing to /proc/sys/fs/binfmt\_misc/register).  
2. **Reactively** identifying the highly anomalous runtime state where a non-SUID binary runs with effective root credentials.

Effective mitigation requires a strategic defensive shift, prioritising policy restriction over vulnerability patching. Organisations must enforce strict Mandatory Access Control policies to prevent unauthorised modification of the binfmt\_misc configuration and prioritise the hunting and elimination of external persistence mechanisms designed to reinstall the volatile kernel hook after system reboots.

## Reference

Today I learned: binfmt\_misc | dfir.ch, accessed on November 23, 2025, [https://dfir.ch/posts/today\_i\_learned\_binfmt\_misc/](https://dfir.ch/posts/today_i_learned_binfmt_misc/)
