# eBPF Rootkits: The Stealthy Evolution of Linux Malware

Extended Berkeley Packet Filter (eBPF) is a revolutionary technology in the Linux kernel that allows sandboxed programs to run in kernel space without modifying the kernel source code. Originally designed for network packet filtering, its use has exploded into areas like observability, security, and performance monitoring. However, this powerful capability has also been weaponized by sophisticated threat actors to create a new generation of stealthy and evasive rootkits that operate entirely from user space while manipulating kernel-space data and logic.

## How eBPF Rootkits Work

Traditional Linux rootkits operate by directly modifying the kernel's memory (e.g., syscall table hooking) or loading malicious kernel modules. These methods are relatively noisy and can be detected by modern integrity-checking tools and EDR solutions.

eBPF rootkits, in contrast, are far more subtle. They work by **loading legitimate eBPF bytecode into the kernel** through the standard, unprivileged (or sometimes privileged) `bpf()` system call. Once loaded, these eBPF programs can be attached to various kernel "hook" points, such as:

* **Tracepoints and Kprobes:** To intercept and modify the flow of kernel functions before they return to user space.
* **Socket Filters and XDP (eXpress Data Path):** To inspect, drop, or manipulate network traffic at line rate.

The key to their stealth is that they **do not alter the kernel's code or static data structures**. Instead, they dynamically filter or modify the data that is *returned* to user-space applications. This means the malicious logic resides in the eBPF program itself, which lives in a protected map in kernel memory, making it extremely difficult to detect with traditional forensic tools.

For example, an eBPF rootkit can use the `kretprobe` (kernel return probe) mechanism to hook the `getdents` or `getdents64` system calls, which are responsible for listing directory contents. When a user runs `ls`, the rootkit can intercept the response from the kernel and remove any entries that match its hidden files or directories before the data is sent back to the `ls` command, effectively making them invisible.

## Real-World Examples of eBPF Malware

### BPFDoor

**BPFDoor** is the most prominent and well-documented example of an eBPF-powered backdoor in the wild. It has been attributed to **China-based threat actors**, including groups tracked as **Red Menshen and Earth Lusca** [^2]. First observed in 2021, it has since been found on thousands of compromised Linux systems globally [^2].

BPFDoor is a **passive backdoor**, meaning it doesn't beacon out to a command-and-control (C2) server. Instead, it waits silently for an attacker to send a specially crafted "knock" packet. This packet contains an encrypted password. The eBPF program, attached to the network stack (likely via a socket filter or XDP), intercepts all incoming traffic. When it detects a packet with the correct password, it opens a hidden network port that provides the attacker with a direct, unlogged shell on the compromised host [^1].

Its primary stealth capability is its use of eBPF to **hide its own network activity and processes** from any user-space monitoring tools. Because the eBPF program filters network data at the kernel level, tools like `netstat` or `ss` will not show the open port used by the backdoor [^1].

### LinkPro

Discovered in 2024, **LinkPro** is another sophisticated eBPF-based rootkit that demonstrates the adaptive nature of this threat [^6]. It is a Golang-based rootkit that was found targeting AWS-hosted infrastructure [^3]. Like BPFDoor, it uses eBPF for concealment, specifically to **intercept the `getdents` system call to hide files and directories** [^5].

What makes LinkPro notable is its activation mechanism. The rootkit remains dormant until it is triggered by a specific, hidden file being created in the `/tmp` directory or by a TCP packet with a window size of 54321 [^4]. This "dead man's switch" design makes it incredibly difficult to analyze in a sandbox, as the malicious eBPF programs are only loaded after the trigger condition is met [^3].

### ebpfkit

While not known to be used in active campaigns, **ebpfkit** is a publicly available, open-source proof-of-concept rootkit that demonstrates the full range of capabilities available to an eBPF attacker. Created by security researcher Guillaume Fournier, it serves as a blueprint for malicious actors [^8].

ebpfkit can:

* Hide processes, files, and network connections.
* Escalate privileges by hooking credential-related kernel functions.
* Bypass security modules like AppArmor.
Its existence proves that a feature-rich, powerful rootkit can be built entirely on the eBPF framework without ever loading a single kernel module [^8]. The source code is available on GitHub at: [https://github.com/Gui774ume/ebpfkit](https://github.com/Gui774ume/ebpfkit) [^7]].

## Why eBPF Rootkits Are a Critical Threat

1. **Unprecedented Stealth:** They leave minimal traces. No modified kernel code, no new kernel modules (`.ko` files), and no unusual processes. The malicious logic is a bytecode program running in a kernel-verified virtual machine.
2. **Legitimate Mechanism:** They abuse a core, trusted, and widely used Linux subsystem. Blocking eBPF entirely is often not feasible in modern cloud and containerised environments, as it is used by legitimate security and monitoring tools like Cilium and Falco.
3. **Evasion of Traditional EDR:** Most Endpoint Detection and Response (EDR) solutions for Linux are not yet equipped to inspect or monitor the loading and behaviour of eBPF programs in real-time. They focus on file system and process activity, which the rootkit can easily hide from.
4. **Persistence:** An eBPF program can be loaded and remain active until the system is rebooted, providing a stable, hidden foothold.

In conclusion, eBPF rootkits like BPFDoor and LinkPro represent a significant shift in the Linux threat landscape, moving from crude kernel modifications to elegant and stealthy manipulations of kernel data flows. Defending against them requires a new generation of security tools that can introspect the eBPF subsystem itself.

## References

[^1]: BPFDoor - An Evasive Linux Backdoor Technical Analysis. Available at: <https://www.leveryd.com/bpfdoor-technical-analysis> (Summary from web search result).
[^2]: BPFDoor (Malware Family) - Recorded Future. Available at: <https://www.recordedfuture.com/>
[^3]: New Linux rootkit "LinkPro" uses eBPF, spreads via Docker. Available at: <https://securityaffairs.com/>
[^4]: LinkPro Linux Rootkit Uses eBPF to Hide and Activates via Secret "Magic". Available at: <https://www.infosecurity-magazine.com/>
[^5]: LinkPro Linux Rootkit cleanup report. (Summary from web search result).
[^6]: A Linux rootkit called LinkPro, first discovered in 2024. Available at: <https://www.bleepingcomputer.com/>
[^7]: Guillaume Fournier (Gui774ume) - ebpfkit repository. Available at: <https://github.com/Gui774ume/ebpfkit>
[^8]: ebpfkit is a rootkit powered by eBPF. Available at: <https://github.com/Gui774ume/ebpfkit>
