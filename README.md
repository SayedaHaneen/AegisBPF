# 🛡️ AegisBPF: Kernel-Native Runtime Threat Hunter & Tactical SOC

[![Linux](https://img.shields.io/badge/OS-Linux%20Kernel%205.8+-orange?style=for-the-badge&logo=linux&logoColor=white)](https://kernel.org)
[![eBPF](https://img.shields.io/badge/Powered%20By-eBPF%20%2F%20BCC-blueviolet?style=for-the-badge&logo=ebpf&logoColor=white)](https://ebpf.io/)
[![Python](https://img.shields.io/badge/Backend-Python%203.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/Streaming-FastAPI%20%26%20WebSockets-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![MIT License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/Threat%20Coverage-MITRE%20ATT%26CK-red?style=for-the-badge)](https://attack.mitre.org/)

> **AegisBPF** is a high-performance, kernel-native runtime security monitoring agent and threat-hunting platform. Leveraging **eBPF (Extended Berkeley Packet Filter)** probes hooked directly into the Linux kernel, AegisBPF captures malicious syscall patterns in real-time with sub-microsecond latency, bypassing user-space tampering and streaming actionable intelligence directly to a futuristic tactical SOC dashboard.

---

## ⚡ High-Level Architecture

```
                    ┌────────────────────────────────────────────────────────┐
                    │                      LINUX KERNEL                      │
                    │                                                        │
                    │   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
                    │   │ hook: execve │  │ hook: ptrace │  │ hook: connect│ │
                    │   └──────┬───────┘  └──────┬───────┘  └──────┬───────┘ │
                    └──────────┼─────────────────┼─────────────────┼─────────┘
                               │ eBPF Perf Ring Buffers (Zero Copy)│
                    ┌──────────▼─────────────────▼─────────────────▼─────────┐
                    │               AEGIS CORE AGENT (User Space)            │
                    │                                                        │
                    │  [Event Decoder] ──► [Threat Detection Engine]         │
                    │                             │                          │
                    │                  ┌──────────┴──────────┐               │
                    │                  ▼                     ▼               │
                    │         [Heuristic Rules]    [MITRE ATT&CK Matrix]     │
                    └──────────────────┬─────────────────────┬───────────────┘
                                       │                     │
                    ┌──────────────────▼──────┐   ┌──────────▼───────────────┐
                    │     TACTICAL CLI HUD    │   │  FASTAPI WEBSOCKET RELAY │
                    │ (Real-time Syslog View) │   └──────────┬───────────────┘
                    └─────────────────────────┘              │
                                                  ┌──────────▼───────────────┐
                                                  │ CYBERPUNK SOC DASHBOARD  │
                                                  │  - Live Threat Radar     │
                                                  │  - Memory Exploit Feeds  │
                                                  │  - 1-Click Process Kill  │
                                                  └──────────────────────────┘
```

---

## 🎯 Threat Detection & MITRE ATT&CK Coverage

AegisBPF monitors critical kernel syscall transitions to neutralize attacks that bypass traditional disk-based AV:

| Threat Category | Syscall Hook | MITRE ATT&CK Technique | Detection Mechanism |
| :--- | :--- | :--- | :--- |
| **Fileless RAM Execution** | `sys_enter_execve` | [T1059](https://attack.mitre.org/techniques/T1059/) | Identifies binaries executed directly from volatile memory partitions (`/dev/shm`, `memfd:*`, `/tmp`). |
| **Process Injection** | `sys_enter_ptrace` | [T1055](https://attack.mitre.org/techniques/T1055/) | Flags unauthorized cross-process memory manipulation (e.g., shellcode injection into `nginx`/`systemd`). |
| **Reverse Shells / C2 Beaconing** | `sys_enter_connect` | [T1071](https://attack.mitre.org/techniques/T1071/) | Correlates interactive shell processes (`bash`, `sh`, `zsh`, `python`) initiating outbound socket handshakes. |
| **Abnormal Privilege Shifts** | `sys_enter_setuid` | [T1068](https://attack.mitre.org/techniques/T1068/) | Detects unexpected privilege escalations to `root` (UID 0) originating from non-authorized parent processes. |

---

## 🔮 Tactical SOC Dashboard Highlights

* **Neon-Glassmorphism HUD:** Designed like an active cyber-defense command center with responsive ambient lighting.
* **Live Vector Threat Radar:** Continuous circular radar sweep that dynamically plots high-risk kernel telemetries.
* **Process Telemetry Matrix:** Real-time stream of parent/child PIDs, arguments, UIDs, and network endpoints.
* **Defensive Containment (Kill-Switch):** One-click manual or automated `SIGKILL` termination of suspicious processes directly from the UI.

---

## 🛠️ Project Directory Structure

```text
AegisBPF/
├── agent/
│   ├── probes/
│   │   ├── execve.c          # eBPF probe for execution monitoring
│   │   ├── ptrace.c          # eBPF probe for memory tampering
│   │   └── connect.c         # eBPF probe for socket network connections
│   ├── rules/
│   │   ├── fileless_rules.py # RAM execution heuristics
│   │   ├── network_rules.py  # Reverse shell detection logic
│   │   └── injection_rules.py# Memory tampering heuristics
│   └── daemon.py             # Core BCC runtime loop
├── server/
│   └── app.py                # FastAPI WebSocket server & REST dispatcher
├── dashboard/
│   ├── index.html            # Tactical Cyberpunk SOC Interface
│   ├── radar.js              # Animated threat radar canvas engine
│   └── styles.css            # Custom glassmorphic neon aesthetic
├── simulations/
│   ├── sim_reverse_shell.py  # Benign simulated C2 connection test
│   ├── sim_fileless_exec.sh  # Benign /dev/shm RAM execution test
│   └── sim_injection.c       # Benign ptrace process attachment test
├── requirements.txt
└── README.md
```

---

## 🚀 Quickstart Guide

### 1. Prerequisites
* **Operating System:** Linux Kernel 5.8+ (Ubuntu 20.04/22.04 LTS or WSL2 with kernel headers).
* **Compiler & Headers:** `clang`, `llvm`, `linux-headers-$(uname -r)`.
* **Python Runtime:** Python 3.10+ with BCC (BPF Compiler Collection) bindings.

### 2. Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/AegisBPF.git
cd AegisBPF

# Install dependencies (Ubuntu / WSL2)
sudo apt update
sudo apt install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc python3-pip

# Install Python requirements
pip3 install -r requirements.txt
```

### 3. Launching AegisBPF

```bash
# Start the Backend Agent & WebSocket Dispatcher (Requires root privileges for eBPF hooks)
sudo python3 -m server.app

# Open the Tactical SOC Dashboard
# Navigate to http://localhost:8000 in your browser
```

---

## 🔬 Research & Academic Background

Traditional Linux monitoring solutions (e.g., `auditd`, LD_PRELOAD hooks, ptrace wrappers) introduce significant performance overhead or can be readily bypassed by sophisticated rootkits and namespace manipulation.

**AegisBPF** operates at the **VFS and Syscall boundaries within the Linux Kernel**, running inside the kernel's in-tree bytecode sandbox. This ensures:
1. **Tamper Resistance:** Attackers in user-space cannot alter in-kernel verification hooks.
2. **Deterministic Latency:** Zero context-switching overhead for discarded events.
3. **Container-Aware Telemetry:** Native visibility across Linux cgroups, namespaces, and Docker/Kubernetes pods.

---

## 📜 License
Distributed under the **MIT License**. See `LICENSE` for more information.
