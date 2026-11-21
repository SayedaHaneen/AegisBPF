import socket
import struct
from datetime import datetime

EVENT_EXEC = 1
EVENT_CONNECT = 2
EVENT_PTRACE = 3

SUSPICIOUS_EXEC_PATHS = ("/dev/shm", "/tmp", "/var/tmp", "memfd:")
SHELL_NAMES = {"sh", "bash", "dash", "zsh", "python", "python3", "perl", "ruby", "nc", "ncat", "netcat"}

class ThreatEngine:
    def __init__(self):
        self.alert_history = []

    def evaluate(self, event):
        """
        Takes raw decoded kernel event and evaluates MITRE ATT&CK detection heuristics.
        Returns an enriched telemetry dict with threat metadata.
        """
        timestamp = datetime.utcnow().strftime("%H:%M:%S.%f")[:-3]
        event_dict = {
            "timestamp": timestamp,
            "pid": event.pid,
            "ppid": event.ppid,
            "uid": event.uid,
            "comm": event.comm.decode("utf-8", "replace").strip(),
            "severity": "INFO",
            "threat": None,
            "mitre": None,
            "description": "Standard system operation",
        }

        # 1. EVALUATE EXECUTION EVENTS (execve)
        if event.event_type == EVENT_EXEC:
            filename = event.filename.decode("utf-8", "replace").strip()
            event_dict["filename"] = filename
            event_dict["event_type"] = "EXECVE"

            # Check for fileless / RAM execution
            for bad_path in SUSPICIOUS_EXEC_PATHS:
                if filename.startswith(bad_path):
                    event_dict["severity"] = "CRITICAL"
                    event_dict["threat"] = "Fileless RAM Execution"
                    event_dict["mitre"] = "T1059 / T1620 (Reflective Code Loading)"
                    event_dict["description"] = f"Binary executed from volatile RAM storage partition: {filename}"
                    break

        # 2. EVALUATE OUTBOUND NETWORK CONNECTIONS (connect)
        elif event.event_type == EVENT_CONNECT:
            ip_str = socket.inet_ntoa(struct.pack("<I", event.daddr))
            port = event.dport
            event_dict["destination"] = f"{ip_str}:{port}"
            event_dict["event_type"] = "CONNECT"

            # Check for Reverse Shell or C2 Beaconing
            is_shell = event_dict["comm"] in SHELL_NAMES
            is_non_loopback = not ip_str.startswith("127.") and ip_str != "0.0.0.0"

            if is_shell and is_non_loopback:
                event_dict["severity"] = "CRITICAL"
                event_dict["threat"] = "Outbound Interactive Reverse Shell / C2 Beacon"
                event_dict["mitre"] = "T1071 (Application Layer Protocol) / T1059"
                event_dict["description"] = f"Interactive shell ({event_dict['comm']}) opened socket to remote IP {ip_str}:{port}"
            elif is_non_loopback:
                event_dict["severity"] = "LOW"
                event_dict["description"] = f"Outbound socket opened by {event_dict['comm']} to {ip_str}:{port}"

        # 3. EVALUATE PROCESS INJECTION (ptrace)
        elif event.event_type == EVENT_PTRACE:
            event_dict["event_type"] = "PTRACE"
            event_dict["target_pid"] = event.target_pid
            event_dict["ptrace_req"] = event.ptrace_req

            event_dict["severity"] = "CRITICAL"
            event_dict["threat"] = "Cross-Process Memory Tampering / Injection"
            event_dict["mitre"] = "T1055 (Process Injection)"
            event_dict["description"] = f"Process {event_dict['comm']} (PID {event.pid}) attached or modified memory of Target PID {event.target_pid}"

        return event_dict
