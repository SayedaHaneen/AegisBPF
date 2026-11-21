import socket
import sys
import time

# Benign Reverse Shell Simulation (MITRE ATT&CK T1071 / T1059.004)
# Attempts an outbound socket handshake to a remote IP
TARGET_IP = "1.1.1.1" # Cloudflare DNS IP (Harmless external probe)
TARGET_PORT = 4444

print(f"[*] Simulating reverse shell outbound handshake from Python to {TARGET_IP}:{TARGET_PORT}...")
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.5)
    s.connect((TARGET_IP, TARGET_PORT))
except Exception as e:
    print(f"[*] Handshake initiated (Connection expectedly closed: {e})")
finally:
    s.close()

print("[+] Reverse shell probe triggered. Check AegisBPF dashboard for T1071 breach alert!")
