import ctypes
import os
import subprocess
import time

# Benign Process Injection / ptrace attachment test (MITRE ATT&CK T1055)
libc = ctypes.CDLL("libc.so.6")
PTRACE_ATTACH = 16
PTRACE_DETACH = 17

# Spawn a harmless sleep process
p = subprocess.Popen(["sleep", "5"])
target_pid = p.pid
print(f"[*] Spawned target process PID {target_pid}...")
time.sleep(0.5)

print(f"[*] Simulating memory inspection/attachment via ptrace to PID {target_pid}...")
ret = libc.ptrace(PTRACE_ATTACH, target_pid, None, None)
if ret == 0:
    print("[+] Successfully attached via ptrace! (Kernel should catch this)")
    time.sleep(1)
    libc.ptrace(PTRACE_DETACH, target_pid, None, None)
else:
    print(f"[-] ptrace returned code {ret}")

p.kill()
print("[+] Process injection probe finished. Check AegisBPF dashboard for T1055 breach alert!")
