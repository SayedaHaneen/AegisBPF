#!/usr/bin/env bash
# Benign Fileless RAM Execution Simulation (MITRE ATT&CK T1059 / T1620)
echo "[*] Creating harmless payload in volatile memory partition /dev/shm..."
cat << 'EOF' > /dev/shm/aegis_test_payload.sh
#!/bin/bash
echo "[+] Harmless payload executing from /dev/shm (RAM)!"
sleep 2
EOF

chmod +x /dev/shm/aegis_test_payload.sh
echo "[*] Triggering execution from RAM..."
/dev/shm/aegis_test_payload.sh

# Cleanup
rm -f /dev/shm/aegis_test_payload.sh
echo "[+] Simulation finished."
