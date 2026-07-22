#!/bin/bash

# Exit on error
set -e

echo "[*] Adding Wazuh GPG key and repository..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import || true
chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list

echo "[*] Updating apt..."
apt-get update -y

echo "[*] Installing Wazuh Agent..."
WAZUH_MANAGER="127.0.0.1" apt-get install -y wazuh-agent

echo "[*] Enabling and starting Wazuh Agent..."
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

echo "[*] Wazuh Agent deployed successfully on local machine!"
sleep 3
echo "[*] Checking agent status..."
/var/ossec/bin/wazuh-control info || true
