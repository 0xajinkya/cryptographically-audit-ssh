#!/bin/bash

# Script to set up a vulnerable SSH server with old cryptographic algorithms
# For testing purposes only. Do NOT expose this server to the internet.

# Step 1: Update and install OpenSSH server
echo "Updating package list and installing OpenSSH server..."
sudo apt update
sudo apt install -y openssh-server

# Step 2: Create missing privilege separation directory for sshd
echo "Creating missing /run/sshd directory..."
sudo mkdir -p /run/sshd
sudo chmod 755 /run/sshd

# Step 3: Backup the existing SSH configuration
CONFIG_FILE="/etc/ssh/sshd_config"
BACKUP_FILE="/etc/ssh/sshd_config.bak"
if [[ -f "$CONFIG_FILE" ]]; then
    echo "Backing up existing SSH configuration..."
    sudo cp "$CONFIG_FILE" "$BACKUP_FILE"
else
    echo "SSH configuration file not found. Exiting."
    exit 1
fi

# Step 4: Configure old cryptographic algorithms and enable password authentication
echo "Configuring old cryptographic algorithms and enabling password authentication..."
sudo bash -c "cat > $CONFIG_FILE" <<EOF

# Configuration for testing with old cryptographic algorithms
KexAlgorithms diffie-hellman-group1-sha1,diffie-hellman-group14-sha1
Ciphers aes128-ctr,aes256-ctr
MACs hmac-sha1,hmac-md5
HostKeyAlgorithms ssh-rsa,ssh-dss

# Allow password authentication (important for testing)
PasswordAuthentication yes

# Allow root login (optional, for testing purposes only)
PermitRootLogin yes
EOF

# Step 5: Restart the SSH service to apply changes
echo "Restarting SSH service to apply changes..."
sudo systemctl restart ssh

# Step 6: Output server details
echo "Vulnerable SSH server setup complete!"
echo "You can connect to this server on port 22."
echo "If this is a local server, use 'ssh localhost'."
