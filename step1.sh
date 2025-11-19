#!/bin/bash
original_dir=$(pwd)
echo "Start to install Dependencies"
sudo apt update
sudo apt install -y net-tools python3-dev python3-pip iproute2 netplan.io pptpd pptp-linux
sudo modprobe ppp_generic
sudo modprobe pppoe
sudo modprobe ppp_async
pip install pymongo psutil netaddr pyroute2 django python-decouple gunicorn pytz python-dotenv python-dateutil
pip install django-cors-headers django_ratelimit djangorestframework-simplejwt
ufw allow 5000 500 4789/udp 89 53 22 67/udp 179/tcp
ufw disable
is_mongodb_installed() {
    if pgrep mongo >/dev/null 2>&1; then
        return 0  # MongoDB is installed
    else
        return 1  # MongoDB is not installed
    fi
}
if is_mongodb_installed; then
    echo "MongoDB is already installed."
else
    echo "Start to install MongoDB."
    apt-get install gnupg curl
    curl -fsSL https://pgp.mongodb.com/server-6.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-6.0.gpg --dearmor
    echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-6.0.gpg ] https://repo.mongodb.com/apt/ubuntu focal/mongodb-org/7.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
    apt update
    apt-get install -y mongodb
    systemctl daemon-reload
    if systemctl start mongodb.service; then
        if systemctl enable mongodb.service; then
            echo "MongoDB is installed successfully."
        fi
    else
        echo "Error in installing MongoDB. Pl try to install again."
        cd "$original_dir" || exit 
    fi
fi
working_DIR="/etc/reach"
if [ -d "$working_DIR" ]; then
    echo "Directory $DIR exists."
else:
    echo "Creating Working Directory"
    mkdir -p /etc/reach
    if [ $? -eq 0 ]; then
        echo "Directory $working_DIR created successfully."
    else
        echo "Failed to create directory $working_DIR."
        cd "$original_dir" || exit 
    fi
fi
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p
echo "Disabling unattended upgrades"
echo 'Unattended-Upgrade::Automatic-Reboot "false";' >> /etc/apt/apt.conf.d/50unattended-upgrades
systemctl restart unattended-upgrades
echo "Configuring Time Zone"
timedatectl set-timezone Asia/Riyadh
