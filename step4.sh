#!/bin/bash
#sudo apt install apache2
sudo apt install software-properties-common ca-certificates lsb-release apt-transport-https -y
sudo add-apt-repository ppa:ondrej/php
sudo apt update
sudo apt install php8.1 
sudo apt install libapache2-mod-php
sudo apt-get install -y php8.1-cli php8.1-common php8.1-mysql php8.1-zip php8.1-gd php8.1-mbstring php8.1-curl php8.1-xml php8.1-bcmath php8.1-ldap php8.1-pgsql
