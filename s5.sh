#!/bin/bash
sudo rm /etc/apt/sources.list.d/ondrej-ubuntu-php-focal.list
echo "deb [arch=amd64] http://ppa.launchpad.net/ondrej/php/ubuntu focal main" | sudo tee /etc/apt/sources.list.d/ondrej-php.list
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys E5267A6C
sudo apt update
