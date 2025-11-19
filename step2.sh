#!/bin/bash
wget https://ftp.postgresql.org/pub/source/v14.0/postgresql-14.0.tar.bz2
sudo apt-get install build-essential libreadline-dev zlib1g-dev flex bison libxml2-dev libxslt-dev libssl-dev libxml2-utils xsltproc ccache
sudo apt-get install lbzip2
tar xf postgresql-14.0.tar.bz2
sudo apt-get install libicu-dev
sudo apt-get -y install pkg-config
./configure
