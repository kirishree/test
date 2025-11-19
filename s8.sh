#!/bin/bash
wget https://cdn.zabbix.com/zabbix/sources/stable/7.0/zabbix-7.0.21.tar.gz
tar -zxvf zabbix-7.0.21.tar.gz
addgroup --system --quiet zabbix
adduser --quiet --system --disabled-login --ingroup zabbix --home /var/lib/zabbix --no-create-home zabbix
