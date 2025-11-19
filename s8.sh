#!/bin/bash
wget https://cdn.zabbix.com/zabbix/sources/stable/6.4/zabbix-6.4.20.tar.gz
tar -zxvf zabbix-6.4.20.tar.gz
addgroup --system --quiet zabbix
adduser --quiet --system --disabled-login --ingroup zabbix --home /var/lib/zabbix --no-create-home zabbix
