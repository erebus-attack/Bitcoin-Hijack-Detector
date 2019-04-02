import os, sys
from os import listdir
from os.path import isfile, join
import shlex, subprocess
from collections import defaultdict
from ipaddress import ip_network
import ipaddress
import ipaddress, sys
import sys


btc_ip_file = "path-to-Bitcoin-ip-addresses-data"
with open(btc_ip_file) as f:
    content = f.readlines()
btc_ip_list = [x.strip() + ":8333" for x in content]

btc_ip_header_set = set()
btc_ip_header_dict = dict()

for btc_ip in btc_ip_list:
    btc_ip = btc_ip.strip('[]')

    if 'onion' in btc_ip: # take only ipv4 or ipv6 addresses into account.
        continue

    if '.' in btc_ip:
        btc_ip_header = btc_ip[0:btc_ip.index('.', btc_ip.index('.') + 1) + 1]
    elif ':' in btc_ip:
        btc_ip_header = btc_ip[0:btc_ip.index(':', btc_ip.index(':') + 1) + 1]
    btc_ip_header_set.add(btc_ip_header)
    if btc_ip_header not in btc_ip_header_dict:
        btc_ip_header_dict[btc_ip_header] = list()
    btc_ip_header_dict[btc_ip_header].append(btc_ip)

result_path = "path-to-the-result-file"
result_file = open(result_path, 'w')



ris_ripe_data_path = "path-to-the-ris-ripe-data-file"
with open(ris_ripe_data_path) as f:
    content = f.readlines()
announcements = [x.strip() for x in content]



for raw_line in announcements :
    if("BGP4MP" not in raw_line) : continue
    prefix = raw_line.split('|')[5]
    prefix_header = ""
    if '.' in prefix:
        prefix_header = prefix[0:prefix.index('.', prefix.index('.') + 1) + 1]
    elif ':' in prefix:
        prefix_header = prefix[0:prefix.index(':', prefix.index(':') + 1) + 1]
    if prefix_header in btc_ip_header_set:

        btc_ip_included = False
        btc_ip_set = set()
        for btc_ip in btc_ip_header_dict[prefix_header]:
            if ipaddress.ip_address(btc_ip) in ipaddress.ip_network(prefix):
                btc_ip_set.add(btc_ip)
                btc_ip_included = True
        if btc_ip_included:
            result_file.write(raw_line + '\n')
result_file.close()

