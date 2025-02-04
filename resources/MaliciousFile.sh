#!/bin/bash

# This is a malicious script that executes arbitrary commands
echo "This is a test of a malicious file" >> /tmp/malicious_log.txt
date >> /tmp/malicious_log.txt
hostname >> /tmp/malicious_log.txt
