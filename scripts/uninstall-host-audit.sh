#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then echo "Run as root: sudo $0" >&2; exit 1; fi
rm -f /etc/audit/rules.d/70-sentinel.rules
augenrules --load
echo "Sentinel audit rules removed. auditd remains installed and active."
