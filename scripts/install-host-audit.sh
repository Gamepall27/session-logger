#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

command -v auditctl >/dev/null 2>&1 || {
  apt-get update
  apt-get install -y auditd audispd-plugins
}

SAMBA_PATHS="${SAMBA_PATHS:-/srv/samba}"
RULE_FILE=/etc/audit/rules.d/70-sentinel.rules

{
  echo "## Managed by session-logger/scripts/install-host-audit.sh"
  echo "-a always,exit -F arch=b64 -S execve,execveat -F auid>=1000 -F auid!=unset -k user-exec"
  echo "-a always,exit -F arch=b32 -S execve,execveat -F auid>=1000 -F auid!=unset -k user-exec"
  echo "-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid -F auid>=1000 -F auid!=unset -k privilege"
  echo "-w /etc/passwd -p wa -k identity-change"
  echo "-w /etc/group -p wa -k identity-change"
  echo "-w /etc/sudoers -p wa -k privilege"
  echo "-w /etc/ssh/sshd_config -p wa -k ssh-config"
  for audit_path in $(printf '%s' "$SAMBA_PATHS" | tr ',' ' '); do
    if [ -d "$audit_path" ]; then
      echo "-w $audit_path -p wa -k samba-files"
    else
      echo "Warning: Samba path does not exist and was skipped: $audit_path" >&2
    fi
  done
} > "$RULE_FILE"

chmod 600 "$RULE_FILE"
augenrules --load
systemctl enable --now auditd
auditctl -s
echo "Sentinel audit rules installed in $RULE_FILE"
