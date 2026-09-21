#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then echo "Run as root: sudo $0" >&2; exit 1; fi
command -v docker >/dev/null 2>&1 || { echo "Docker is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

container="${SAMBA_CONTAINER:-samba}"
compose_file="$(docker inspect "$container" --format '{{ index .Config.Labels "com.docker.compose.project.config_files" }}')"
project="$(docker inspect "$container" --format '{{ index .Config.Labels "com.docker.compose.project" }}')"
project_dir="$(dirname "$compose_file")"
include_dir=/etc/sentinel
include_file="$include_dir/samba-audit.conf"

test -f "$compose_file" || { echo "Compose file not found: $compose_file" >&2; exit 1; }
mkdir -p "$include_dir"
current_vfs="$(docker exec "$container" testparm -s --section-name=files --parameter-name='vfs objects' 2>/dev/null || true)"
case " $current_vfs " in *" full_audit "*) ;; *) current_vfs="$current_vfs full_audit" ;; esac
{
  printf '[global]\nlog level = 1 full_audit:1\n\n[files]\nvfs objects =%s\n' "$current_vfs"
  grep '^full_audit:' "$(dirname "$0")/../config/samba-full-audit.conf.example"
} > "$include_file"
chmod 644 "$include_file"

if ! grep -q '/etc/samba/sentinel-audit.conf' "$compose_file"; then
  cp "$compose_file" "$compose_file.before-sentinel"
  python3 - "$compose_file" <<'PY'
from pathlib import Path
import sys

p = Path(sys.argv[1])
lines = p.read_text().splitlines()
volume_indent = command_indent = None
volume_insert = command_insert = None
for i, line in enumerate(lines):
    stripped = line.strip()
    if stripped.startswith("-") and ":/share" in stripped:
        volume_indent = line[:len(line) - len(line.lstrip())]
        volume_insert = i + 1
    if stripped.startswith("-s "):
        command_indent = line[:len(line) - len(line.lstrip())]
        command_insert = i + 1
if volume_insert is None or command_insert is None:
    raise SystemExit("Could not locate Samba volume and command entries")
lines.insert(volume_insert, f"{volume_indent}- /etc/sentinel/samba-audit.conf:/etc/samba/sentinel-audit.conf:ro")
if command_insert >= volume_insert:
    command_insert += 1
lines.insert(command_insert, f'{command_indent}-I "/etc/samba/sentinel-audit.conf"')
p.write_text("\n".join(lines) + "\n")
PY
fi

docker compose -p "$project" -f "$compose_file" config >/dev/null
cd "$project_dir"
docker compose -p "$project" -f "$compose_file" up -d --force-recreate "$container"
sleep 3
docker exec "$container" testparm -s >/dev/null
docker exec "$container" testparm -s 2>/dev/null | grep -E 'vfs objects|full_audit'
echo "Samba full_audit enabled; backup: $compose_file.before-sentinel"
