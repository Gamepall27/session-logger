#!/bin/sh
set -eu

container="${SAMBA_CONTAINER:-samba}"
user="${SMB_USER:-joshua}"
password="${SMB_PASSWORD:?Set SMB_PASSWORD for the temporary SMB login}"
local_file=/tmp/sentinel-smb-probe.txt
remote_file=sentinel-smb-probe.txt
remote_moved=sentinel-smb-probe-moved.txt

docker exec "$container" sh -c "printf 'sentinel smb test\\n' > '$local_file'"
cleanup() {
  docker exec "$container" rm -f "$local_file" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker exec "$container" smbclient //127.0.0.1/files -U "$user%$password" \
  -c "put $local_file $remote_file; rename $remote_file $remote_moved; del $remote_moved"
echo "SMB create, rename and delete probe completed"
