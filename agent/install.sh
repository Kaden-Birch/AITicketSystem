#!/usr/bin/env bash
# Ubuntu/Debian installer. Identity and command execution history are preserved.
set -euo pipefail
server='' ca='' source_dir='' verify_only=0
while (($#)); do
  case "$1" in
    --server) server="$2"; shift 2;;
    --ca) ca="$2"; shift 2;;
    --source) source_dir="$2"; shift 2;;
    --verify-only) verify_only=1; shift;;
    *) echo "Usage: sudo bash install.sh [--server URL] [--ca FILE] [--source REPOSITORY]" >&2; exit 2;;
  esac
done
if (( ! verify_only )); then
  [[ $EUID == 0 ]] || { echo 'Run this installer with sudo.' >&2; exit 1; }
  command -v systemctl >/dev/null || { echo 'systemd is required.' >&2; exit 1; }
  apt-get update
  apt-get install -y python3 curl ca-certificates tar iproute2 openssl
fi
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
if [[ -z "$source_dir" ]]; then
  curl --fail --location --silent --show-error https://github.com/Kaden-Birch/AITicketSystem/archive/refs/heads/main.tar.gz -o "$stage/source.tar.gz"
  tar -xzf "$stage/source.tar.gz" -C "$stage"
  source_dir="$stage/AITicketSystem-main"
fi
python3 - "$source_dir" <<'PY'
import hashlib,sys
from pathlib import Path
if sys.version_info < (3,11): raise SystemExit('Python 3.11+ is required.')
root=Path(sys.argv[1]); sums={}
for line in (root/'SHA256SUMS').read_text().splitlines():
    digest,path=line.split('  ',1);sums[path]=digest
for name in ('agent.py','diagnostics.py','monitoring.py','network.py','actions.py','commands.py','install_verify.py','aiticket-agent.service','updater.py','update_support.py','release-public.pem','aiticket-agent-updater.service','aiticket-agent-updater.timer'):
    path='agent/'+name
    if sums.get(path)!=hashlib.sha256((root/path).read_bytes()).hexdigest():raise SystemExit('Checksum mismatch: '+path)
print('Agent source checksums verified.')
PY
((verify_only)) && exit 0
python3 - "$source_dir/agent" <<'PYPREFLIGHT'
import sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from update_support import preflight_existing
preflight_existing(Path('/var/lib/aiticket-agent/identity.json'),Path(sys.argv[1]))
PYPREFLIGHT
if ! id aiticket-agent >/dev/null 2>&1; then
  useradd --system --home /var/lib/aiticket-agent --shell /usr/sbin/nologin aiticket-agent
fi
systemctl stop aiticket-agent-updater.timer aiticket-agent-updater.service 2>/dev/null || true
systemctl stop aiticket-agent 2>/dev/null || true
install -d -o root -g root -m 0755 /opt/aiticket-agent /etc/aiticket-agent
install -d -o root -g root -m 0700 /var/lib/aiticket-agent
install -d -o root -g root -m 0755 /opt/aiticket-agent/releases
bundle_dir=$(mktemp -d /opt/aiticket-agent/releases/bootstrap-XXXXXXXX)
for file in agent.py diagnostics.py monitoring.py network.py actions.py commands.py install_verify.py; do
  install -o root -g root -m 0644 "$source_dir/agent/$file" "$bundle_dir/$file"
  rm -f "/opt/aiticket-agent/$file"
  ln -s "current/$file" "/opt/aiticket-agent/$file"
done
ln -s "$bundle_dir" /opt/aiticket-agent/current.install
mv -Tf /opt/aiticket-agent/current.install /opt/aiticket-agent/current
for file in updater.py update_support.py release-public.pem; do
  install -o root -g root -m 0644 "$source_dir/agent/$file" "/opt/aiticket-agent/$file"
done
for unit in aiticket-agent-updater.service aiticket-agent-updater.timer; do
  install -o root -g root -m 0644 "$source_dir/agent/$unit" "/etc/systemd/system/$unit"
done
if [[ ! -f /etc/aiticket-agent/updater.json ]]; then
  printf '%s\n' '{"automatic":true}' > /etc/aiticket-agent/updater.json
  chmod 600 /etc/aiticket-agent/updater.json
fi
python3 - "$bundle_dir" <<'PYINSTALL'
import sys,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from agent import VERSION
p=Path('/var/lib/aiticket-agent/update-status.json')
p.write_text(json.dumps({'installed':VERSION,'state':'available','detail':'Independent updater installed; release check pending.'}))
p.chmod(0o600)
PYINSTALL
install -o root -g root -m 0644 "$source_dir/agent/aiticket-agent.service" /etc/systemd/system/aiticket-agent.service
# Override older drop-ins too; retain unrelated local unit customizations.
install -d -o root -g root -m 0755 /etc/systemd/system/aiticket-agent.service.d
cat > /etc/systemd/system/aiticket-agent.service.d/zz-aiticket-full-access.conf <<'UNIT'
[Service]
User=root
Group=root
PrivateUsers=false
DynamicUser=false
NoNewPrivileges=false
ProtectSystem=off
ProtectHome=false
PrivateTmp=false
ProtectKernelTunables=false
ProtectKernelModules=false
ProtectControlGroups=false
RestrictSUIDSGID=false
MemoryMax=512M
CPUQuota=100%
UNIT
python3 - <<'PY'
import json,os
from pathlib import Path
p=Path('/etc/aiticket-agent/policy.json')
if p.is_symlink():raise SystemExit('Policy must not be a symlink.')
policy=json.loads(p.read_text()) if p.exists() else {}
policy['commands']={'enabled':True,'timeout':3600,'output_limit':65536,'sudo':False}
p.write_text(json.dumps(policy,indent=2)+'\n');os.chown(p,0,0);p.chmod(0o600)
PY
systemctl daemon-reload
if [[ ! -f /var/lib/aiticket-agent/identity.json ]]; then
  if [[ -z "$server" ]]; then read -r -p 'Main application URL: ' server </dev/tty; fi
  args=(enroll --server "$server")
  [[ "$server" == http://* ]] && args+=(--allow-http)
  [[ -n "$ca" ]] && args+=(--ca "$ca")
  python3 /opt/aiticket-agent/agent.py "${args[@]}" </dev/tty
else
  echo 'Existing enrollment preserved.'
fi
systemctl enable aiticket-agent
systemctl restart aiticket-agent
sleep 2
systemctl is-active --quiet aiticket-agent || { journalctl -u aiticket-agent -n 30 --no-pager; exit 1; }
python3 /opt/aiticket-agent/install_verify.py
systemctl enable --now aiticket-agent-updater.timer
echo "Independent automatic updater enabled (checks every five minutes)."
echo 'Agent running with local root command access. Main application host policy controls remote execution.'
command -v docker >/dev/null && docker info >/dev/null 2>&1 && echo 'Docker daemon accessible.' || echo 'Docker unavailable; other monitoring continues.'
echo 'Check the host in the application after its next heartbeat.'
