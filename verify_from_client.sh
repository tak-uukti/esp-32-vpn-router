#!/usr/bin/env bash
# Acceptance test for the tailnet gadget. Run this FROM a client joined to the gadget
# AP (or with the USB-NCM link up), with no Tailscale installed on that client.
#
# Usage: ./verify_from_client.sh <ssh-target-ip> [ssh-user]
set -uo pipefail

TARGET="${1:?usage: verify_from_client.sh <tailnet-ip> [user]}"
USER_="${2:-$USER}"
GADGET=192.168.4.1
pass=0; fail=0

check() { # name, expected-substring, actual
  if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; pass=$((pass+1));
  else echo "FAIL  $1 (wanted '$2', got '$3')"; fail=$((fail+1)); fi
}

echo "== 1. client has a gadget-assigned address =="
ip -4 addr show | grep -E "inet 192\.168\.4\." | head -1
check "client on 192.168.4.0/24" "192.168.4." "$(ip -4 addr show | grep -c 'inet 192.168.4.')"

echo "== 2. gadget reachable, DHCP/DNS sane =="
GW=$(ip route | awk '/default/ {print $3; exit}')
check "default route via gadget" "$GADGET" "$GW"
check "gateway answers ping" "0% packet loss" "$(ping -c 3 -W 2 "$GADGET" | tail -2)"

echo "== 3. internet still works through the gadget =="
IP_PUB=$(curl -s --max-time 10 https://api.ipify.org || echo "none")
check "public IP resolvable" "." "$IP_PUB"
echo "    uplink public IP: $IP_PUB"

echo "== 4. tailnet path =="
check "ping $TARGET" "0% packet loss" "$(ping -c 3 -W 2 "$TARGET" | tail -2)"
BANNER=$(timeout 6 bash -c "exec 3<>/dev/tcp/$TARGET/22; head -c 40 <&3" 2>/dev/null || echo "none")
check "SSH banner from $TARGET" "SSH-2.0" "$BANNER"

echo "== 5. real login (needs a key or password already set up) =="
if timeout 15 ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 \
     "$USER_@$TARGET" 'echo LOGIN_OK; uname -n' 2>/dev/null; then
  echo "PASS  ssh login"; pass=$((pass+1))
else
  echo "SKIP  ssh login (no key configured for $USER_@$TARGET)"
fi

echo "== 6. throughput (1 MB over the tunnel) =="
dd if=/dev/urandom of=/tmp/gadget-test.bin bs=1M count=1 2>/dev/null
START=$(date +%s.%N)
if timeout 90 scp -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
     /tmp/gadget-test.bin "$USER_@$TARGET:/tmp/gadget-test.bin" 2>/dev/null; then
  END=$(date +%s.%N)
  Mbps=$(awk -v s="$START" -v e="$END" 'BEGIN{printf "%.2f", 8/(e-s)}')
  echo "PASS  scp 1MB at ${Mbps} Mb/s"; pass=$((pass+1))
else
  echo "SKIP  scp (no key configured)"
fi
rm -f /tmp/gadget-test.bin

echo
echo "== summary: $pass passed, $fail failed =="
[[ $fail -eq 0 ]]
