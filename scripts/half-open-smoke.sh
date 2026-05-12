#!/usr/bin/env bash
set -euo pipefail

addr="${1:?usage: $0 host:port [connections]}"
count="${2:-200}"
host="${addr%:*}"
port="${addr##*:}"

echo "opening $count half-open TCP connections to $addr"
idx=0
while (( idx < count )); do
  ((idx++))
  (exec 3<>"/dev/tcp/$host/$port"; sleep "${KNOCK_PROXY_HALF_OPEN_HOLD:-30}") 2>/dev/null &
done
wait
