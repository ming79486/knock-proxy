#!/usr/bin/env bash
set -euo pipefail

backend="${1:-nftables}"
image="${KNOCK_PROXY_E2E_IMAGE:-golang:1.25-bookworm}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

docker run --rm --network bridge --cap-add NET_ADMIN --cap-add NET_RAW \
  -e KNOCK_PROXY_FIREWALL_BACKEND="$backend" \
  -v "$repo:/src" -w /src "$image" bash -lc '
set -euo pipefail
apt-get update >/dev/null
apt-get install -y --no-install-recommends nftables iptables ipset netcat-openbsd >/dev/null
CGO_ENABLED=0 go build -o /tmp/knock-proxy ./cmd/knock-proxy
secret="base64:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
cat >/tmp/server.yaml <<YAML
mode: server
server:
  tcp_listen: "0.0.0.0:2443"
  upstream: "127.0.0.1:2222"
access:
  mode: proxy
  require_tcp_auth: true
knock:
  method: udp
  udp_listen: "0.0.0.0:2443"
auth:
  clients:
    - client_id: e2e
      secret: "$secret"
firewall:
  backend: "$KNOCK_PROXY_FIREWALL_BACKEND"
  port: 2443
  default_action: drop
  allow_seconds: 3
  remove_after_auth: true
transport:
  encryption: false
limits:
  max_tracked_ips: 1000
  max_nonce_entries: 10000
YAML
cat >/tmp/client.yaml <<YAML
mode: client
client:
  listen: "127.0.0.1:10022"
  server_addr: "127.0.0.1:2443"
  client_id: e2e
  secret: "$secret"
knock:
  method: udp
transport:
  encryption: false
YAML
python3 - <<'"'"'PY'"'"' &
import socket, threading
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", 2222)); s.listen()
while True:
    c,_=s.accept()
    threading.Thread(target=lambda x: (x.sendall(x.recv(65535)), x.close()), args=(c,), daemon=True).start()
PY
/tmp/knock-proxy server --config /tmp/server.yaml >/tmp/server.log 2>&1 & srv=$!
sleep 1
if nc -z -w 1 127.0.0.1 2443; then echo "expected protected port to be blocked before knock" >&2; cat /tmp/server.log >&2; kill "$srv"; exit 1; fi
/tmp/knock-proxy probe --config /tmp/client.yaml --payload ok
sleep 4
if nc -z -w 1 127.0.0.1 2443; then echo "expected protected port to be blocked after expiry" >&2; cat /tmp/server.log >&2; kill "$srv"; exit 1; fi
kill "$srv"
'
