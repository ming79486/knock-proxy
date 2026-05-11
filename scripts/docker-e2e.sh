#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${IMAGE:-golang:1.25-bookworm}

run_docker() {
  docker run --rm \
    -v "$ROOT:/src:ro" \
    -w /work \
    "$@"
}

run_core() {
  echo "[INFO] running docker core e2e"
  run_docker "$IMAGE" bash -lc '
set -euo pipefail
export PATH=/usr/local/go/bin:$PATH
cp -a /src/. /work
export GOCACHE=/tmp/gocache GOMODCACHE=/tmp/gomodcache

go test ./...
go build -trimpath -o /tmp/knock-proxy ./cmd/knock-proxy
/tmp/knock-proxy version

cat > /tmp/tcp_roundtrip.go <<'EOF'
package main
import (
  "flag"
  "fmt"
  "io"
  "net"
  "os"
  "time"
)
func main() {
  addr := flag.String("addr", "", "address")
  expect := flag.String("expect", "", "expected response")
  flag.Parse()
  if *addr == "" { panic("missing -addr") }
  payload, err := io.ReadAll(os.Stdin)
  if err != nil { panic(err) }
  conn, err := net.DialTimeout("tcp", *addr, 5*time.Second)
  if err != nil { panic(err) }
  defer conn.Close()
  _ = conn.SetDeadline(time.Now().Add(5*time.Second))
  if _, err := conn.Write(payload); err != nil { panic(err) }
  buf := make([]byte, len(*expect))
  if _, err := io.ReadFull(conn, buf); err != nil { panic(err) }
  got := string(buf)
  if got != *expect { panic(fmt.Sprintf("expected %q got %q", *expect, got)) }
  fmt.Println(got)
}
EOF
go build -trimpath -o /tmp/tcp_roundtrip /tmp/tcp_roundtrip.go
wait_port() {
  host=$1
  port=$2
  name=$3
  for i in $(seq 1 100); do
    if timeout 1 bash -lc "</dev/tcp/$host/$port" >/dev/null 2>&1; then
      echo "[OK] $name ready: $host:$port"
      return 0
    fi
    sleep 0.1
  done
  echo "[FAIL] $name not ready: $host:$port" >&2
  return 1
}

secret=$(mktemp)
printf "12345678901234567890123456789012" > "$secret"
cat > /tmp/server-proxy.yaml <<EOF
mode: server
server:
  tcp_listen: "127.0.0.1:18443"
  upstream: "127.0.0.1:18022"
access:
  mode: "proxy"
  require_tcp_auth: true
knock:
  method: "udp"
auth:
  clients:
    - client_id: "client-001"
      secret_file: "$secret"
firewall:
  backend: "script"
  default_action: "drop"
  allow_seconds: 5
  script:
    allow_cmd: "/bin/true"
    revoke_cmd: "/bin/true"
    cleanup_cmd: "/bin/true"
transport:
  encryption: false
log:
  format: "text"
  file: "/tmp/server-proxy.log"
EOF
cat > /tmp/client-proxy.yaml <<EOF
mode: client
client:
  listen: "127.0.0.1:11022"
  server_addr: "127.0.0.1:18443"
  client_id: "client-001"
  secret_file: "$secret"
knock:
  method: "udp"
transport:
  encryption: false
EOF
cat > /tmp/upstream.go <<'EOF'
package main
import (
  "bufio"
  "fmt"
  "log"
  "net"
  "strings"
)
func main(){
  ln,err:=net.Listen("tcp","127.0.0.1:18022"); if err!=nil{panic(err)}
  log.Println("upstream proxy listening")
  for { c,err:=ln.Accept(); if err!=nil{return}; go func(){defer c.Close(); log.Println("upstream proxy accepted"); r:=bufio.NewReader(c); s,err:=r.ReadString(10); if err!=nil{log.Println("upstream proxy read", err); return}; log.Printf("upstream proxy got %q", s); fmt.Fprintf(c,"echo:%s",strings.TrimSpace(s))}() }
}
EOF
trap "kill 0 2>/dev/null || true" EXIT
go run /tmp/upstream.go >/tmp/upstream-proxy.log 2>&1 & upstream=$!
wait_port 127.0.0.1 18022 upstream-proxy
/tmp/knock-proxy server --config /tmp/server-proxy.yaml >/tmp/server-proxy.stdout 2>&1 & server=$!
wait_port 127.0.0.1 18443 server-proxy
/tmp/knock-proxy client --config /tmp/client-proxy.yaml >/tmp/client-proxy.stdout 2>&1 & client=$!
wait_port 127.0.0.1 11022 client-proxy
if ! resp=$(printf "hello\n" | /tmp/tcp_roundtrip -addr 127.0.0.1:11022 -expect "echo:hello" 2>/tmp/tcp-proxy.err); then
  echo "[FAIL] proxy roundtrip failed" >&2
  cat /tmp/tcp-proxy.err >&2 || true
  echo "--- upstream proxy log ---" >&2; cat /tmp/upstream-proxy.log >&2 || true
  echo "--- server proxy stdout ---" >&2; cat /tmp/server-proxy.stdout >&2 || true
  echo "--- server proxy log ---" >&2; cat /tmp/server-proxy.log >&2 || true
  echo "--- client proxy stdout ---" >&2; cat /tmp/client-proxy.stdout >&2 || true
  exit 1
fi
[ "$resp" = "echo:hello" ] || { echo "unexpected proxy response: $resp" >&2; exit 1; }
/tmp/knock-proxy probe --config /tmp/client-proxy.yaml --knock-only
/tmp/knock-proxy doctor --config /tmp/client-proxy.yaml
/tmp/knock-proxy doctor --config /tmp/server-proxy.yaml
/tmp/knock-proxy status --config /tmp/server-proxy.yaml
kill $client $server $upstream 2>/dev/null || true
wait $client $server $upstream 2>/dev/null || true
trap - EXIT

echo "[OK] proxy udp/script e2e"

cat > /tmp/server-direct.yaml <<EOF
mode: server
server:
  tcp_listen: "127.0.0.1:18444"
  upstream: "127.0.0.1:18023"
access:
  mode: "direct"
  require_tcp_auth: false
  remove_after_first_connect: true
  max_connections_per_knock: 1
knock:
  method: "udp"
auth:
  clients:
    - client_id: "client-001"
      secret_file: "$secret"
firewall:
  backend: "script"
  default_action: "drop"
  allow_seconds: 5
  script:
    allow_cmd: "/bin/true"
    revoke_cmd: "/bin/true"
    cleanup_cmd: "/bin/true"
transport:
  encryption: false
log:
  format: "text"
  file: "/tmp/server-direct.log"
EOF
cat > /tmp/upstream_direct.go <<'EOF'
package main
import (
  "bufio"
  "fmt"
  "log"
  "net"
  "strings"
)
func main(){
  ln,err:=net.Listen("tcp","127.0.0.1:18023"); if err!=nil{panic(err)}
  log.Println("upstream direct listening")
  for { c,err:=ln.Accept(); if err!=nil{return}; go func(){defer c.Close(); log.Println("upstream direct accepted"); r:=bufio.NewReader(c); s,err:=r.ReadString(10); if err!=nil{log.Println("upstream direct read", err); return}; log.Printf("upstream direct got %q", s); fmt.Fprintf(c,"direct:%s",strings.TrimSpace(s))}() }
}
EOF
trap "kill 0 2>/dev/null || true" EXIT
go run /tmp/upstream_direct.go >/tmp/upstream-direct.log 2>&1 & upstream=$!
wait_port 127.0.0.1 18023 upstream-direct
/tmp/knock-proxy server --config /tmp/server-direct.yaml >/tmp/server-direct.stdout 2>&1 & server=$!
wait_port 127.0.0.1 18444 server-direct
/tmp/knock-proxy knock --server 127.0.0.1:18444 --client-id client-001 --secret-file "$secret" --method udp --wait-open --wait-open-timeout 3s
if ! resp=$(printf "hello\n" | /tmp/tcp_roundtrip -addr 127.0.0.1:18444 -expect "direct:hello" 2>/tmp/tcp-direct.err); then
  echo "[FAIL] direct roundtrip failed" >&2
  cat /tmp/tcp-direct.err >&2 || true
  echo "--- upstream direct log ---" >&2; cat /tmp/upstream-direct.log >&2 || true
  echo "--- server direct stdout ---" >&2; cat /tmp/server-direct.stdout >&2 || true
  echo "--- server direct log ---" >&2; cat /tmp/server-direct.log >&2 || true
  exit 1
fi
[ "$resp" = "direct:hello" ] || { echo "unexpected direct response: $resp" >&2; exit 1; }
kill $server $upstream 2>/dev/null || true
wait $server $upstream 2>/dev/null || true
trap - EXIT

echo "[OK] direct udp/script e2e"
'
}

run_nftables() {
  echo "[INFO] running docker nftables smoke"
  if ! docker info >/dev/null 2>&1; then
    echo "[SKIP] docker daemon unavailable"
    return 0
  fi
  docker run --rm --privileged \
    -v "$ROOT:/src:ro" \
    -w /work \
    "$IMAGE" bash -lc '
set -euo pipefail
export PATH=/usr/local/go/bin:$PATH
apt-get update >/dev/null
apt-get install -y --no-install-recommends nftables iproute2 >/dev/null
cp -a /src/. /work
export GOCACHE=/tmp/gocache GOMODCACHE=/tmp/gomodcache
go build -trimpath -o /tmp/knock-proxy ./cmd/knock-proxy
/tmp/knock-proxy doctor --config examples/server.yaml | tee /tmp/doctor-nft.log
grep -q "nft temporary table check passed" /tmp/doctor-nft.log
/tmp/knock-proxy server --config examples/server.yaml --dry-run

echo "[OK] nftables privileged smoke"
'
}

run_core
run_nftables
