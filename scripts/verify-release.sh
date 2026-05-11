#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

fail() { echo "[FAIL] $*" >&2; exit 1; }
ok() { echo "[OK] $*"; }

BIN=${BIN:-/tmp/knock-proxy-verify-release}
VERSION=${VERSION:-}

go test ./...
go build -trimpath -o "$BIN" ./cmd/knock-proxy
ok "go test and build"

help=$($BIN --help 2>&1 || true)
for cmd in client server knock probe doctor status init version; do
  grep -q "knock-proxy $cmd\|<$cmd" <<<"$help" || fail "help does not mention command: $cmd"
done
$BIN inspect --help >/tmp/knock-proxy-inspect-help.txt 2>&1 || true
grep -q "Usage of status" /tmp/knock-proxy-inspect-help.txt || fail "inspect alias is not wired to status"
ok "CLI help and inspect alias"

if grep -RIn --exclude-dir=.git --exclude='verify-release.sh' 'v1\.1\|V1\.1' README.md docs examples cmd internal; then
  fail "stale v1.1 reference found"
fi
if grep -RIn --exclude-dir=.git --exclude='verify-release.sh' -E "access\.mode.*both|mode: *['\"]both['\"]|proxy / direct / both|proxy, direct, or both" README.md docs examples cmd internal; then
  fail "unimplemented both mode reference found"
fi
ok "no stale v1.1 or unimplemented both-mode claims"

python3 - <<'PY'
from pathlib import Path
import re, sys
bad=[]
for p in [Path('README.md'), *Path('docs').glob('*.md')]:
    s=p.read_text()
    for m in re.finditer(r'\[[^\]]+\]\(([^)#][^)]+)\)', s):
        target=m.group(1)
        if '://' in target or target.startswith('mailto:'):
            continue
        q=target.split('#',1)[0]
        if q and not (p.parent/q).exists():
            bad.append((str(p),target))
if bad:
    for p,t in bad: print(f'{p}: missing {t}', file=sys.stderr)
    sys.exit(1)
print('[OK] markdown links')
PY

for cfg in examples/*.yaml; do
  $BIN doctor --config "$cfg" >/tmp/knock-proxy-doctor.out 2>&1 || fail "doctor failed for $cfg"
  grep -q "config valid" /tmp/knock-proxy-doctor.out || fail "doctor did not validate $cfg"
done
ok "example configs validate through doctor"

if [[ -f demand.md ]] && git check-ignore -q demand.md; then
  ok "demand.md is locally ignored"
elif [[ -f demand.md ]]; then
  fail "demand.md exists but is not ignored"
else
  ok "demand.md absent"
fi

if [[ -n "$VERSION" ]]; then
  out=$($BIN version)
  grep -q "knock-proxy $VERSION" <<<"$out" || fail "version output mismatch: $out"
  ok "version output: $out"
fi

ok "release verification complete"
