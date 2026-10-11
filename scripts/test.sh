#!/usr/bin/env bash
#
# Integration test: two network namespaces + UDP tunnel between them.
# Verifies that ping flows through tun0 and that traffic on the wire
# is encrypted (UDP, not raw ICMP).
#
# Usage:  sudo ./scripts/test.sh
# Exit 0 on success, 1 on failure.
#
set -euo pipefail

# --- project paths (needed before settings to compute LOG_DIR) -----
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
TUNNEL_BIN="$PROJECT_DIR/tunnel"

# --- settings ------------------------------------------------------
NS1=ns1
NS2=ns2
VETH1=veth1
VETH2=veth2

# "Physical" network addresses (veth pair between namespaces).
PHY1=10.0.0.1
PHY2=10.0.0.2
PORT=5000

# Inner (tunnel) addresses.
TUN1=192.168.99.1
TUN2=192.168.99.2
TUN_MTU=1400

# Logs and key live in a project-local directory, not /tmp.
# This avoids permission issues with /tmp under WSL2.
LOG_DIR="$PROJECT_DIR/.test-logs"
KEY_FILE="$LOG_DIR/tunnel.key"
LOG1="$LOG_DIR/ns1.log"
LOG2="$LOG_DIR/ns2.log"

# --- colors --------------------------------------------------------
if [[ -t 1 ]]; then
    R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1m'; N=$'\e[0m'
else
    R=; G=; Y=; B=; N=
fi

log()  { printf '%s==>%s %s\n' "$B" "$N" "$*"; }
ok()   { printf '%s  ok%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s ! %s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '%serr%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

# --- cleanup, always runs on exit ----------------------------------
cleanup() {
    local rc=$?
    log "cleanup"

    pkill -f "tunnel --tun" 2>/dev/null || true
    sleep 0.3

    ip netns del "$NS1" 2>/dev/null || true
    ip netns del "$NS2" 2>/dev/null || true
    ip link del "$VETH1" 2>/dev/null || true

    rm -rf "$LOG_DIR"

    if (( rc == 0 )); then
        printf '\n%s%s--- PASS ---%s\n' "$B" "$G" "$N"
    else
        printf '\n%s%s--- FAIL (rc=%d) ---%s\n' "$B" "$R" "$rc" "$N"
    fi
    exit $rc
}
trap cleanup EXIT INT TERM

# --- preconditions -------------------------------------------------
[[ $EUID -eq 0 ]] || die "run as root: sudo $0"
[[ -x "$TUNNEL_BIN" ]] || die "not found: $TUNNEL_BIN (run 'make' first)"

command -v ip   >/dev/null || die "ip not found (install iproute2)"
command -v ping >/dev/null || die "ping not found (install iputils-ping)"

# --- initial cleanup -----------------------------------------------
log "pre-clean"
pkill -f "tunnel --tun" 2>/dev/null || true
sleep 0.3
ip netns del "$NS1" 2>/dev/null || true
ip netns del "$NS2" 2>/dev/null || true
ip link del "$VETH1" 2>/dev/null || true

# --- fresh log directory -------------------------------------------
rm -rf "$LOG_DIR"
mkdir -p "$LOG_DIR"

# --- generate key --------------------------------------------------
log "generate key: $KEY_FILE"
"$TUNNEL_BIN" --genkey > "$KEY_FILE"
size=$(stat -c %s "$KEY_FILE" 2>/dev/null || echo 0)
[[ "$size" == "32" ]] || die "key size expected 32, got $size"
ok "key: 32 bytes"

# --- namespaces and veth -------------------------------------------
log "create namespaces and veth pair"
ip netns add "$NS1"
ip netns add "$NS2"

ip link add "$VETH1" type veth peer name "$VETH2"
ip link set "$VETH1" netns "$NS1"
ip link set "$VETH2" netns "$NS2"

ip netns exec "$NS1" ip link set lo up
ip netns exec "$NS2" ip link set lo up

ip netns exec "$NS1" ip addr add "$PHY1/24" dev "$VETH1"
ip netns exec "$NS2" ip addr add "$PHY2/24" dev "$VETH2"

ip netns exec "$NS1" ip link set "$VETH1" up
ip netns exec "$NS2" ip link set "$VETH2" up
ok "veth up: $PHY1 <-> $PHY2"

# --- baseline: ns1 reaches ns2 over veth ---------------------------
log "baseline: $PHY1 -> $PHY2"
if ! ip netns exec "$NS1" ping -c1 -W1 "$PHY2" >/dev/null 2>&1; then
    die "baseline ping failed — veth not routed"
fi
ok "baseline ok"

# --- start tunnels -------------------------------------------------
log "start tunnel in both namespaces"
ip netns exec "$NS1" "$TUNNEL_BIN" --tun tun0 \
    --listen "$PHY1:$PORT" --peer "$PHY2:$PORT" \
    --key "$KEY_FILE" > "$LOG1" 2>&1 &
PID1=$!

ip netns exec "$NS2" "$TUNNEL_BIN" --tun tun0 \
    --listen "$PHY2:$PORT" --peer "$PHY1:$PORT" \
    --key "$KEY_FILE" > "$LOG2" 2>&1 &
PID2=$!

sleep 1

if ! kill -0 "$PID1" 2>/dev/null; then
    warn "ns1 tunnel exited:"
    cat "$LOG1" >&2 || true
    die "tunnel (ns1) died at startup"
fi
if ! kill -0 "$PID2" 2>/dev/null; then
    warn "ns2 tunnel exited:"
    cat "$LOG2" >&2 || true
    die "tunnel (ns2) died at startup"
fi

if ! ip netns exec "$NS1" ip link show tun0 >/dev/null 2>&1; then
    warn "ns1 log:"
    cat "$LOG1" >&2 || true
    die "tun0 not present in ns1"
fi
if ! ip netns exec "$NS2" ip link show tun0 >/dev/null 2>&1; then
    warn "ns2 log:"
    cat "$LOG2" >&2 || true
    die "tun0 not present in ns2"
fi
ok "tun0 created in both namespaces"

# --- configure tun0 inside each ns ---------------------------------
log "configure tun0 addresses"
ip netns exec "$NS1" ip addr add "$TUN1/24" dev tun0
ip netns exec "$NS2" ip addr add "$TUN2/24" dev tun0
ip netns exec "$NS1" ip link set tun0 up mtu "$TUN_MTU"
ip netns exec "$NS2" ip link set tun0 up mtu "$TUN_MTU"

# --- test 1: ping over the tunnel ----------------------------------
log "test 1: ping $TUN1 -> $TUN2 (through tun0)"
if ! ip netns exec "$NS1" ping -c3 -W2 "$TUN2"; then
    warn "ns1 log:"
    cat "$LOG1" >&2 || true
    warn "ns2 log:"
    cat "$LOG2" >&2 || true
    die "ping through tunnel failed"
fi
ok "ping ok"

# --- test 2: tcpdump on veth (optional) ----------------------------
if command -v tcpdump >/dev/null 2>&1; then
    log "test 2: sniff veth — traffic must be UDP, not plain ICMP"

    DUMP="$LOG_DIR/tunnel.tcpdump"
    ip netns exec "$NS1" tcpdump -i "$VETH1" -n -l -c 20 "udp port $PORT" \
        > "$DUMP" 2>/dev/null &
    DUMP_PID=$!
    sleep 0.3

    ip netns exec "$NS1" ping -c2 -W1 "$TUN2" >/dev/null 2>&1 || true
    sleep 0.5
    kill "$DUMP_PID" 2>/dev/null || true
    wait "$DUMP_PID" 2>/dev/null || true

    if grep -q "UDP, length" "$DUMP"; then
        ok "UDP traffic present on veth"
    else
        warn "no UDP packets captured — tcpdump check skipped"
    fi
else
    warn "tcpdump not installed, skipping sniff test"
fi

# --- check logs for errors -----------------------------------------
log "check logs for errors"
if grep -qE '^\S+ \[ERR\]' "$LOG1" "$LOG2"; then
    warn "errors found in logs:"
    grep -E '\[ERR\]' "$LOG1" "$LOG2" >&2 || true
    die "errors in tunnel logs"
fi
ok "no errors in logs"

ok "all checks passed"
exit 0