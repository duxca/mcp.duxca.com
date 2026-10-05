#!/usr/bin/env bash
# mcp.duxca.com — supported run mode: foreground CLI only.
# Ctrl+C (or SIGTERM) stops the gateway, Cloudflare Tunnel, and any MCP child processes.
# No daemon / systemd / nohup.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# --- env ---
# Prefer project secrets, then optional .env (local overrides).
load_env_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$f"
    set +a
    echo "loaded env: $f" >&2
  fi
}

load_env_file "$ROOT/.secrets/runtime.env"
load_env_file "$ROOT/.env"

if [[ -z "${PUBLIC_URL:-}" ]]; then
  echo "error: PUBLIC_URL is required (set in .secrets/runtime.env or .env)" >&2
  exit 1
fi

PORT="${PORT:-8000}"
export PUBLIC_URL PORT
export RUST_LOG="${RUST_LOG:-info,mcp_duxca_com=debug}"

# --- Cloudflare Tunnel (optional, same session) ---
# Token sources (first match wins):
#   1. CLOUDFLARED_TOKEN or TUNNEL_TOKEN env
#   2. CLOUDFLARED_TOKEN_FILE (default search if unset:
#        /home/box/.cloudflared/mcp-duxca-com.token
#        then $ROOT/.secrets/tunnel.token)
CLOUDFLARED_TOKEN_FILE="${CLOUDFLARED_TOKEN_FILE:-}"
TUNNEL_PID=""
GATEWAY_PID=""
CLEANED=0

resolve_tunnel_token() {
  if [[ -n "${CLOUDFLARED_TOKEN:-}" ]]; then
    printf '%s' "$CLOUDFLARED_TOKEN"
    return 0
  fi
  if [[ -n "${TUNNEL_TOKEN:-}" ]]; then
    printf '%s' "$TUNNEL_TOKEN"
    return 0
  fi

  local candidates=()
  if [[ -n "$CLOUDFLARED_TOKEN_FILE" ]]; then
    candidates+=("$CLOUDFLARED_TOKEN_FILE")
  else
    candidates+=(
      "/home/box/.cloudflared/mcp-duxca-com.token"
      "$ROOT/.secrets/tunnel.token"
    )
  fi

  local f
  for f in "${candidates[@]}"; do
    if [[ -f "$f" && -s "$f" ]]; then
      tr -d '\n\r' <"$f"
      return 0
    fi
  done
  return 1
}

kill_tree() {
  local pid="$1"
  [[ -z "$pid" ]] && return 0
  if ! kill -0 "$pid" 2>/dev/null; then
    return 0
  fi
  # Kill the whole process group when the child is a group leader (setsid).
  local pgid
  pgid="$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ' || true)"
  if [[ -n "$pgid" && "$pgid" != "1" && "$pgid" != "$$" ]]; then
    kill -TERM -- "-$pgid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
  else
    kill -TERM "$pid" 2>/dev/null || true
  fi
}

force_kill_tree() {
  local pid="$1"
  [[ -z "$pid" ]] && return 0
  if ! kill -0 "$pid" 2>/dev/null; then
    return 0
  fi
  local pgid
  pgid="$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ' || true)"
  if [[ -n "$pgid" && "$pgid" != "1" && "$pgid" != "$$" ]]; then
    kill -KILL -- "-$pgid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
  else
    kill -KILL "$pid" 2>/dev/null || true
  fi
}

cleanup() {
  local ec=$?
  if [[ "$CLEANED" -eq 1 ]]; then
    exit "$ec"
  fi
  CLEANED=1
  trap - EXIT INT TERM
  echo "" >&2
  echo "shutting down mcp.duxca.com (gateway + tunnel)…" >&2
  kill_tree "${GATEWAY_PID:-}"
  kill_tree "${TUNNEL_PID:-}"
  local i
  for i in 1 2 3 4 5; do
    local alive=0
    if [[ -n "${GATEWAY_PID:-}" ]] && kill -0 "$GATEWAY_PID" 2>/dev/null; then alive=1; fi
    if [[ -n "${TUNNEL_PID:-}" ]] && kill -0 "$TUNNEL_PID" 2>/dev/null; then alive=1; fi
    [[ "$alive" -eq 0 ]] && break
    sleep 0.2
  done
  force_kill_tree "${GATEWAY_PID:-}"
  force_kill_tree "${TUNNEL_PID:-}"
  wait 2>/dev/null || true
  echo "stopped." >&2
  exit "$ec"
}

trap cleanup EXIT INT TERM

TOKEN=""
if TOKEN="$(resolve_tunnel_token)"; then
  if ! command -v cloudflared >/dev/null 2>&1; then
    echo "warning: tunnel token found but cloudflared is not on PATH; running gateway only" >&2
    TOKEN=""
  fi
fi

if [[ -n "$TOKEN" ]]; then
  echo "starting cloudflared tunnel (same session; Ctrl+C stops all)…" >&2
  # New session/process group so Ctrl+C cleanup can TERM the whole tree.
  # Token only on argv to cloudflared; never echo it.
  setsid cloudflared tunnel run --token "$TOKEN" </dev/null &
  TUNNEL_PID=$!
  TOKEN=""
  unset CLOUDFLARED_TOKEN TUNNEL_TOKEN TOKEN 2>/dev/null || true
else
  echo "warning: no Cloudflare Tunnel token (CLOUDFLARED_TOKEN / TUNNEL_TOKEN / CLOUDFLARED_TOKEN_FILE)." >&2
  echo "         running gateway only on 0.0.0.0:${PORT} (local / tests OK)." >&2
fi

# --- gateway (foreground wait) ---
MCP_BIN="${MCP_BIN:-}"
echo "starting gateway (PUBLIC_URL=${PUBLIC_URL} PORT=${PORT})…" >&2
echo "Ctrl+C stops gateway + tunnel + MCP children. No daemon." >&2

if [[ -n "$MCP_BIN" ]]; then
  if [[ ! -x "$MCP_BIN" ]]; then
    echo "error: MCP_BIN is not executable: $MCP_BIN" >&2
    exit 1
  fi
  setsid "$MCP_BIN" </dev/null &
  GATEWAY_PID=$!
elif [[ -x "$ROOT/target/release/mcp-duxca-com" && "${MCP_USE_RELEASE:-}" == "1" ]]; then
  setsid "$ROOT/target/release/mcp-duxca-com" </dev/null &
  GATEWAY_PID=$!
else
  # Dev default: cargo run (debug). Prefer MCP_BIN after `cargo build`.
  setsid cargo run </dev/null &
  GATEWAY_PID=$!
fi

set +e
wait "$GATEWAY_PID"
GATEWAY_EC=$?
set -e
GATEWAY_PID=""
exit "$GATEWAY_EC"
