#!/usr/bin/env bash
set -euo pipefail

# Checks that this checkout's revtty and an older revision's work together, or fail with
# the hint their messages promise, in each mix of operator, relay and agent versions:
# probe, status and an interactive connect must work; exec must work, or say which side
# to upgrade. Linux only (util-linux `script`), over loopback, as the current user.
#
# Usage: compat-check.sh <older-git-ref> <work-dir>
# <work-dir> must not exist. Both versions are built into it, and it is left in place,
# logs included, for inspection.

if (( $# != 2 )); then
  echo "usage: $0 <older-git-ref> <work-dir>" >&2
  exit 2
fi
ref="$1"
work="$2"
repo="$(git rev-parse --show-toplevel)"
name="compat-agent"

fail() {
  echo "compat-check: $*" >&2
  exit 1
}

[[ ! -e "$work" ]] || fail "$work already exists"
mkdir -p "$work/old-src"
work="$(cd "$work" && pwd -P)"

git -C "$repo" archive --format=tar "$ref" | tar -x -C "$work/old-src"
cargo build --release --locked --manifest-path "$work/old-src/Cargo.toml" \
  --target-dir "$work/target-old"
cargo build --release --locked --manifest-path "$repo/Cargo.toml" \
  --target-dir "$work/target-new"
old="$work/target-old/release/revtty"
new="$work/target-new/release/revtty"

pids=()
cleanup() {
  local pid
  # A second signal must not cut the waits short and leave a child running.
  trap '' INT TERM
  for pid in "${pids[@]}"; do
    kill "$pid" 2> /dev/null || true
  done
  for pid in "${pids[@]}"; do
    wait "$pid" 2> /dev/null || true
  done
}
trap cleanup EXIT
# Bash runs no EXIT trap when a signal ends it: exit instead, so that cleanup runs.
trap 'exit 130' INT
trap 'exit 143' TERM

# as <role-dir> <binary> <args...>: runs revtty with that role's own directories.
as() {
  local dir="$1" binary="$2"
  shift 2
  env -u REVTTY_RELAY -u REVTTY_DB REVTTY_CONFIG_DIR="$dir/config" \
    REVTTY_STATE_DIR="$dir/state" "$binary" "$@"
}

# spawn <log> <role-dir> [NAME=value...] <binary> <args...>: starts revtty in the background
# as `as` runs it, with its stderr in <log>, and records its PID for cleanup. A simple
# command, not a function, goes to the background: `$!` is then revtty's own PID, as env
# execs it, where a function would leave it in a subshell that cleanup's kill does not pass on.
spawn() {
  local log="$1" dir="$2"
  shift 2
  env -u REVTTY_RELAY -u REVTTY_DB REVTTY_CONFIG_DIR="$dir/config" \
    REVTTY_STATE_DIR="$dir/state" "$@" 2> "$log" &
  pids+=("$!")
}

has_exec() {
  "$1" exec --help > /dev/null 2>&1
}

# wait_log <file> <text>: waits up to 20 s for <text> in <file>.
wait_log() {
  local tries=0
  until grep -q -- "$2" "$1" 2> /dev/null; do
    (( ++tries <= 200 )) || fail "no '$2' in $1: $(cat "$1" 2> /dev/null)"
    sleep 0.1
  done
}

# scenario <label> <operator-binary> <relay-binary> <agent-binary>
scenario() {
  local label="$1" operator_bin="$2" relay_bin="$3" agent_bin="$4"
  local dir="$work/$label"
  local operator="$dir/operator" relay="$dir/relay" agent="$dir/agent"
  mkdir -m 0700 "$dir" "$operator" "$relay" "$agent" "$agent/home"
  echo "--- $label"

  as "$operator" "$operator_bin" init > /dev/null
  as "$relay" "$relay_bin" relay init --db "$relay/relay.db" > /dev/null
  spawn "$relay/serve.log" "$relay" "$relay_bin" relay serve --bind 127.0.0.1:0 \
    --db "$relay/relay.db"
  wait_log "$relay/serve.log" "listening on "
  local url
  url="http://$(sed -n 's/.*listening on \([^ ]*\).*/\1/p' "$relay/serve.log" | head -n 1)"

  local out token host_key
  out="$(as "$relay" "$relay_bin" relay enroll "$name" \
    --operator-key "$operator/config/id_ed25519.pub" --db "$relay/relay.db" 2>&1)" ||
    fail "$label: relay enroll failed: $out"
  token="$(sed -n 's/^token[[:space:]]*//p' <<< "$out" | head -n 1)"
  [[ -n "$token" ]] || fail "$label: no enrollment token in: $out"
  out="$(as "$agent" "$agent_bin" agent enroll --relay "$url" --token "$token" 2>&1)" ||
    fail "$label: agent enroll failed: $out"
  host_key="$(sed -n 's/^host[[:space:]]*//p' <<< "$out" | head -n 1)"
  [[ -n "$host_key" ]] || fail "$label: no host key in: $out"
  spawn "$agent/run.log" "$agent" SHELL=/bin/sh HOME="$agent/home" "$agent_bin" agent run
  wait_log "$agent/run.log" "connected to"

  as "$operator" "$operator_bin" probe "$name" --relay "$url" --host-key "$host_key" \
    > "$dir/probe.out" 2>&1 || fail "$label: probe failed: $(cat "$dir/probe.out")"
  as "$operator" "$operator_bin" status "$name" --relay "$url" > "$dir/status.out" 2>&1 ||
    fail "$label: status failed: $(cat "$dir/status.out")"
  echo "probe and status work"

  # Typed into the operator's terminal once the remote shell had time to start. Only the
  # remote shell expands it, so that its echo cannot match.
  local connect
  printf -v connect '%q connect %q --relay %q' "$operator_bin" "$name" "$url"
  # shellcheck disable=SC2016
  { sleep 3; printf 'echo COMPAT_$((6*7))\n'; sleep 2; printf 'exit\n'; sleep 1; } |
    env -u REVTTY_RELAY -u REVTTY_DB REVTTY_CONFIG_DIR="$operator/config" \
      REVTTY_STATE_DIR="$operator/state" script -qec "$connect" /dev/null \
      > "$dir/connect.out" 2>&1 || true
  grep -q COMPAT_42 "$dir/connect.out" || fail "$label: connect failed: $(cat "$dir/connect.out")"
  echo "connect works"

  if ! has_exec "$operator_bin"; then
    echo "exec: not in this operator's version"
    return
  fi
  # What exec must print, and whether it must succeed.
  local expected succeeds=false
  if ! has_exec "$relay_bin"; then
    expected="the relay does not support exec"
  elif ! has_exec "$agent_bin"; then
    expected="the agent may predate exec"
  else
    expected="COMPAT_42"
    succeeds=true
  fi
  local status=0
  # shellcheck disable=SC2016 # expanded by the remote shell
  as "$operator" "$operator_bin" exec "$name" --relay "$url" --host-key "$host_key" -n -- \
    'echo COMPAT_$((6*7))' > "$dir/exec.out" 2>&1 || status=$?
  grep -q -- "$expected" "$dir/exec.out" ||
    fail "$label: exec gave no '$expected': $(cat "$dir/exec.out")"
  if [[ "$succeeds" == true ]] && (( status != 0 )); then
    fail "$label: exec exited with $status: $(cat "$dir/exec.out")"
  elif [[ "$succeeds" == false ]] && (( status == 0 )); then
    fail "$label: exec succeeded where it should have refused: $(cat "$dir/exec.out")"
  fi
  echo "exec: $expected (exit $status)"
}

scenario all-new "$new" "$new" "$new"
scenario old-relay "$new" "$old" "$new"
scenario old-agent "$new" "$new" "$old"
scenario old-relay-and-agent "$new" "$old" "$old"
scenario old-operator "$old" "$new" "$new"
echo "compat-check: every mix with $ref works or explains itself"
