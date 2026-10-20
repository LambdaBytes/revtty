#!/usr/bin/env bash
# Checks packaging/launchd on a disposable macOS CI runner, with launchd itself: it starts the
# agent as the plist's account, restarts it after a crash, and SIGTERM stops it with exit status
# 0 and no restart. Run from the repository root after `cargo build --release`; it needs
# passwordless sudo and removes only what it installed.
set -euo pipefail

account="$(id -un)"
group="$(id -gn)"
label="io.lambdabytes.revtty-agent.$account"
plist="/Library/LaunchDaemons/$label.plist"
binary="/usr/local/bin/revtty"
support_dir="/Library/Application Support/revtty"
state_root="$support_dir/$account"
log_dir="/Library/Logs/revtty"
log_file="$log_dir/agent-$account.log"
work="${RUNNER_TEMP:?RUNNER_TEMP is not set}/revtty-launchd-smoke"
relay_url="http://127.0.0.1:18787"
target="launchd-ci"
relay_pid=""
installed=false
loaded=false
# Deepest first, so that rmdir can remove them in order.
created_dirs=()

fail() {
  echo "launchd smoke: $*" >&2
  exit 1
}

for path in "$plist" "$binary" "$state_root" "$log_file" "$work"; do
  [[ ! -e "$path" && ! -L "$path" ]] || fail "$path already exists; refusing to touch it"
done
if sudo launchctl print "system/$label" > /dev/null 2>&1; then
  fail "a service $label is already loaded; refusing to touch it"
fi

cleanup() {
  local status=$?
  set +e
  if ((status != 0)); then
    echo "--- launchctl print system/$label" >&2
    sudo launchctl print "system/$label" >&2
    echo "--- $log_file" >&2
    sudo cat "$log_file" >&2
    echo "--- relay log" >&2
    cat "$work/relay.log" >&2
  fi
  if [[ "$loaded" == true ]]; then
    sudo launchctl bootout "system/$label" 2> /dev/null
  fi
  if [[ "$installed" == true ]]; then
    sudo rm -f "$plist" "$log_file" "$binary"
    sudo rm -rf "$state_root"
    if ((${#created_dirs[@]} > 0)); then
      sudo rmdir "${created_dirs[@]}" 2> /dev/null
    fi
  fi
  if [[ -n "$relay_pid" ]]; then
    kill "$relay_pid" 2> /dev/null
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

# Creates DIR, root-owned with MODE, and any missing parent, remembering each one it created.
make_dir() {
  local mode=$1 dir=$2
  [[ -d "$dir" ]] && return 0
  make_dir "$mode" "$(dirname "$dir")"
  sudo install -d -m "$mode" "$dir"
  created_dirs=("$dir" ${created_dirs[@]+"${created_dirs[@]}"})
}

operator() {
  REVTTY_CONFIG_DIR="$work/operator/config" REVTTY_STATE_DIR="$work/operator/state" "$binary" "$@"
}

# The value of `name = value` in the job's description, empty when absent; fails when launchd
# cannot describe the job, so that an unknown state never reads as a stopped agent.
job_field() {
  local description
  description="$(sudo launchctl print "system/$label" 2> /dev/null)" || return 1
  sed -n "s/^[[:space:]]*$1 = //p" <<< "$description" | head -n 1
}

agent_pid() {
  job_field pid
}

running() {
  local pid
  pid="$(agent_pid)" && [[ -n "$pid" ]]
}

stopped() {
  local pid
  pid="$(agent_pid)" && [[ -z "$pid" ]]
}

restarted_since() {
  local pid
  pid="$(agent_pid)" && [[ -n "$pid" && "$pid" != "$1" ]]
}

runs_as_account() {
  local pid uid
  pid="$(agent_pid)" && [[ -n "$pid" ]] || return 1
  uid="$(ps -o uid= -p "$pid" | tr -d '[:space:]')" || return 1
  [[ "$uid" == "$(id -u)" ]]
}

reachable() {
  operator probe "$target" --relay "$relay_url" --host-key "$host_key" > /dev/null 2>&1
}

relay_up() {
  kill -0 "$relay_pid" 2> /dev/null || fail "the relay exited"
  curl -fs -o /dev/null "$relay_url/health"
}

agent_connections() {
  sudo grep -c "connected to" "$log_file" || true
}

logged_more_than() {
  (($(agent_connections) > $1))
}

# wait_for SECONDS WHAT COMMAND...
wait_for() {
  local deadline=$((SECONDS + $1)) what=$2
  shift 2
  until "$@"; do
    ((SECONDS < deadline)) || fail "timed out waiting for $what"
    sleep 0.5
  done
}

installed=true
make_dir 0755 "$(dirname "$binary")"
sudo install -m 0755 target/release/revtty "$binary"
mkdir -p "$work"

"$binary" relay init --db "$work/relay.db"
"$binary" relay serve --bind 127.0.0.1:18787 --db "$work/relay.db" 2> "$work/relay.log" &
relay_pid=$!
wait_for 15 "the relay" relay_up

operator init > "$work/init.txt"
operator_key="$(sed -n 's/^public[[:space:]]*//p' "$work/init.txt")"
[[ -n "$operator_key" ]] || fail "revtty init printed no public key path"
token="$("$binary" relay enroll "$target" --operator-key "$operator_key" --db "$work/relay.db" |
  sed -n 's/^token[[:space:]]*//p')"
[[ -n "$token" ]] || fail "relay enroll printed no token"

# As docs/LAUNCHD.md installs it.
make_dir 0755 "$support_dir"
make_dir 0755 "$log_dir"
sudo install -d -m 0700 -o "$account" -g "$group" "$state_root" "$state_root/config" "$state_root/state"
sudo install -m 0600 -o "$account" -g "$group" /dev/null "$log_file"
host_key="$(REVTTY_CONFIG_DIR="$state_root/config" REVTTY_STATE_DIR="$state_root/state" \
  "$binary" agent enroll --relay "$relay_url" --token "$token" |
  sed -n 's/^host[[:space:]]*//p' | head -n 1)"
[[ -n "$host_key" ]] || fail "agent enroll printed no host key"

sed "s/ACCOUNT/$account/g" packaging/launchd/io.lambdabytes.revtty-agent.plist |
  sudo tee "$plist" > /dev/null
sudo chown root:wheel "$plist"
sudo chmod 0644 "$plist"
plutil -lint "$plist"
sudo launchctl bootstrap system "$plist"
loaded=true

wait_for 20 "launchd to start the agent" running
wait_for 10 "the agent to run as $account" runs_as_account
pid="$(agent_pid)"
wait_for 30 "the agent to answer a probe" reachable
echo "launchd started agent $pid as $account and it answers probes"

sudo kill -9 "$pid"
wait_for 20 "launchd to restart the crashed agent" restarted_since "$pid"
pid="$(agent_pid)"
wait_for 30 "the restarted agent to answer a probe" reachable
echo "launchd restarted the crashed agent as $pid"

sudo launchctl kill SIGTERM "system/$label"
wait_for 15 "the agent to stop on SIGTERM" stopped
exit_code="$(job_field 'last exit code')" || fail "launchd cannot describe $label"
[[ "$exit_code" == "0" ]] || fail "the agent exited with '$exit_code' after SIGTERM"
# Past ThrottleInterval: launchd must not restart an agent that exited cleanly.
sleep 7
stopped || fail "launchd restarted an agent that exited cleanly, or cannot describe it"
echo "SIGTERM stopped the agent with exit status 0 and launchd left it stopped"

connections="$(agent_connections)"
sudo launchctl kickstart "system/$label"
wait_for 20 "kickstart to start the agent" running
wait_for 30 "the agent to answer a probe after kickstart" reachable
wait_for 10 "the agent started by kickstart to log to $log_file" logged_more_than "$connections"
echo "kickstart started the agent again, and it logs to $log_file"
