#!/usr/bin/env bash
# Benchmark: nix-relay (wss://) vs direct SSH (ssh-ng://)
#
# Measures copy throughput and remote build latency, printing a comparison table.
#
# Provide a token via TOKEN
#
# Env vars:
#   TOKEN      -- pre-generated JWT token
#   RELAY_URL  -- relay WebSocket URL    (default: wss://nix-relay.numtide.com/relay)
#   SSH_HOST   -- SSH target host        (default: nix-relay.numtide.com)
#   SSH_USER   -- SSH user               (default: $USER)
#   RUNS       -- repetitions per test   (default: 3)
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
relay_url="${RELAY_URL:-wss://nix-relay.numtide.com/relay}"
ssh_host="${SSH_HOST:-nix-relay.numtide.com}"
ssh_user="${SSH_USER:-$USER}"
runs="${RUNS:-3}"

bench_dir="$(cd "$(dirname "$0")" && pwd)"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { printf '[bench] %s\n' "$*" >&2; }

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

require_cmd() {
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || die "required command not found: $cmd"
    done
}

# Elapsed time in fractional seconds using bash EPOCHREALTIME (bash >= 5.0)
now_secs() {
    printf '%s' "$EPOCHREALTIME"
}

# Run a command and print elapsed seconds to stdout, command output to stderr.
time_cmd() {
    local t0 t1 elapsed
    t0=$(now_secs)
    "$@" >&2
    t1=$(now_secs)
    elapsed=$(awk "BEGIN {printf \"%.3f\", $t1 - $t0}")
    printf '%s' "$elapsed"
}

# Compute the median of a list of numbers passed as arguments.
median() {
    local sorted
    sorted=$(printf '%s\n' "$@" | sort -n)
    local count=$#
    local mid=$(( (count + 1) / 2 ))
    printf '%s\n' "$sorted" | sed -n "${mid}p"
}

# Format bytes to human-readable.
human_bytes() {
    local bytes=$1
    awk "BEGIN {
        b = $bytes
        if      (b >= 1073741824) printf \"%.1f GB\", b/1073741824
        else if (b >= 1048576)    printf \"%.1f MB\", b/1048576
        else if (b >= 1024)       printf \"%.1f KB\", b/1024
        else                      printf \"%d B\",  b
    }"
}

# Format throughput (bytes/sec) to human-readable.
human_throughput() {
    local bytes=$1
    local secs=$2
    awk "BEGIN {
        rate = $bytes / $secs
        if      (rate >= 1073741824) printf \"%.1f GB/s\", rate/1073741824
        else if (rate >= 1048576)    printf \"%.1f MB/s\", rate/1048576
        else if (rate >= 1024)       printf \"%.1f KB/s\", rate/1024
        else                         printf \"%.0f B/s\",  rate
    }"
}

# Compute overhead percentage.
overhead_pct() {
    local relay_secs=$1
    local ssh_secs=$2
    awk "BEGIN {
        if ($ssh_secs == 0) { print \"N/A\"; exit }
        pct = (($relay_secs - $ssh_secs) / $ssh_secs) * 100
        if (pct >= 0) printf \"+%.0f%%\", pct
        else           printf \"%.0f%%\", pct
    }"
}

# Delete an entire closure from the remote store via SSH (best-effort).
remote_delete_closure() {
    local path=$1
    local closure_paths
    closure_paths=$(nix path-info -r "$path")
    # shellcheck disable=SC2029
    ssh "${ssh_user}@${ssh_host}" "for p in $closure_paths; do nix store delete \"\$p\" 2>/dev/null || true; done" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
log "pre-flight checks"
require_cmd nix ssh websocat awk sort sed
if [[ -z "${TOKEN:-}" ]]; then
    require_cmd nix-relay
fi

# Verify EPOCHREALTIME support
[[ -n "${EPOCHREALTIME:-}" ]] || die "bash >= 5.0 required (EPOCHREALTIME not available)"

# Verify SSH connectivity
log "testing SSH connectivity to ${ssh_user}@${ssh_host}"
ssh -o ConnectTimeout=10 "${ssh_user}@${ssh_host}" true \
    || die "SSH connection to ${ssh_user}@${ssh_host} failed"

# Acquire token
if [[ -n "${TOKEN:-}" ]]; then
    token="$TOKEN"
    log "using provided TOKEN"
else
    die "set TOKEN"
fi

# Export for nix-relay-client
export NIX_RELAY_URL="$relay_url"
export NIX_RELAY_TOKEN="$token"

relay_store="ssh-ng://localhost?remote-program=nix-relay-client"
ssh_store="ssh-ng://${ssh_user}@${ssh_host}"

# ---------------------------------------------------------------------------
# Prepare test closures
# ---------------------------------------------------------------------------
log "building test closures locally"

small_path=$(nix build --no-link --print-out-paths nixpkgs#hello)
large_path=$(nix build --no-link --print-out-paths nixpkgs#git)

small_size=$(nix path-info -rS "$small_path" | awk 'END {print $2}')
small_count=$(nix path-info -r "$small_path" | wc -l)
large_size=$(nix path-info -rS "$large_path" | awk 'END {print $2}')
large_count=$(nix path-info -r "$large_path" | wc -l)

log "small closure: $small_path ($(human_bytes "$small_size"), $small_count paths)"
log "large closure: $large_path ($(human_bytes "$large_size"), $large_count paths)"

# ---------------------------------------------------------------------------
# Copy throughput benchmark
# ---------------------------------------------------------------------------
log "starting copy throughput benchmark ($runs runs each)"

declare -a small_relay_times small_ssh_times large_relay_times large_ssh_times

log "== small closure =="
for i in $(seq 1 "$runs"); do
    log "run $i/$runs -- small closure via relay"
    remote_delete_closure "$small_path"
    t=$(time_cmd nix copy --no-check-sigs --to "$relay_store" "$small_path")
    small_relay_times+=("$t")
    log "  relay: ${t}s"

    log "run $i/$runs -- small closure via SSH"
    remote_delete_closure "$small_path"
    t=$(time_cmd nix copy --no-check-sigs --to "$ssh_store" "$small_path")
    small_ssh_times+=("$t")
    log "  ssh: ${t}s"
done

log "== large closure =="
for i in $(seq 1 "$runs"); do
    log "run $i/$runs -- large closure via relay"
    remote_delete_closure "$large_path"
    t=$(time_cmd nix copy --no-check-sigs --to "$relay_store" "$large_path")
    large_relay_times+=("$t")
    log "  relay: ${t}s"

    log "run $i/$runs -- large closure via SSH"
    remote_delete_closure "$large_path"
    t=$(time_cmd nix copy --no-check-sigs --to "$ssh_store" "$large_path")
    large_ssh_times+=("$t")
    log "  ssh: ${t}s"
done

small_relay_med=$(median "${small_relay_times[@]}")
small_ssh_med=$(median "${small_ssh_times[@]}")
large_relay_med=$(median "${large_relay_times[@]}")
large_ssh_med=$(median "${large_ssh_times[@]}")

# ---------------------------------------------------------------------------
# Remote build benchmark
# ---------------------------------------------------------------------------
log "starting remote build benchmark ($runs runs each)"

declare -a build_relay_times build_ssh_times

for i in $(seq 1 "$runs"); do
    nonce="bench-$(date +%s%N)-${i}"

    log "run $i/$runs -- remote build via relay (nonce=$nonce)"
    t=$(time_cmd nix build --no-link --eval-store auto \
        --store "$relay_store" \
        -f "$bench_dir/dummy-build.nix" --argstr nonce "$nonce")
    build_relay_times+=("$t")
    log "  relay: ${t}s"

    # Use a different nonce so we don't hit any caching
    nonce="bench-$(date +%s%N)-${i}-ssh"

    log "run $i/$runs -- remote build via SSH (nonce=$nonce)"
    t=$(time_cmd nix build --no-link --eval-store auto \
        --store "$ssh_store" \
        -f "$bench_dir/dummy-build.nix" --argstr nonce "$nonce")
    build_ssh_times+=("$t")
    log "  ssh: ${t}s"
done

build_relay_med=$(median "${build_relay_times[@]}")
build_ssh_med=$(median "${build_ssh_times[@]}")

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------
printf '\n'
printf 'nix-relay benchmark -- %s\n' "$ssh_host"
printf '============================================\n'
printf '\n'
printf 'Copy throughput (median of %d runs):\n' "$runs"
printf '  %-16s %-16s %-24s %-24s %s\n' "Closure" "Size" "Relay (wss://)" "SSH (ssh-ng://)" "Overhead"

printf '  %-16s %-16s %-24s %-24s %s\n' \
    "hello" \
    "$(human_bytes "$small_size") ($small_count paths)" \
    "${small_relay_med}s ($(human_throughput "$small_size" "$small_relay_med"))" \
    "${small_ssh_med}s ($(human_throughput "$small_size" "$small_ssh_med"))" \
    "$(overhead_pct "$small_relay_med" "$small_ssh_med")"

printf '  %-16s %-16s %-24s %-24s %s\n' \
    "git" \
    "$(human_bytes "$large_size") ($large_count paths)" \
    "${large_relay_med}s ($(human_throughput "$large_size" "$large_relay_med"))" \
    "${large_ssh_med}s ($(human_throughput "$large_size" "$large_ssh_med"))" \
    "$(overhead_pct "$large_relay_med" "$large_ssh_med")"

printf '\n'
printf 'Remote build (median of %d runs):\n' "$runs"
printf '  %-16s %-24s %-24s %s\n' "Derivation" "Relay (wss://)" "SSH (ssh-ng://)" "Overhead"
printf '  %-16s %-24s %-24s %s\n' \
    "dummy" \
    "${build_relay_med}s" \
    "${build_ssh_med}s" \
    "$(overhead_pct "$build_relay_med" "$build_ssh_med")"

printf '\n'
printf 'Raw timings:\n'
printf '  small relay: %s\n' "${small_relay_times[*]}"
printf '  small ssh:   %s\n' "${small_ssh_times[*]}"
printf '  large relay: %s\n' "${large_relay_times[*]}"
printf '  large ssh:   %s\n' "${large_ssh_times[*]}"
printf '  build relay: %s\n' "${build_relay_times[*]}"
printf '  build ssh:   %s\n' "${build_ssh_times[*]}"
