#!/usr/bin/env bash
# Render bootstrap.
#   bootstrap/run.sh <fetch|plan|install|mount|render|finalize|cleanup> [arg]
set -euo pipefail
umask 077
: "${RUNNER_TEMP:?}"
W="$RUNNER_TEMP/w"; SRC="$W/src"; LOGS="$W/logs"; MNT="$W/gdrive"
mkdir -p "$SRC" "$LOGS" "$MNT"

# Dispatch inputs are strictly validated (allowlisted characters, no path traversal).
ARG=${2:-all}
[[ "$ARG" =~ ^[A-Za-z0-9._,-]{1,400}$ && "$ARG" != *..* ]] || { echo "input FAIL (invalid deliverable)"; exit 2; }
[[ "${V5_JOB:-latest.json}" =~ ^[A-Za-z0-9_-]{1,80}\.json$ ]] || { echo "input FAIL (invalid job name)"; exit 2; }
[[ "${V5_FORCE:-0}" =~ ^[01]$ ]] || { echo "input FAIL (invalid force flag)"; exit 2; }

cfg() {  # read one key of the bundle's render-runner.json; never prints a traceback
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$SRC/render-runner.json" "$1" 2>/dev/null \
    || { echo "config FAIL"; exit 1; }
}

step() {  # step <name> <cmd...>: generic status on the console, full output in the private log only
  local name=$1 t0=$SECONDS; shift
  echo "$name STARTED"
  if "$@" >> "$LOGS/$name.log" 2>&1; then echo "$name PASS ($((SECONDS - t0))s)"; else echo "$name FAIL ($((SECONDS - t0))s)"; return 1; fi
}

unmount_drive() {  # unmount, then wait for the rclone process to finish its pending uploads before exiting
  local pid; pid=$(pgrep -f "mount gd: $MNT" || true)
  mountpoint -q "$MNT" && fusermount3 -u "$MNT" 2>/dev/null || true
  for _ in $(seq 360); do [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null || return 0; sleep 5; done
  return 1
}

safe_extract() {  # tar members may not escape the target (Python "data" filter: no absolute paths, '..', devices, links out)
  python3 - "$1" "$2" <<'PY'
import sys, tarfile
with tarfile.open(sys.argv[1]) as t:
    t.extractall(sys.argv[2], filter="data")
PY
}

case "${1:-}" in
  fetch)
    : "${DRIVE_BUNDLE_PATH:?}" "${DRIVE_BUNDLE_SHA256:?}"
    step fetch-bundle rclone copyto "gd:$DRIVE_BUNDLE_PATH" "$W/bundle.tgz"
    echo "$DRIVE_BUNDLE_SHA256  $W/bundle.tgz" | sha256sum --check --status || { echo "bundle-integrity FAIL"; rm -f "$W/bundle.tgz"; exit 1; }
    echo "bundle-integrity PASS"
    step extract safe_extract "$W/bundle.tgz" "$SRC"
    rm -f "$W/bundle.tgz"
    test -f "$SRC/render-runner.json" || { echo "bundle FAIL (no render-runner.json)"; exit 1; }
    ;;
  plan)
    cd "$SRC"; step plan python3 "$(cfg plan)" plan "$ARG"
    ;;
  install)
    cd "$SRC"
    step npm-ci npm ci --no-audit --no-fund
    step browser npx remotion browser ensure
    if [[ "$ARG" =~ $(cfg whisper_pattern) ]]; then step whisper pip install -q faster-whisper; fi
    ;;
  mount)
    python3 - "$W/rclone.conf" <<'PY'
import os, sys
e = os.environ
with open(sys.argv[1], "w") as f:
    f.write("[gd]\ntype = drive\nscope = drive\n")
    f.write(f"client_id = {e['RCLONE_CONFIG_GD_CLIENT_ID']}\nclient_secret = {e['RCLONE_CONFIG_GD_CLIENT_SECRET']}\n")
    f.write(f"token = {e['RCLONE_CONFIG_GD_TOKEN']}\n")
PY
    env -i PATH="$PATH" HOME="$HOME" rclone --config "$W/rclone.conf" mount gd: "$MNT" --daemon --vfs-cache-mode full --vfs-cache-max-size 8G --vfs-cache-max-age 6h \
      --dir-cache-time 30s --drive-chunk-size 64M --cache-dir "$W/rclone-cache" --log-file "$LOGS/rclone-mount.log" --log-level NOTICE
    for _ in $(seq 30); do mountpoint -q "$MNT" && [ -d "$MNT/$(cfg drive_root)" ] && break; sleep 2; done
    rm -f "$W/rclone.conf"
    mountpoint -q "$MNT" && { echo "mount PASS"; exit 0; }
    echo "mount FAIL"; exit 1
    ;;
  render)
    cd "$SRC"
    export V5_DRIVE_ROOT="$MNT/$(cfg drive_root)" V5_STUDIO="$SRC" V5_ONLY="$ARG"
    date -u +%FT%TZ > "$W/start"
    step worker-gen sh -c 'python3 "$1" > "$2"' _ "$(cfg worker_generator)" "$W/worker.py"
    step render python3 "$W/worker.py"
    ;;
  finalize)
    cd "$SRC"
    step unmount unmount_drive
    step verify python3 "$(cfg plan)" finalize "$ARG" "$(cat "$W/start" 2>/dev/null || date -u +%FT%TZ)"
    ;;
  cleanup)
    unmount_drive > /dev/null 2>&1 || true
    if [ -f "$SRC/render-runner.json" ]; then
      rclone copy "$LOGS" "gd:$(cfg drive_root)/$(cfg logs_dir)/${GITHUB_RUN_ID:-local}-${GITHUB_JOB:-job}-$ARG" \
        --log-level ERROR > /dev/null 2>&1 && echo "logs PASS" || echo "logs FAIL"
    fi
    rm -rf "$W" "$RUNNER_TEMP/bundle" "$RUNNER_TEMP/tmp" "$HOME/.config/rclone"   # private bundle, media, renders, logs, rclone cache
    echo "cleanup PASS"
    ;;
  *) sed -n '2,3p' "$0"; exit 2 ;;
esac
