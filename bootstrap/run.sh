#!/usr/bin/env bash
# Render bootstrap. Host side = audited generic operations only (bootstrap/drive.py holds the Google credential);
# every line of bundle / npm / Remotion / Chrome / FFmpeg code runs inside the hardened container (box), never here.
#   bootstrap/run.sh <fetch|image|install|inputs|pull|render|upload|plan-pull|plan|plan-publish|selftest|revoke|cleanup> [arg]
set -euo pipefail
umask 077
: "${RUNNER_TEMP:?}"
W="$RUNNER_TEMP/w"; SRC="$W/src"; LOGS="$W/logs"; STAGE="$W/drive"; OUT="$W/out"; SCRATCH="$W/scratch"; PYENV="$W/pyenv"; RENDERS="$W/renders"
mkdir -p "$SRC" "$LOGS" "$STAGE" "$OUT" "$SCRATCH/tmp" "$PYENV" "$RENDERS"
DRIVE=(python3 -I "$(cd "$(dirname "$0")" && pwd)/drive.py")
IMAGE=render-box:local
JOBS=01_PROJECT_CONTROL/jobs

# Dispatch inputs are strictly validated (allowlisted characters, no path traversal, known deliverable ids only).
ARG=${2:-all}
[[ "$ARG" =~ ^[A-Za-z0-9._,-]{1,400}$ && "$ARG" != *..* ]] || { echo "input FAIL (invalid deliverable)"; exit 2; }
[[ "$ARG" =~ ^(all|plan|selftest|revoke|V5-V00[1-6]-(master|reel)(,V5-V00[1-6]-(master|reel))*)$ ]] || { echo "input FAIL (unknown deliverable)"; exit 2; }
[[ "${V5_JOB:-latest.json}" =~ ^[A-Za-z0-9_-]{1,80}\.json$ ]] || { echo "input FAIL (invalid job name)"; exit 2; }
[[ "${V5_FORCE:-0}" =~ ^[01]$ ]] || { echo "input FAIL (invalid force flag)"; exit 2; }
V5_JOB=${V5_JOB:-latest.json}; V5_FORCE=${V5_FORCE:-0}
one() { [[ "$ARG" =~ ^V5-V00[1-6]-(master|reel)$ ]] || { echo "input FAIL (one deliverable expected)"; exit 2; }; }

cfg() {  # one key of the bundle's render-runner.json, copied to $W before any untrusted code ran; never a traceback
  python3 -I -c 'import json,re,sys; v=json.load(open(sys.argv[1]))[sys.argv[2]]; assert re.fullmatch(r"[A-Za-z0-9_./^$()|*+?-]{1,200}", v) and ".." not in v; print(v)' \
    "$W/cfg.json" "$1" 2>/dev/null || { echo "config FAIL"; exit 1; }
}

step() {  # step <name> <cmd...>: generic status on the console, full output in the private log only
  local name=$1 t0=$SECONDS; shift
  echo "$name STARTED"
  if "$@" >> "$LOGS/$name.log" 2>&1; then echo "$name PASS ($((SECONDS - t0))s)"; else echo "$name FAIL ($((SECONDS - t0))s)"; return 1; fi
}

idle() {  # authenticated steps run only once every container has exited
  [ -z "$(docker ps -q)" ] || { echo "container FAIL (still running)"; exit 1; }
}

box() {  # box <none|bridge> <docker mount args...> -- <command...>: untrusted code: no credential, no GITHUB_*/ACTIONS_* variable
  local net=$1 mounts=(); shift
  while [ "$1" != -- ]; do mounts+=("$1"); shift; done; shift
  [ "$(id -u)" != 0 ] || { echo "container FAIL (root)"; return 1; }
  docker run --rm --network "$net" --user "$(id -u):$(id -g)" --cap-drop=ALL --security-opt=no-new-privileges --read-only \
    --tmpfs /tmp:rw,nosuid,nodev,size=1g --pids-limit 4096 "${mounts[@]}" \
    -e HOME=/tmp -e TMPDIR=/scratch/tmp -e RUNNER_TEMP=/scratch -e PATH=/pyenv/bin:/usr/local/bin:/usr/bin:/bin \
    -e HF_HOME=/pyenv/hf -e PYTHONDONTWRITEBYTECODE=1 -e NO_UPDATE_NOTIFIER=1 -e npm_config_update_notifier=false \
    -e npm_config_cache=/scratch/npm -e V5_DRIVE_ROOT=/drive -e V5_STUDIO=/studio \
    -e V5_ONLY="$ARG" -e V5_JOB="$V5_JOB" -e V5_FORCE="$V5_FORCE" -w /studio "$IMAGE" "$@"
}

safe_extract() {  # tar members may not escape the target (Python "data" filter: no absolute paths, '..', devices, links out)
  python3 -I - "$1" "$2" <<'PY'
import sys, tarfile
with tarfile.open(sys.argv[1]) as t:
    t.extractall(sys.argv[2], filter="data")
PY
}

case "${1:-}" in
  fetch)    # host: bundle (sha256-verified) + job file
    : "${DRIVE_BUNDLE_SHA256:?}"
    step fetch-bundle "${DRIVE[@]}" bundle "$W/bundle.tgz"
    echo "$DRIVE_BUNDLE_SHA256  $W/bundle.tgz" | sha256sum --check --status || { echo "bundle-integrity FAIL"; rm -f "$W/bundle.tgz"; exit 1; }
    echo "bundle-integrity PASS"
    step extract safe_extract "$W/bundle.tgz" "$SRC"
    rm -f "$W/bundle.tgz"
    test -f "$SRC/render-runner.json" || { echo "bundle FAIL (no render-runner.json)"; exit 1; }
    cp "$SRC/render-runner.json" "$W/cfg.json"
    step fetch-job "${DRIVE[@]}" pull "$STAGE" "$W/pulled.json" "$JOBS/$V5_JOB"
    ;;
  image)    # no credential: build the sandbox from the public Dockerfile (base pinned by digest)
    step image docker build -q -t "$IMAGE" "$(cd "$(dirname "$0")/.." && pwd)/container"
    ;;
  install)  # container, network allowed: npm ci, Chrome, faster-whisper (+ model) for matching deliverables
    one
    step install box bridge -v "$SRC:/studio:rw" -v "$SCRATCH:/scratch" -v "$PYENV:/pyenv:ro" -- \
      sh -c 'npm ci --no-audit --no-fund && npx remotion browser ensure && mkdir -p renders node_modules/.cache'
    if [[ "$ARG" =~ $(cfg whisper_pattern) ]]; then
      step whisper box bridge -v "$SRC:/studio:ro" -v "$SCRATCH:/scratch" -v "$PYENV:/pyenv:rw" -- \
        sh -c 'python3 -m venv /pyenv && /pyenv/bin/pip install -q faster-whisper && /pyenv/bin/python -c "from faster_whisper import WhisperModel as M; M(\"small\", device=\"cpu\", compute_type=\"int8\")"'
    fi
    ;;
  inputs)   # container, network none: emits the Drive paths + audio URLs this deliverable needs (untrusted data)
    one
    step inputs box none -v "$SRC:/studio:ro" -v "$STAGE:/drive:ro" -v "$OUT:/out" -v "$SCRATCH:/scratch" -v "$PYENV:/pyenv:ro" -- \
      python3 "$(cfg plan)" inputs "$ARG" /out/inputs.json
    ;;
  pull)     # host: validated pulls into the staging tree + allowlisted audio prefetch
    one; idle
    step pull "${DRIVE[@]}" pull-spec "$STAGE" "$W/pulled.json" "$OUT/inputs.json"
    step prefetch "${DRIVE[@]}" fetch "$STAGE" "$OUT/inputs.json"
    ;;
  render)   # container, network none: the unchanged worker against the staging tree, then its result helper
    one
    date -u +%FT%TZ > "$W/start"
    step render box none -v "$SRC:/studio:ro" -v "$RENDERS:/studio/renders:rw" --tmpfs /studio/node_modules/.cache:rw,size=4g \
      -v "$STAGE:/drive:rw" -v "$OUT:/out" -v "$SCRATCH:/scratch" -v "$PYENV:/pyenv:ro" -e HF_HUB_OFFLINE=1 -- \
      sh -c 'python3 "$1" > /scratch/worker.py && python3 /scratch/worker.py; s=$?; python3 "$2" result "$V5_ONLY" /out/result.json; exit $s' \
      _ "$(cfg worker_generator)" "$(cfg plan)"
    ;;
  upload)   # host: upload NEW/CHANGED allowlisted files (md5+size+drive verified), then the FINAL ledger record
    one; idle
    step push "${DRIVE[@]}" push "$STAGE" "$W/pulled.json" "$ARG" "$W/push.json" || true   # finalize records the failure
    step finalize "${DRIVE[@]}" finalize "$STAGE" "$OUT/result.json" "$ARG" "$(cat "$W/start" 2>/dev/null || date -u +%FT%TZ)" "$W/push.json"
    ;;
  plan-pull)  # host: ledger folder into the staging tree
    printf '{"pull":[{"path":"01_PROJECT_CONTROL/render-ledger"}]}' > "$W/plan-inputs.json"
    step plan-pull "${DRIVE[@]}" pull-spec "$STAGE" "$W/pulled.json" "$W/plan-inputs.json"
    ;;
  plan)     # container, network none: matrix + WAITING_FOR_CAPTURE ledger records
    step plan box none -v "$SRC:/studio:ro" -v "$STAGE:/drive:rw" -v "$OUT:/out" -v "$SCRATCH:/scratch" -v "$PYENV:/pyenv:ro" -- \
      python3 "$(cfg plan)" plan "$ARG" /out/matrix.json
    ;;
  plan-publish)  # host: upload the WAITING records, validate the matrix before it reaches GITHUB_OUTPUT
    idle
    step plan-ledger "${DRIVE[@]}" push "$STAGE" "$W/pulled.json" plan "$W/push.json"
    matrix=$(python3 -I - "$OUT/matrix.json" <<'PY' || true
import json, os, re, sys
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW)
m = json.loads(os.read(fd, 65536))
ok = isinstance(m, list) and len(m) <= 12 and len(set(m)) == len(m) and all(isinstance(x, str) and re.fullmatch(r"V5-V00[1-6]-(master|reel)", x) for x in m)
print(json.dumps(m) if ok else "")
PY
)
    [ -n "$matrix" ] || { echo "matrix FAIL"; exit 1; }
    echo "matrix=$matrix" >> "$GITHUB_OUTPUT"
    echo "matrix PASS"
    ;;
  selftest)  # host only, no container: proves the Drive boundary; one PASS/FAIL line per check, counts only
    [ "$ARG" = selftest ] || { echo "input FAIL (selftest expected)"; exit 2; }
    "${DRIVE[@]}" selftest "${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}" 2>> "$LOGS/selftest.log"
    ;;
  revoke)   # host only, end of production: revoke the Google grant, then prove the credential is dead
    [ "$ARG" = revoke ] || { echo "input FAIL (revoke expected)"; exit 2; }
    "${DRIVE[@]}" revoke 2>> "$LOGS/revoke.log"
    rm -f "$LOGS/revoke.log"   # nothing to archive: the credential that would upload it no longer exists
    ;;
  cleanup)
    docker ps -q | xargs -r docker kill > /dev/null 2>&1 || true
    if [ -n "$(ls -A "$LOGS" 2>/dev/null)" ] && [ -n "${DRIVE_STUDIO_FOLDER_ID:-}" ]; then
      "${DRIVE[@]}" logs "$LOGS" "${GITHUB_RUN_ID:-local}-${GITHUB_JOB:-job}-$ARG" > /dev/null 2>&1 && echo "logs PASS" || echo "logs FAIL"
    fi
    chmod -R u+rwX "$W" 2>/dev/null || true
    rm -rf "$W"   # private bundle, staging tree, media, renders, logs
    docker image rm -f "$IMAGE" > /dev/null 2>&1 || true
    echo "cleanup PASS"
    ;;
  *) sed -n '2,4p' "$0"; exit 2 ;;
esac
