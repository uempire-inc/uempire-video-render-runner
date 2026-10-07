#!/usr/bin/env bash
# Public repository safety audit. Exit 0 = PASS, 1 = FAIL. Checks the working tree AND every commit of every ref.
#
#   scripts/public-safety-audit.sh [private-patterns-file]
#
# private-patterns-file (optional, kept OUTSIDE this repository): one case-insensitive extended regex per line
# describing private business content (product names, prices, people, ids...). Keeping it outside means the audit
# itself never publishes what it protects. This script only holds generic secret patterns.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"
PRIVATE_PATTERNS=${1:-}
FAIL=0
fail() { echo "FAIL  $*"; FAIL=1; }
ok()   { echo "PASS  $*"; }

ALLOW='^(\.gitignore|README\.md|\.github/workflows/render\.yml|bootstrap/run\.sh|bootstrap/drive\.py|container/Dockerfile|scripts/public-safety-audit\.sh)$'
PUBLIC_FILES='.github/workflows/render.yml .gitignore README.md bootstrap/drive.py bootstrap/run.sh container/Dockerfile scripts/public-safety-audit.sh'
SELF='scripts/public-safety-audit.sh'   # holds the patterns below, so it is excluded from the content scan
MEDIA='\.(mp4|mov|m4v|mkv|webm|avi|wav|mp3|m4a|aac|flac|ogg|opus|png|jpe?g|gif|webp|avif|heic|tiff?|bmp|psd|svg|pdf|zip|t?gz|tar|7z|bin|onnx|pt|ckpt|safetensors|ipynb|jsonl?|env|log|pem|p12|key|srt|vtt)$'
SECRETS='-----BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ya29\.[0-9A-Za-z_-]+|1//[0-9A-Za-z_-]{20,}|GOCSPX-[0-9A-Za-z_-]+|gh[pousr]_[0-9A-Za-z]{30,}|github_pat_[0-9A-Za-z_]{20,}|sk-[0-9A-Za-z]{20,}|xox[abpr]-[0-9A-Za-z-]+|xi-api-key|X-Goog-(Signature|Credential)|storage\.googleapis\.com/[^ ]*\?|drive\.google\.com/(file/d|open\?id)|docs\.google\.com/|"refresh_token" *: *"[^"$]|client_secret *[:=] *["'"'"'][^"'"'"'$]|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}'
DRIVE_ID='(^|[^A-Za-z0-9_-])1[A-Za-z0-9_-]{32}([^A-Za-z0-9_-]|$)'

scan() {  # scan <label> <content-stream on stdin>
  local label=$1 data; data=$(sed -E 's/[A-Za-z0-9._+-]+@users\.noreply\.github\.com//g; s/noreply@anthropic\.com//g')  # public no-reply addresses are fine
  if grep -Eq -- "$SECRETS" <<<"$data"; then fail "$label: secret-like pattern: $(grep -Eo -- "$SECRETS" <<<"$data" | head -3 | sed 's/\(.\{6\}\).*/\1…/' | tr '\n' ' ')"; fi
  if grep -Eq -- "$DRIVE_ID" <<<"$data"; then fail "$label: Google Drive file id pattern"; fi
  if [ -n "$PRIVATE_PATTERNS" ]; then
    while IFS= read -r pat; do
      [ -z "$pat" ] || [[ "$pat" == \#* ]] && continue
      grep -Eiq -- "$pat" <<<"$data" && fail "$label: private content pattern #$(grep -nxF -- "$pat" "$PRIVATE_PATTERNS" | cut -d: -f1)"
    done < "$PRIVATE_PATTERNS"
  fi
}

echo "== 0. Staged index (exactly what the next commit will contain)"
staged=$(git diff --cached --name-only)
if [ -n "$staged" ]; then
  while IFS= read -r f; do
    [[ "$f" =~ $ALLOW ]] || fail "staged: file not in public allowlist: $f"
    [[ "$f" =~ $MEDIA ]] && fail "staged: media/data/secret file type: $f"
    [ "$f" = "$SELF" ] || git show ":$f" | scan "staged:$f"
  done <<<"$staged"
  [ "$(git ls-files | sort)" = "$(printf '%s\n' $PUBLIC_FILES | sort)" ] \
    && ok "staged/index set equals the 7-file allowlist" || fail "index does not equal the exact 7-file allowlist"
else ok "nothing staged"; fi

echo "== 1. Working tree"
while IFS= read -r f; do
  [[ "$f" =~ $ALLOW ]] || fail "tree: file not in public allowlist: $f"
  [[ "$f" =~ $MEDIA ]] && fail "tree: media/data/secret file type: $f"
  [ "$f" = "$SELF" ] || scan "tree:$f" < "$f"
done < <(git ls-files --cached --others --exclude-standard; find . -type f -not -path './.git/*' | sed 's|^\./||')
[ -z "$(find . -type f -size +512k -not -path './.git/*')" ] || fail "tree: file larger than 512 KB"

echo "== 2. Git history (all refs, all commits)"
if git rev-parse --verify -q HEAD > /dev/null; then
  while IFS= read -r f; do
    [[ "$f" =~ $ALLOW ]] || fail "history: path ever committed outside allowlist: $f"
    [[ "$f" =~ $MEDIA ]] && fail "history: media/data/secret file type ever committed: $f"
  done < <(git log --all --format= --name-only | sort -u | sed '/^$/d')
  git log --all -p --format='commit %H%n%an <%ae>%n%s' -- . ":(exclude)$SELF" | scan "history"
  git log --all --format='%an <%ae> | %cn <%ce>' | sort -u | while read -r who; do echo "      author/committer: $who"; done
else
  ok "history: no commits yet"
fi

echo "== 3. Workflow policy"
W=.github/workflows/render.yml
triggers=$(python3 - "$W" <<'PY'
import sys, re
s = open(sys.argv[1]).read()
block = re.search(r'^on:\n((?:[ \t]+.*\n|\n)+)', s, re.M).group(1)
print(" ".join(re.findall(r'^  ([a-z_]+):', block, re.M)))
PY
)
[ "$triggers" = "workflow_dispatch" ] && ok "triggers: workflow_dispatch only" || fail "triggers: '$triggers' (only workflow_dispatch allowed)"
grep -Eq 'pull_request_target|^\s*(push|pull_request|schedule|repository_dispatch|workflow_run|issue_comment):' "$W" && fail "workflow: forbidden trigger keyword present"
python3 -c 'import re,sys; s=open(sys.argv[1]).read(); sys.exit(0 if re.search(r"^permissions:\n  contents: read\n(?!  )", s, re.M) and s.count("permissions:")==1 else 1)' "$W" \
  && ok "permissions: exactly contents: read, workflow level only" || fail "permissions: must be exactly 'contents: read' at workflow level"
grep -Eq 'upload-artifact|actions/cache' "$W" && fail "workflow: artifact/cache upload present" || ok "no artifact or cache upload"
grep -Eq 'ACTIONS_(STEP|RUNNER)_DEBUG|set -x|--verbose|-vv|log-level (DEBUG|INFO)|http\.client\.HTTPConnection\.debuglevel|set_debuglevel' "$W" bootstrap/run.sh bootstrap/drive.py && fail "debug logging enabled" || ok "no debug logging"
grep -Eq 'max-parallel: 2$' "$W" && ok "max-parallel: 2" || fail "max-parallel must be 2"
grep -Eq 'persist-credentials: false' "$W" && ok "checkout does not persist the token" || fail "checkout must set persist-credentials: false"
grep -E '^\s*- uses: ' "$W" | grep -Evq '@[0-9a-f]{40}( |$)' && fail "actions not pinned to a commit SHA" || ok "actions pinned to commit SHAs"
grep -E '^\s*run: .*\$\{\{' "$W" | grep -q . && fail "expression interpolated directly in a run: line" || ok "no \${{ }} inside run: lines"
grep -Eq '(echo|printf|cat).*(SECRET|TOKEN|REFRESH|CLIENT_ID|BUNDLE_PATH|WIF_|SHARED_DRIVE)' "$W" bootstrap/run.sh && fail "a secret may be printed" || ok "no secret printing"
grep -Eq 'echo .*(url|URL)|print\(.*url' bootstrap/run.sh && fail "a URL may be printed" || ok "no URL printing"
V='\b(url|full|session|token|form|want|got|rel|path|STUDIO|FINAL|meta|fid|r|m|st|tag|data|back|vf|chain|ids|e\.(reason|read|headers|url|msg))\b'
grep -Eq "(log|print|die)\((f\"[^\"]*\{[^}]*$V|[^\"]*$V)" bootstrap/drive.py \
  && fail "drive.py may print a token, URL, id, path or configuration value" || ok "drive.py prints no token/URL/id/config value"

echo "== 4. Workflow exfiltration surface (YAML, step level)"
ruby -ryaml -rjson -e 'puts JSON.generate(YAML.load_file(ARGV[0]))' "$W" > "${TMPDIR:-/tmp}/wf.json" || fail "workflow YAML does not parse"
python3 - "$W" "${TMPDIR:-/tmp}/wf.json" <<'PY' || FAIL=1
import json, re, sys
src = open(sys.argv[1]).read()
wf = json.load(open(sys.argv[2]))
dump = lambda o: json.dumps(o)
on = wf.get("on", wf.get("true"))
bad = []
def chk(cond, msg): print(("PASS  " if cond else "FAIL  ") + msg); cond or bad.append(msg)
chk(set(on) == {"workflow_dispatch"}, "only workflow_dispatch trigger")
chk(wf.get("permissions") == {"contents": "read"}, "workflow token: exactly contents: read (no id-token)")
SECRET = re.compile(r"\$\{\{\s*(secrets|vars)\.")
chk(set(re.findall(r"secrets\.([A-Za-z0-9_]+)", src)) <= {"GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REFRESH_TOKEN", "DRIVE_BUNDLE_SHA256"},
    "only the OAuth client/refresh-token secrets and DRIVE_BUNDLE_SHA256 are secrets")
chk(set(re.findall(r"vars\.([A-Za-z0-9_]+)", src)) <= {"DRIVE_STUDIO_FOLDER_ID", "DRIVE_FINAL_FOLDER_ID", "DRIVE_BUNDLE_PATH"}, "only DRIVE_STUDIO_FOLDER_ID / DRIVE_FINAL_FOLDER_ID / DRIVE_BUNDLE_PATH are variables")
chk(not SECRET.search(dump(wf.get("env", {}))), "no secrets in workflow-level env")
ALLOWED_ACTIONS = {"actions/checkout"}   # no third-party (auth) action: the OIDC exchange is bootstrap/drive.py
for jname, job in wf["jobs"].items():
    chk("permissions" not in job, f"{jname}: no job-level permission escalation")
    chk(not SECRET.search(dump(job.get("env", {}))), f"{jname}: no secrets in job-level env")
    if "strategy" in job: chk(job["strategy"].get("max-parallel") == 2, f"{jname}: max-parallel 2")
    steps = job["steps"]
    for st in steps:
        name = st.get("name") or st.get("uses", "?")
        if "uses" in st:
            repo, _, ref = st["uses"].partition("@")
            chk(repo in ALLOWED_ACTIONS and re.fullmatch(r"[0-9a-f]{40}", ref or ""), f"{jname}/{name}: allowlisted action pinned by SHA")
            chk(st.get("with", {}).get("persist-credentials") is not False if repo != "actions/checkout" else st["with"].get("persist-credentials") is False,
                f"{jname}/{name}: checkout token not persisted" if repo == "actions/checkout" else f"{jname}/{name}: ok")
        run = st.get("run", "")
        chk("${{" not in run, f"{jname}/{name}: no expression inside run")
        has_secret = bool(SECRET.search(dump(st.get("env", {}))))
        if re.search(r"run\.sh (image|install|inputs|render|plan)( |$)", run) or re.search(r"apt-get|docker|npm|npx|node|ffmpeg|pip", run):
            chk(not has_secret, f"{jname}/{name}: sandbox/third-party step runs without secrets or variables")
        if has_secret:
            chk(re.fullmatch(r"bootstrap/run\.sh (fetch|plan-pull|plan-publish|pull|upload|selftest|cleanup) \"?\$[A-Z_]+\"?|bootstrap/run\.sh cleanup plan", run.strip()) is not None,
                f"{jname}/{name}: credentials only reach the host steps fetch/plan-pull/plan-publish/pull/upload/selftest/cleanup")
        chk(not re.search(r"ACTIONS_ID_TOKEN|GITHUB_TOKEN|github\.token", dump(st)), f"{jname}/{name}: no OIDC/GitHub token handed to a step")
    cleanup = [s for s in steps if "cleanup" in s.get("run", "")]
    chk(bool(cleanup) and cleanup[-1].get("if") == "always()" and steps[-1] is cleanup[-1], f"{jname}: final cleanup step with if: always()")
chk(not re.search(r"upload-artifact|actions/cache|cache:", src), "no artifact or cache usage")
chk(not re.search(r"toJSON\(\s*secrets|secrets\[", src), "no bulk secret serialization")
sys.exit(1 if bad else 0)
PY

echo "== 5. Bootstrap hygiene"
B=bootstrap/run.sh
# a dump = env/printenv with no argument (or piped/redirected), export -p, declare -p, compgen -v, bare `set`; `env -i` (clears) is fine
grep -Eq '\bprintenv\b|(^|[^-_[:alnum:]])env[[:space:]]*($|[|>;&)])|export -p|declare -p|compgen -v|(^|[;&|)][[:space:]]*)set[[:space:]]*($|[|>])' \
  <(grep -v '^\s*#' "$B" "$W") && fail "environment dump command present" || ok "no env/printenv/declare dump (env -i allowed)"
grep -Eq '(curl|wget)[^|]*\|\s*(sudo\s+)?(ba)?sh' "$B" "$W" && fail "curl|sh install pattern" || ok "no curl|sh installs"
grep -q 'sha256sum --check' "$B" && ok "bundle sha256 verified before extraction" || fail "bundle integrity check missing"
grep -q 'filter="data"' "$B" && ok "safe tar extraction (data filter)" || fail "unsafe bundle extraction"
grep -q 'sha256 mismatch' bootstrap/drive.py && grep -q 'hmac.compare_digest' bootstrap/drive.py && ok "bundle sha256 also verified in drive.py" || fail "drive.py bundle sha256 check missing"
grep -Eq 'npm (install|i) ' "$B" && fail "npm install (non-lockfile) used" || ok "npm ci only (lockfile integrity)"
grep -q 'rm -rf "\$W"' "$B" && ok "bundle, media and logs wiped at cleanup" || fail "cleanup does not wipe the workspace"
grep -q 'umask 077' "$B" && ok "private files created 0600/0700" || fail "umask 077 missing"
miss=0; for v in 'ARG" =~' 'V5_JOB:-latest.json}" =~' 'V5_FORCE:-0}" =~' '!= *..*'; do grep -qF -- "$v" "$B" || { fail "input validation missing: $v"; miss=1; }; done
[ $miss -eq 0 ] && ok "all dispatch inputs validated (allowlist regex, no '..')"
if grep -Eq '^\s+echo ' <(grep -v '^\s*#' "$B") && grep -E '^\s+echo ' "$B" | grep -Evq 'echo "[a-z-]+ (STARTED|PASS|FAIL)[^"]*"|echo "\$name (STARTED|PASS|FAIL)|echo "\$DRIVE_BUNDLE_SHA256  \$W/bundle.tgz" \| sha256sum|echo "(input|config|container|matrix|bundle|bundle-integrity|logs|cleanup) (PASS|FAIL)[^"]*"|echo "matrix=\$matrix" >> "\$GITHUB_OUTPUT"'; then
  fail "console echo outside the generic STARTED/PASS/FAIL vocabulary"; grep -nE '^\s+echo ' "$B" | grep -Ev 'STARTED|PASS|FAIL|sha256sum'
else ok "console output limited to STARTED/PASS/FAIL/duration"; fi

echo "== 6. Credential scope, sandbox and studio-folder invariants"
D=bootstrap/drive.py; F=container/Dockerfile
# 6a. no rclone, no SA keys / workload identity / OIDC token, no third-party auth action
grep -Eiq 'rclone|credentials_json|GOOGLE_APPLICATION_CREDENTIALS|private_key|service_account|serviceAccount|google-github-actions|id-token|ACTIONS_ID_TOKEN|sts\.googleapis|iamcredentials' \
  "$W" "$B" "$D" "$F" README.md .gitignore && fail "rclone / SA key / OIDC / auth action referenced" || ok "no rclone, SA key, id-token/OIDC or third-party auth action"
# 6b. every container goes through ONE hardened docker run
[ "$(grep -c 'docker run' "$B")" = 1 ] && ok "a single docker run (box) launches every container" || fail "docker run outside the hardened box() helper"
run_line=$(grep 'docker run' "$B")
for flag in '--cap-drop=ALL' '--security-opt=no-new-privileges' '--read-only' '--user "$(id -u):$(id -g)"' '--network "$net"' '--rm'; do
  grep -qF -- "$flag" <<<"$run_line" && ok "docker run has $flag" || fail "docker run lacks $flag"
done
[ "$(grep -Ec '^\s+step (inputs|render|plan) box none ' "$B")" = 3 ] \
  && ok "plan, plan-inputs and render containers run with --network none" || fail "plan/inputs/render container not on --network none"
grep -E '\bbox [a-z]+ ' "$B" | grep -Ev '\bbox none |step (install|whisper) box bridge ' | grep -q . \
  && fail "a container other than install/whisper has network" || ok "only the install stage has network"
grep -Eq 'docker\.sock|--privileged|--pid[= ]*host|--ipc[= ]*host|--uts[= ]*host|--userns[= ]*host|--network[= ]*host|--cap-add|--device|--env-file|unconfined|-v "?(\$HOME|~|/:|/proc|/sys|/var/run|/home|\$RUNNER_TEMP:|\$GITHUB_)' "$B" \
  && fail "forbidden docker option (socket, privileged, host namespaces, cap-add, device, env-file, HOME/proc mount)" || ok "no docker socket, privileged, host pid/ipc/net, cap-add, env-file, HOME or /proc mount"
grep -Eo -- '(^|\s)-e [^ ]+' "$B" | grep -Ev -- '-e [A-Za-z0-9_]+=' | grep -q . && fail "docker -e passthrough without a value" || ok "every docker -e sets an explicit value (no host env passthrough)"
grep -Eq -- '-e "?(GITHUB_|ACTIONS_|GOOGLE_|DRIVE_)' "$B" && fail "GITHUB_/ACTIONS_/credential variable passed to a container" || ok "no GITHUB_/ACTIONS_/GOOGLE_/DRIVE_ variable passed to a container"
[ "$(grep -Ec '^\s+(one; )?idle$' "$B")" -ge 3 ] && ok "authenticated steps first assert that no container is running" || fail "idle() check missing before authenticated steps"
# 6c. Dockerfile: every base image pinned by digest, non-root user, nothing copied in
grep -E '^FROM ' "$F" | grep -Evq '@sha256:[0-9a-f]{64}( |$)' && fail "Dockerfile base image not pinned by @sha256 digest" || ok "Dockerfile base image pinned by @sha256 digest"
last_user=$(grep -E '^USER ' "$F" | tail -1 | awk '{print $2}')
[ -n "$last_user" ] && [[ ! "$last_user" =~ ^(root|0)(:|$) ]] && ok "Dockerfile ends as a non-root user" || fail "Dockerfile must end with a non-root USER"
grep -Eq '^(ADD|COPY) ' "$F" && fail "Dockerfile copies files into the image" || ok "Dockerfile copies nothing into the image"
# 6d. drive.py: stdlib only, studio-folder scope, no global search, guarded deletes, allowlisted uploads and fetches
python3 - "$D" <<'PYCHECK' || FAIL=1
import ast, re, sys
src = open(sys.argv[1]).read(); tree = ast.parse(src)
bad = []
def chk(cond, msg): print(("PASS  " if cond else "FAIL  ") + msg); cond or bad.append(msg)
STDLIB = {"datetime", "fnmatch", "hashlib", "hmac", "json", "os", "re", "secrets", "stat", "sys", "time", "urllib", "urllib.error", "urllib.parse", "urllib.request"}
mods = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} | {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
chk(mods <= STDLIB, "drive.py imports the standard library only")
chk(not re.search(r"subprocess|\beval\(|\bexec\(|pickle|os\.system|os\.popen", src), "drive.py never executes anything")
fns = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
seg = lambda name: ast.get_source_segment(src, fns[name]) if name in fns else ""
callers = lambda target: {f for f, n in fns.items() if any(isinstance(c, ast.Call) and getattr(c.func, "id", "") == target for c in ast.walk(n))}
direct = [ast.get_source_segment(src, c.args[1]) for c in ast.walk(tree) if isinstance(c, ast.Call) and getattr(c.func, "id", "") == "_req" and len(c.args) > 1]
chk(not any(re.search(r"DRIVE_API|UPLOAD_API", a) for a in direct), "every Drive call goes through api() (only token, upload session and fetch call _req)")
# auth: refresh-token exchange, memory only, renewed on expiry / 401
chk('TOKEN_URL = "https://oauth2.googleapis.com/token"' in src and '"grant_type": "refresh_token"' in seg("Auth") if "Auth" in fns else
    'TOKEN_URL = "https://oauth2.googleapis.com/token"' in src and '"grant_type": "refresh_token"' in src, "OAuth refresh token exchanged at oauth2.googleapis.com/token")
chk("renew=True" in seg("api") and "time.time() > self.expires" in src, "access token re-exchanged on expiry and on HTTP 401")
auth = ast.get_source_segment(src, next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Auth"))
outside_auth = src.replace(auth, "").replace(ast.get_docstring(tree, clean=False) or "", "")   # the docstring only names the variables
chk(not re.search(r"\bopen\(|\.write\(|\bprint\(|\blog\(|json\.dump|environ\[|setdefault", auth)
    and not re.search(r"GOOGLE_CLIENT_SECRET|GOOGLE_REFRESH_TOKEN|client_secret|refresh_token|access_token|\bform\b", outside_auth)
    and not re.search(r"(open|write|dump)\([^)]*(token|AUTH|secret)", src, re.I) and "environ[" not in src,
    "credentials stay inside Auth: never written, logged or exported; only the access token leaves it, in memory")
# scope: parent-scoped resolution from the studio folder, no global search
NAMEQ = re.compile(r"""name\s*(=|!=|contains)\s*\\?'|fullText""")
chk({f for f, n in fns.items() if NAMEQ.search(ast.get_source_segment(src, n))} == {"children"} and not NAMEQ.search(re.sub(r"(?s)\ndef .*", "", src.split("\ndef ", 1)[0]))
    and re.search(r"""q = f"'\{need_in\(folder_id\)\}' in parents and trashed = false\"""", seg("children")) is not None,
    "name queries only inside children(), always '<parent>' in parents (no global name search)")
chk(not re.search(r"allDrives|corpora\W+(domain|drive)|\bspaces\b|sharedWithMe|/drive/v2", src.replace("supportsAllDrives", "")),
    "no corpora=allDrives/domain/drive, no sharedWithMe/spaces/v2")
chk({f for f, n in fns.items() if "corpora" in ast.get_source_segment(src, n)} <= {"boundary"} and '"corpora": "user", "q": "trashed = false"' in seg("boundary")
    and callers("boundary") == {"cmd_selftest"}, "the only account-wide listing is the selftest boundary count (corpora=user, trashed=false)")
chk('STUDIO = env("DRIVE_STUDIO_FOLDER_ID"' in src and 'FINAL = env("DRIVE_FINAL_FOLDER_ID"' in src, "both roots come from repository variables (no hardcoded folder id)")
chk("root, video, parts = route(rel)" in seg("lookup") and "parent = root" in seg("lookup") and "return FINAL, " in seg("route") and "return STUDIO, " in seg("route"),
    "paths resolve parent -> child from their own root (final exports -> final root, the rest -> studio)")
r6 = re.search(r'FINAL_SUBS = \(([^)]*)\)', src); rt = re.search(r'FINAL_ROUTE = re.compile\(r"06_FINAL_EXPORTS/2026/\(V\\d\{3\}\)_\[\^/\]\+/\(([A-Z|]+)\)', src)
chk(bool(r6 and rt) and sorted(re.findall(r'"([A-Z]+)"', r6.group(1))) == sorted(rt.group(1).split("|")) == sorted(["MASTER", "REEL", "QA", "SUBTITLES", "THUMBNAILS", "MANIFEST"]),
    "final root receives exactly MASTER/REEL/QA/SUBTITLES/THUMBNAILS/MANIFEST")
chk(re.search(r'\n( +)if root == FINAL and not \(\(i == 0 and part in FINAL_SUBS\) or \(i == 1 and parts\[0\] == "QA" and SELFTEST_DIR\.fullmatch\(part\)\)\):\n\1    die\("refused: folder creation in the final root outside the allowlist"\)\n\1meta = mkdir\(parent, part, root\)', seg("lookup")) is not None
    and seg("lookup").count("mkdir(") == 1 and "video_folder(video)" in seg("lookup") and "mkdir" not in seg("video_folder"),
    "final root: video folders never created, only allowlisted SUB folders (+ the QA self-test sandbox)")
for f in ("children", "download", "upload", "file_meta", "mkdir"):
    chk("need_in(" in seg(f), f"{f}() proves the target descends from its allowed root")
chk("parents" in seg("ancestry") and "root_of(" in seg("need_in") and "upload(" in seg("cmd_push") and "need_in(parent[\"id\"], root)" in seg("upload"),
    "ancestry walks parents up; each prefix may only be written to its own root")
# deletes: _selftest only
dels = {f for f, n in fns.items() if re.search(r'"DELETE"|\.delete\(|"trashed": *[Tt]rue', ast.get_source_segment(src, n))}
chk(dels == {"delete_selftest"} and callers("delete_selftest") == {"cmd_selftest"}, "delete exists only in delete_selftest(), called only by the selftest")
d = seg("delete_selftest")
g = seg("deletable")
chk("deletable(" in d and d.index("deletable(") < d.index('"DELETE"') and d.index("die(") < d.index('"DELETE"')
    and "lookup(SELFTEST)" in d and 'video_folder("V003")' in d and 'children(vf["id"], "QA")' in d
    and 'SELFTEST = "01_PROJECT_CONTROL/_selftest"' in src and "studio_selftest in ids[1:]" in g and "final_qa in ids[1:]" in g and "SELFTEST_DIR.fullmatch" in g
    and 'SELFTEST_DIR = re.compile(r"_selftest-' in src, "delete guarded: only under studio 01_PROJECT_CONTROL/_selftest or final V003_*/QA/_selftest-<run>")
# uploads
chk(callers("upload") == {"cmd_push", "cmd_finalize", "cmd_logs", "cmd_selftest"}, "uploads only from push / finalize / logs / selftest")
push = seg("cmd_push")
chk("write_allowed(" in push and push.index("write_allowed(") < push.index("upload("), "push checks every destination against the write allowlist before upload")
chk('upload(f, f"01_PROJECT_CONTROL/render-ledger/{cid}.final.json")' in seg("cmd_finalize") and "LOGS_ROOT" in seg("cmd_logs")
    and set(re.findall(r'probe\(f"([^{]*\{[A-Z_]*)', seg("cmd_selftest"))) == {"{SELFTEST", "06_FINAL_EXPORTS/2026/{"} and "/QA/_selftest-{tag}/" in seg("cmd_selftest"),
    "finalize / logs / selftest upload only to ledger / render-logs / the self-test sandboxes")
allow = re.search(r"WRITE_ALLOW = \((.*?)\n\)", src, re.S)
prefixes = sorted(set(re.findall(r'r"([^{(\\"]+)', allow.group(1)))) if allow else []
chk(prefixes == ["01_PROJECT_CONTROL/render-ledger/", "04_AUDIO/", "05_WORK_IN_PROGRESS/V5_QA_FAIL/", "06_FINAL_EXPORTS/2026/"],
    "write allowlist prefixes are exactly the owner's (final exports, 04_AUDIO, QA_FAIL, render-ledger)")
chk('FETCH_HOST, FETCH_PREFIX = "storage.googleapis.com", "/xi-backend/"' in src and "u.netloc != FETCH_HOST" in seg("cmd_fetch"), "fetch is limited to https://storage.googleapis.com/xi-backend/")
chk("Authorization" not in seg("cmd_fetch"), "fetch never sends a Google credential")
chk("_NoRedirect" in src and "O_NOFOLLOW" in seg("open_regular") and "followlinks=False" in push, "no HTTP redirect followed; staged symlinks never followed")
sys.exit(1 if bad else 0)
PYCHECK

if [ "${CHECK_REMOTE:-}" ]; then
  echo "== 7. Remote repository"
  [ "$(gh api "repos/$CHECK_REMOTE" -q .size 2>/dev/null)" = "0" ] && [ -z "$(gh api "repos/$CHECK_REMOTE/commits" 2>/dev/null | grep -o '"sha"' | head -1)" ] \
    && ok "remote $CHECK_REMOTE is empty (0 commits)" || fail "remote $CHECK_REMOTE is not empty"
  n=$(gh secret list --repo "$CHECK_REMOTE" 2>/dev/null | wc -l | tr -d ' '); echo "      remote secrets configured: $n"
fi

echo "== 7. Deliverable-scoped writes"
grep -q '{v}_\[^/\]+/{k}/\[^/\]\*-{k}-' bootstrap/drive.py && grep -q 'kind.upper()' bootstrap/drive.py \
  && ok "writes bound to one deliverable (video + MASTER|REEL kind)" || fail "write allowlist not bound to deliverable kind"
grep -q '^CREATE_ONLY = ' bootstrap/drive.py && grep -q 'CREATE_ONLY.fullmatch(rel) and lookup(rel)' bootstrap/drive.py \
  && ok "shared audio inputs are create-only" || fail "shared audio inputs can be overwritten"

echo
[ $FAIL -eq 0 ] && echo "FINAL_SECURITY_VERDICT=PASS" || echo "FINAL_SECURITY_VERDICT=FAIL"
exit $FAIL
