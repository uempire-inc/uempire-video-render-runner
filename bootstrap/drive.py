#!/usr/bin/env python3
"""Authenticated host tool of the render runner (stdlib only). It is the ONLY code that holds a Google credential.

Auth: OAuth refresh token of a dedicated low-privilege renderer account -> short-lived access token (kept in memory
only, re-exchanged on expiry or HTTP 401, then the operation is retried once). Scope: the TWO folders the owner shared
with the renderer as Editor: the studio folder $DRIVE_STUDIO_FOLDER_ID and the final output root $DRIVE_FINAL_FOLDER_ID.
06_FINAL_EXPORTS/2026/<V00X_*>/{MASTER,REEL,QA,SUBTITLES,THUMBNAILS,MANIFEST} maps to <final>/<V00X_*>/<SUB>; every other
path lives in the studio folder. Paths are resolved parent -> child by name from their root (never a global name
search), and every file is proven to descend from its own root (parents walked up) before it is read, written, renamed,
moved or deleted. Deletes happen only inside the two self-test sandboxes.

  drive.py bundle <out>                                download $DRIVE_BUNDLE_PATH, verify $DRIVE_BUNDLE_SHA256
  drive.py pull <stage> <manifest> <path>...           required Drive files -> staging tree
  drive.py pull-spec <stage> <manifest> <spec.json>    optional files/folders listed by the container (untrusted)
  drive.py fetch <stage> <spec.json>                   prefetch allowlisted HTTPS URLs (no Google credential sent)
  drive.py push <stage> <manifest> <scope> <report>    upload NEW/CHANGED allowlisted files, verify md5 + size
  drive.py finalize <stage> <result.json> <deliverable> <start> <report>   FINAL ledger record (exit 1 unless ready)
  drive.py logs <dir> <run-name>                       upload the private logs
  drive.py selftest <run-name>                         boundary self-test (PASS/FAIL line per check, counts only)

Env: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN, DRIVE_STUDIO_FOLDER_ID, DRIVE_FINAL_FOLDER_ID
(+ DRIVE_BUNDLE_PATH, DRIVE_BUNDLE_SHA256 for bundle). Output: no credential, URL, file id, file name or configuration
value is ever printed; progress goes to stderr (private log). Container outputs (spec, result, staged files) are
untrusted data: validated, never executed, symlinks never followed.
"""
import datetime, fnmatch, hashlib, hmac, json, os, re, secrets, stat, sys, time, urllib.error, urllib.parse, urllib.request

DRIVE_API = "https://www.googleapis.com/drive/v3/files"
UPLOAD_API = "https://www.googleapis.com/upload/drive/v3/files"
TOKEN_URL = "https://oauth2.googleapis.com/token"
FOLDER = "application/vnd.google-apps.folder"
CHUNK = 32 << 20                     # resumable upload chunk (multiple of 256 KiB)
DELIVERABLE = re.compile(r"V5-V00[1-6]-(master|reel)")
FETCH_HOST, FETCH_PREFIX = "storage.googleapis.com", "/xi-backend/"
SEGMENT = re.compile(r"[\w .,()+&@#=-]{1,200}")   # per path segment (unicode letters/digits allowed), no quotes or slashes
PATTERN = re.compile(r"[A-Za-z0-9_.*?\[\]-]{1,64}")

# Paths (relative to the studio folder) the host may READ (pull) and WRITE (push). Writes are bound to one deliverable.
READ_ALLOW = re.compile(r"(01_PROJECT_CONTROL/(jobs|render-ledger)|05_WORK_IN_PROGRESS|06_FINAL_EXPORTS/2026/V\d{3}_[^/]+/(AUDIO|QA))(/.*)?")
WRITE_ALLOW = (   # bound to ONE deliverable: {v}=V00X, {k}=MASTER|REEL (a reel job can never touch master files)
    r"06_FINAL_EXPORTS/2026/{v}_[^/]+/{k}/[^/]*-{k}-[^/]+",
    r"06_FINAL_EXPORTS/2026/{v}_[^/]+/(QA|THUMBNAILS|MANIFEST|SUBTITLES)/[^/]*-{k}-[^/]+",
    r"06_FINAL_EXPORTS/2026/{v}_[^/]+/AUDIO/[^/]+",
    r"04_AUDIO/{v}_[^/]+/[^/]+",
    r"05_WORK_IN_PROGRESS/V5_QA_FAIL/{v}_[^/]+/[^/]*-{k}-[^/]+",
    r"01_PROJECT_CONTROL/render-ledger/{cid}\.jsonl",      # the worker's own log; .final.json is written by finalize only
)
# Shared inputs (approved narration, music, SFX) are create-only: an existing Drive file is never replaced by a job.
CREATE_ONLY = re.compile(r"(06_FINAL_EXPORTS/2026/V\d{3}_[^/]+/AUDIO|04_AUDIO/V\d{3}_[^/]+)/[^/]+")
PLAN_WRITE = re.compile(r"01_PROJECT_CONTROL/render-ledger/V5-V00[1-6]-(master|reel)\.final\.json")
LOGS_ROOT = "01_PROJECT_CONTROL/render-logs"
SELFTEST = "01_PROJECT_CONTROL/_selftest"                # the ONLY place anything may ever be deleted


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def die(msg):
    log("ERROR:", msg)
    sys.exit(1)


def env(name, pattern):
    v = os.environ.get(name, "")
    if not re.fullmatch(pattern, v):
        die(f"{name} missing or malformed")
    return v


def valid_path(rel):
    """Studio-relative path: no absolute path, no '.'/'..', allowlisted characters only."""
    if not isinstance(rel, str) or len(rel) > 1024 or rel.startswith("/") or rel.endswith("/"):
        return False
    parts = rel.split("/")
    return all(SEGMENT.fullmatch(p) and p not in (".", "..") and p.strip() == p for p in parts)


def need_path(rel):
    if not valid_path(rel):
        die("invalid Drive path")
    return rel


def write_allowed(rel, scope):
    if scope == "plan":
        return bool(PLAN_WRITE.fullmatch(rel))
    _, v, kind = scope.split("-")
    k = kind.upper()
    return any(re.fullmatch(p.format(v=v, k=k, cid=re.escape(scope)), rel) for p in WRITE_ALLOW)


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- HTTP (no redirects, ever)
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_open = urllib.request.build_opener(_NoRedirect).open


def _req(method, url, body=None, headers=None, timeout=300):
    return _open(urllib.request.Request(url, data=body, headers=headers or {}, method=method), timeout=timeout)


def _json(resp):
    with resp:
        return json.loads(resp.read().decode())


# ---------------------------------------------------------------- OAuth (refresh token -> short access token)
class Auth:
    token, expires = None, 0.0

    def get(self, renew=False):
        if renew or not self.token or time.time() > self.expires - 300:
            self.token, self.expires = self._exchange()
        return self.token

    @staticmethod
    def _exchange():
        form = urllib.parse.urlencode({
            "client_id": env("GOOGLE_CLIENT_ID", r"[0-9]{6,30}-[a-z0-9]{10,64}\.apps\.googleusercontent\.com"),
            "client_secret": env("GOOGLE_CLIENT_SECRET", r"[A-Za-z0-9_-]{10,128}"),
            "refresh_token": env("GOOGLE_REFRESH_TOKEN", r"[A-Za-z0-9_./-]{20,1024}"),
            "grant_type": "refresh_token"}).encode()
        try:
            r = _json(_req("POST", TOKEN_URL, form, {"Content-Type": "application/x-www-form-urlencoded"}))
            return r["access_token"], time.time() + min(int(r.get("expires_in", 3600)), 3600)
        except urllib.error.HTTPError as e:
            die(f"credential exchange refused (HTTP {e.code})")
        except (urllib.error.URLError, KeyError, ValueError):
            die("credential exchange failed")


AUTH = Auth()


def api(method, url, params=None, body=None, headers=None, ok=(200,), what="request"):
    """Authenticated call. 401 -> re-exchange once and retry; 429/5xx -> bounded backoff. Never logs the URL."""
    params = dict(params or {}, supportsAllDrives="true")
    full = url + "?" + urllib.parse.urlencode(params)
    renewed = False
    for attempt in range(6):
        h = dict(headers or {}, Authorization="Bearer " + AUTH.get())
        try:
            resp = _req(method, full, body, h)
            if resp.status in ok:
                return resp
            resp.close()
            die(f"{what}: unexpected HTTP {resp.status}")
        except urllib.error.HTTPError as e:
            if e.code in ok:          # e.g. 308 (resumable upload incomplete) or 404 (absent) when expected
                return e
            e.close()
            if e.code == 401 and not renewed:
                AUTH.get(renew=True); renewed = True; continue
            if e.code in (429, 500, 502, 503, 504) and attempt < 5:
                time.sleep(2 ** attempt); continue
            die(f"{what}: HTTP {e.code}")
        except urllib.error.URLError:
            if attempt < 5:
                time.sleep(2 ** attempt); continue
            die(f"{what}: network error")
    die(f"{what}: gave up")


# ---------------------------------------------------------------- folder scope: two roots, each prefix to its own root
STUDIO = None                        # DRIVE_STUDIO_FOLDER_ID (working tree, ledger, logs, audio, QA-fail, _selftest)
FINAL = None                         # DRIVE_FINAL_FOLDER_ID  (<V00X_*>/{MASTER,REEL,QA,SUBTITLES,THUMBNAILS,MANIFEST})
FINAL_SUBS = ("MASTER", "REEL", "QA", "SUBTITLES", "THUMBNAILS", "MANIFEST")
FINAL_ROUTE = re.compile(r"06_FINAL_EXPORTS/2026/(V\d{3})_[^/]+/(MASTER|REEL|QA|SUBTITLES|THUMBNAILS|MANIFEST)(?:/(.+))?")
SELFTEST_DIR = re.compile(r"_selftest-[A-Za-z0-9-]{1,80}")   # disposable folder under <final>/V003_*/QA only
FIELDS = "id,name,mimeType,md5Checksum,size,parents,modifiedTime,trashed,webViewLink"
META, ROOT_OF = {}, {}               # id -> {id,name,parents} as observed; id -> root id or None (cache)


def get_meta(file_id, fields=FIELDS):
    """Metadata or None (404/403 = absent or not visible to the renderer)."""
    r = api("GET", f"{DRIVE_API}/{file_id}", {"fields": fields}, ok=(200, 403, 404), what="metadata")
    if (r.code if isinstance(r, urllib.error.HTTPError) else r.status) != 200:
        r.close(); return None
    meta = _json(r)
    META[meta["id"]] = {**META.get(meta["id"], {}), **meta}
    return meta


def ancestry(file_id):
    """[file, parent, ..., root] proven by walking `parents` up; None when no root is reached."""
    chain, cur = [], file_id
    for _ in range(64):
        m = META.get(cur) if cur in META and "parents" in META[cur] and "name" in META[cur] else get_meta(cur, "id,name,parents")
        if cur in (STUDIO, FINAL):
            return chain + [m or {"id": cur, "name": "", "parents": []}]
        if not m or not m.get("parents"):
            return None
        chain.append(m)
        cur = m["parents"][0]
    return None


def root_of(file_id):
    if file_id not in ROOT_OF:
        a = ancestry(file_id)
        ROOT_OF[file_id] = a[-1]["id"] if a else None
    return ROOT_OF[file_id]


def need_in(file_id, root=None):
    """Refuse any target that is not the given root (or, with root=None, either root) or one of its descendants."""
    r = root_of(file_id)
    if r is None or (root is not None and r != root):
        die("target outside its allowed root folder")
    return file_id


def children(folder_id, name=None):
    """Children of ONE folder (parent-scoped query, never a global search); duplicate names: the newest wins."""
    q = f"'{need_in(folder_id)}' in parents and trashed = false"
    if name is not None:
        q += " and name = '" + name.replace("\\", "\\\\").replace("'", "\\'") + "'"
    out, token = [], None
    while True:
        p = {"q": q, "pageSize": "1000", "fields": f"nextPageToken,files({FIELDS})"}
        if token:
            p["pageToken"] = token
        r = _json(api("GET", DRIVE_API, p, what="list"))
        for f in r.get("files", []):
            META[f["id"]] = f
            if folder_id in f.get("parents", []):
                out.append(f)
        token = r.get("nextPageToken")
        if not token:
            break
    newest = {}
    for f in sorted(out, key=lambda f: f.get("modifiedTime", "")):
        newest[(f["name"], f["mimeType"] == FOLDER)] = f
    return list(newest.values())


def mkdir(parent, name, root):
    meta = _json(api("POST", DRIVE_API, {"fields": FIELDS}, json.dumps(
        {"name": name, "mimeType": FOLDER, "parents": [need_in(parent, root)]}).encode(),
        {"Content-Type": "application/json"}, what="mkdir"))
    META[meta["id"]] = meta
    need_in(meta["id"], root)
    return meta


def video_folder(video):
    """The ONE existing <V00X_*> folder directly under the final root (never created)."""
    hits = [c for c in children(FINAL) if c["mimeType"] == FOLDER and c["name"].startswith(video + "_")]
    return hits[0] if len(hits) == 1 else None


def route(rel):
    """(root, video, parts): final-export subfolders go to the final root, everything else to the studio folder."""
    m = FINAL_ROUTE.fullmatch(need_path(rel))
    if m:
        return FINAL, m.group(1), [m.group(2)] + (m.group(3).split("/") if m.group(3) else [])
    return STUDIO, None, rel.split("/")


def lookup(rel, create=False):
    """Resolve a path parent -> child by name from its root; optionally create allowlisted missing folders."""
    root, video, parts = route(rel)
    parent = root
    if video:
        vf = video_folder(video)
        if not vf:
            return None if not create else die("final video folder missing or ambiguous")
        parent = vf["id"]
    meta = None
    for i, part in enumerate(parts):
        last = i == len(parts) - 1
        hits = children(parent, part)
        folders = [f for f in hits if f["mimeType"] == FOLDER]
        files = [f for f in hits if f["mimeType"] != FOLDER]
        meta = (files or folders)[0] if last and (files or folders) else (folders[0] if folders else None)
        if meta is None:                       # create=True: every missing segment is a folder (callers pass folder paths)
            if not create:
                return None
            if root == FINAL and not ((i == 0 and part in FINAL_SUBS) or (i == 1 and parts[0] == "QA" and SELFTEST_DIR.fullmatch(part))):
                die("refused: folder creation in the final root outside the allowlist")
            meta = mkdir(parent, part, root)
        parent = meta["id"]
    return meta if meta is None or need_in(meta["id"], root) else None


def file_meta(file_id):
    meta = get_meta(need_in(file_id))
    return meta if meta and not meta.get("trashed") else None


# ---------------------------------------------------------------- local files (never follow symlinks)
def local_path(stage, rel):
    p = os.path.join(stage, *rel.split("/"))
    real = os.path.realpath(os.path.dirname(p))
    if real != os.path.realpath(stage) and not real.startswith(os.path.realpath(stage) + os.sep):
        die("staging path escapes the staging tree")
    return p


def open_regular(p):
    """Open a regular, single-link file without following a symlink; None otherwise."""
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        os.close(fd)
        return None
    return os.fdopen(fd, "rb")


def digest(f, algo="md5"):
    h = hashlib.new(algo)
    for b in iter(lambda: f.read(1 << 20), b""):
        h.update(b)
    return h.hexdigest()


def download(meta, dest):
    if meta.get("mimeType", "").startswith("application/vnd.google-apps."):
        log("skip native Google document"); return None
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    tmp, md5 = dest + ".part", hashlib.md5()
    with api("GET", f"{DRIVE_API}/{need_in(meta['id'])}", {"alt": "media"}, what="download") as r, open(tmp, "wb") as f:
        for b in iter(lambda: r.read(1 << 20), b""):
            md5.update(b); f.write(b)
    if md5.hexdigest() != meta.get("md5Checksum") or os.path.getsize(tmp) != int(meta.get("size", -1)):
        os.remove(tmp); die("download integrity check failed")
    os.replace(tmp, dest)
    return md5.hexdigest()


def pull_tree(stage, rel, meta, manifest, exclude=(), keep=(), depth=0):
    if depth > 20 or len(manifest) > 50000:
        die("pull too deep or too large")
    if meta["mimeType"] != FOLDER:
        manifest[rel] = download(meta, local_path(stage, rel)); return
    os.makedirs(local_path(stage, rel), exist_ok=True)
    for c in children(meta["id"]):
        name = c["name"]
        if depth == 0 and name not in keep and any(fnmatch.fnmatchcase(name, p) for p in exclude):
            continue
        if not SEGMENT.fullmatch(name) or name in (".", ".."):
            log("skip a Drive entry with a non-allowlisted name"); continue
        pull_tree(stage, f"{rel}/{name}", c, manifest, depth=depth + 1)


def load_json(path, limit=4 << 20):
    f = open_regular(path)
    if f is None:
        return None
    with f:
        data = f.read(limit + 1)
    if len(data) > limit:
        die("JSON input too large")
    try:
        return json.loads(data)
    except ValueError:
        die("JSON input malformed")


def save_manifest(path, manifest):
    old = load_json(path) or {}
    old.update({k: v for k, v in manifest.items() if v})
    with open(path, "w") as f:
        json.dump(old, f)


# ---------------------------------------------------------------- upload (resumable) + verification
def upload(src, rel):
    """Create or replace <rel> (inside the studio folder) from an open local file; return verified metadata or None."""
    size = os.fstat(src.fileno()).st_size
    md5 = digest(src); src.seek(0)
    root = route(rel)[0]
    parent_rel, name = rel.rsplit("/", 1)
    parent = lookup(parent_rel, create=True)
    if not parent:
        die("upload destination folder unavailable")
    need_in(parent["id"], root)
    existing = [f for f in children(parent["id"], name) if f["mimeType"] != FOLDER]
    hdr = {"Content-Type": "application/json; charset=UTF-8", "X-Upload-Content-Length": str(size)}
    if existing:
        init = api("PATCH", f"{UPLOAD_API}/{need_in(existing[0]['id'], root)}", {"uploadType": "resumable"}, b"{}", hdr, what="upload-init")
    else:
        init = api("POST", UPLOAD_API, {"uploadType": "resumable"},
                   json.dumps({"name": name, "parents": [need_in(parent["id"], root)]}).encode(), hdr, what="upload-init")
    session = init.headers.get("Location", ""); init.close()
    if not session.startswith(UPLOAD_API):
        die("upload session refused")
    pos, result, stalls = 0, None, 0
    while result is None:
        src.seek(pos)
        chunk = src.read(CHUNK)
        rng = f"bytes {pos}-{pos + len(chunk) - 1}/{size}" if chunk else f"bytes */{size}"
        try:
            r = _req("PUT", session, chunk, {"Content-Range": rng, "Authorization": "Bearer " + AUTH.get()}, timeout=900)
            result = _json(r)
        except urllib.error.HTTPError as e:
            if e.code == 308:                              # chunk stored, continue from the server's offset
                got = e.headers.get("Range", "")
                pos = int(got.rsplit("-", 1)[1]) + 1 if got else 0; e.close(); stalls = 0; continue
            e.close()
            if e.code == 401:
                AUTH.get(renew=True)
            elif e.code not in (429, 500, 502, 503, 504):
                die(f"upload: HTTP {e.code}")
        except urllib.error.URLError:
            pass
        if result is None:                                 # transient failure: ask the server where it stands
            stalls += 1
            if stalls > 6:
                die("upload: gave up")
            time.sleep(2 ** stalls)
            try:
                _req("PUT", session, b"", {"Content-Range": f"bytes */{size}", "Authorization": "Bearer " + AUTH.get()}).close()
                break                                      # completed meanwhile; the metadata check below is authoritative
            except urllib.error.HTTPError as e:
                got = e.headers.get("Range", "") if e.code == 308 else ""
                pos = int(got.rsplit("-", 1)[1]) + 1 if got else 0; e.close()
            except urllib.error.URLError:
                pass
    fid = (result or {}).get("id") or (lookup(rel) or {}).get("id")
    meta = file_meta(fid) if fid else None
    ok = bool(meta) and meta.get("md5Checksum") == md5 and int(meta.get("size", -1)) == size
    return meta if ok else None


def deletable(file_id, studio_selftest, final_qa):
    """Only a strict descendant of <studio>/01_PROJECT_CONTROL/_selftest, or <final>/V003_*/QA/_selftest-<run>
    and its content. Proven by walking parents up; the anchors are re-resolved by path, never taken from input."""
    chain = ancestry(file_id)
    ids = [m["id"] for m in chain] if chain else []
    if not chain or file_id in (studio_selftest, final_qa, STUDIO, FINAL):
        return False
    if studio_selftest in ids[1:] and ids[-1] == STUDIO:
        return True
    if final_qa in ids[1:] and ids[-1] == FINAL:
        return SELFTEST_DIR.fullmatch(chain[ids.index(final_qa) - 1].get("name", "")) is not None
    return False


def delete_selftest(file_id):
    """Permanent delete, ONLY inside the two self-test sandboxes (see deletable)."""
    studio_selftest = (lookup(SELFTEST) or {}).get("id")
    vf = video_folder("V003")
    final_qa = next((c["id"] for c in children(vf["id"], "QA") if c["mimeType"] == FOLDER), None) if vf else None
    if not deletable(file_id, studio_selftest, final_qa):
        die("refused: delete outside the self-test sandboxes")
    api("DELETE", f"{DRIVE_API}/{file_id}", ok=(200, 204), what="delete").close()


# ---------------------------------------------------------------- commands
def cmd_bundle(out):
    rel = need_path(env("DRIVE_BUNDLE_PATH", r"[^\x00-\x1f]{1,1024}"))
    want = env("DRIVE_BUNDLE_SHA256", r"[0-9a-f]{64}")
    meta = lookup(rel)
    if not meta or meta["mimeType"] == FOLDER:
        die("bundle not found in the studio folder")
    download(meta, out)
    with open(out, "rb") as f:
        got = digest(f, "sha256")
    if not hmac.compare_digest(got, want):
        os.remove(out); die("bundle sha256 mismatch")
    log("bundle verified")


def cmd_pull(stage, manifest_path, *paths):
    manifest = {}
    for rel in paths:
        if not READ_ALLOW.fullmatch(need_path(rel)):
            die("pull path outside the read allowlist")
        meta = lookup(rel)
        if not meta:
            die("required Drive input missing")
        pull_tree(stage, rel, meta, manifest)
    save_manifest(manifest_path, manifest)
    log(f"pulled {len(manifest)} file(s)")


def cmd_pull_spec(stage, manifest_path, spec_path):
    spec = load_json(spec_path)
    entries = spec.get("pull") if isinstance(spec, dict) else None
    if not isinstance(entries, list) or len(entries) > 100:
        die("pull spec malformed")
    manifest = {}
    for e in entries:
        if not isinstance(e, dict):
            die("pull spec malformed")
        rel, exclude, keep = e.get("path"), e.get("exclude", []), e.get("keep", [])
        if not (valid_path(rel) and READ_ALLOW.fullmatch(rel)) or not isinstance(exclude, list) or not isinstance(keep, list) \
                or not all(isinstance(p, str) and PATTERN.fullmatch(p) for p in exclude) \
                or not all(isinstance(k, str) and SEGMENT.fullmatch(k) for k in keep) or len(exclude) + len(keep) > 50:
            die("pull spec entry rejected")
        meta = lookup(rel)
        if meta:                                   # absent optional inputs are fine (first render of a video)
            pull_tree(stage, rel, meta, manifest, exclude, keep)
    save_manifest(manifest_path, manifest)
    log(f"pulled {len(manifest)} file(s)")


def cmd_fetch(stage, spec_path):
    """Prefetch the job's audio. Only https://storage.googleapis.com/xi-backend/...; no Google credential is sent."""
    spec = load_json(spec_path)
    entries = spec.get("fetch") if isinstance(spec, dict) else None
    if not isinstance(entries, list) or len(entries) > 200:
        die("fetch spec malformed")
    n = 0
    for e in entries:
        url, rel = (e.get("url"), e.get("dest")) if isinstance(e, dict) else (None, None)
        if not isinstance(url, str) or len(url) > 4096 or re.search(r"[\s\x00-\x1f\\]", url):
            die("fetch URL rejected")
        u = urllib.parse.urlsplit(url)
        if u.scheme != "https" or u.netloc != FETCH_HOST or not u.path.startswith(FETCH_PREFIX) or u.fragment or ".." in u.path:
            die("fetch URL outside the allowlist")
        if not valid_path(rel) or not READ_ALLOW.fullmatch(rel):
            die("fetch destination rejected")
        dest = local_path(stage, rel)
        if os.path.isfile(dest) and not os.path.islink(dest) and os.path.getsize(dest) > 0:
            continue                               # already ingested on Drive (signed URLs expire)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        try:
            with _req("GET", url, timeout=600) as r, open(dest + ".part", "wb") as f:
                total = 0
                for b in iter(lambda: r.read(1 << 20), b""):
                    total += len(b)
                    if total > 1 << 30:
                        die("fetch too large")
                    f.write(b)
        except urllib.error.HTTPError as e:
            die(f"fetch: HTTP {e.code}")
        except urllib.error.URLError:
            die("fetch: network error")
        if total == 0:
            die("fetch: empty file")
        os.replace(dest + ".part", dest); n += 1
    log(f"fetched {n} file(s)")


def cmd_push(stage, manifest_path, scope, report_path):
    if scope != "plan" and not DELIVERABLE.fullmatch(scope):
        die("invalid push scope")
    pulled = load_json(manifest_path) or {}
    report, skipped = {"uploads": {}, "all_verified": True}, 0
    for top, dirs, files in os.walk(stage, followlinks=False):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(top, d))]
        for name in files:
            rel = os.path.relpath(os.path.join(top, name), stage).replace(os.sep, "/")
            if not valid_path(rel) or not write_allowed(rel, scope):
                skipped += 1; continue
            f = open_regular(os.path.join(top, name))
            if f is None:
                log("skip a non-regular staged file"); continue
            with f:
                md5 = digest(f); f.seek(0)
                if pulled.get(rel) == md5:
                    continue                      # unchanged since pull
                if scope == "plan":               # the plan container may only record WAITING_FOR_CAPTURE
                    try:
                        rec = json.loads(f.read(1 << 20)); f.seek(0)
                    except ValueError:
                        rec = None
                    if not isinstance(rec, dict) or rec.get("FINAL_READY") is not False or rec.get("STATUS") != "WAITING_FOR_CAPTURE":
                        log("reject a plan ledger record"); report["all_verified"] = False; continue
                if CREATE_ONLY.fullmatch(rel) and lookup(rel):
                    log("kept an existing shared input (create-only)"); continue
                meta = upload(f, rel)
            report["uploads"][rel] = "verified" if meta else "FAILED"
            report["all_verified"] &= bool(meta)
    with open(report_path, "w") as f:
        json.dump(report, f)
    log(f"uploaded {len(report['uploads'])} file(s), ignored {skipped} outside the write allowlist")
    if not report["all_verified"]:
        die("an upload did not verify")


def cmd_finalize(stage, result_path, cid, start, report_path):
    if not DELIVERABLE.fullmatch(cid) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", start):
        die("invalid finalize arguments")
    _, video, kind = cid.split("-")
    report = load_json(report_path) or {"uploads": {}, "all_verified": False}
    res = load_json(result_path) or {}
    outs = res.get("outputs") if isinstance(res, dict) else None
    outs = outs if isinstance(outs, list) and len(outs) <= 4 else []
    secs = res.get("render_seconds") if isinstance(res, dict) else None
    secs = secs if isinstance(secs, int) and 0 <= secs <= 86400 else None
    mp4_re = re.compile(rf"06_FINAL_EXPORTS/2026/{video}_[^/]+/{'MASTER' if kind == 'master' else 'REEL'}/[^/]+\.mp4")
    files = []
    for o in outs:
        mp4, qa = (o.get("mp4"), o.get("qa")) if isinstance(o, dict) else (None, None)
        q = {}
        if valid_path(qa) and re.fullmatch(rf"06_FINAL_EXPORTS/2026/{video}_[^/]+/QA/[^/]+-QA\.json", qa):
            q = load_json(local_path(stage, qa)) or {}
            q = q if isinstance(q, dict) else {}
        meta = lookup(mp4) if valid_path(mp4) and mp4_re.fullmatch(mp4) else None
        meta = file_meta(meta["id"]) if meta else None
        ok = (bool(meta) and q.get("status") == "PASS" and q.get("file") == mp4.rsplit("/", 1)[1]
              and meta.get("md5Checksum") == q.get("md5") and int(meta.get("size", -1)) == q.get("size_bytes")
              and report["uploads"].get(mp4, "verified") == "verified")
        files.append({"FILE": mp4.rsplit("/", 1)[1] if isinstance(mp4, str) else None, "PATH": mp4 if meta else None,
                      "QA_STATUS": q.get("status", "MISSING"), "DRIVE_ID": meta["id"] if meta else None,
                      "DRIVE_URL": meta.get("webViewLink") if meta else None,
                      "SIZE": int(meta["size"]) if meta else None,
                      "CHECKSUM": {"md5": meta.get("md5Checksum") if meta else None, "sha256": q.get("sha256")},
                      "VERIFIED": ok})
    ready = (len(files) == (1 if kind == "master" else 2) and all(f["VERIFIED"] for f in files) and report.get("all_verified") is True)
    rec = {"VIDEO": video, "TYPE": kind.upper(), "COMPOSITION": cid, "START": start, "END": now(), "RENDER_SECONDS": secs,
           "QA_STATUS": "PASS" if files and all(f["QA_STATUS"] == "PASS" for f in files) else "FAIL",
           "DRIVE_ID": [f["DRIVE_ID"] for f in files], "DRIVE_URL": [f["DRIVE_URL"] for f in files], "CHECKSUM": [f["CHECKSUM"] for f in files], "OUTPUTS": files,
           "UPLOADS_VERIFIED": report.get("all_verified") is True, "FINAL_READY": ready, "RUN": os.environ.get("GITHUB_RUN_ID")}
    path = os.path.join(os.path.dirname(os.path.abspath(report_path)), f"{cid}.final.json")
    with open(path, "w") as f:
        json.dump(rec, f, ensure_ascii=False, indent=1)
    with open(path, "rb") as f:
        if not upload(f, f"01_PROJECT_CONTROL/render-ledger/{cid}.final.json"):
            die("ledger upload did not verify")
    log(f"FINAL_READY={ready}")
    sys.exit(0 if ready else 1)


def cmd_logs(folder, run_name):
    rel_dir = need_path(f"{LOGS_ROOT}/{run_name}")
    ok = True
    for name in sorted(os.listdir(folder)):
        f = open_regular(os.path.join(folder, name))
        if f is None or not SEGMENT.fullmatch(name):
            continue
        with f:
            ok &= upload(f, f"{rel_dir}/{name}") is not None
    if not ok:
        die("a log upload did not verify")


def boundary():
    """(visible, outside): everything the renderer account can see must be a root or descend from one of the two."""
    items, token = [], None
    while True:
        p = {"corpora": "user", "q": "trashed = false", "pageSize": "1000", "fields": "nextPageToken,files(id,name,parents)"}
        if token:
            p["pageToken"] = token
        r = _json(api("GET", DRIVE_API, p, what="list-visible"))
        for f in r.get("files", []):
            META[f["id"]] = {**META.get(f["id"], {}), **f}; items.append(f["id"])
        token = r.get("nextPageToken")
        if not token:
            break
    return len(items), sum(root_of(i) not in (STUDIO, FINAL) for i in items)


def cmd_selftest(run_name):
    """Host-only proof of the boundary. Console: one PASS/FAIL line per check, counts only."""
    results, st = [], {}
    tag = need_path(f"{run_name}-{secrets.token_hex(4)}")

    def check(name, fn):
        t0 = time.time()
        try:
            ok, extra = fn()
        except SystemExit:
            ok, extra = False, ""
        except Exception as e:                    # no traceback: it could quote an id
            log(f"{name}: {type(e).__name__}"); ok, extra = False, ""
        print(f"selftest-{name} {'PASS' if ok else 'FAIL'} ({time.time() - t0:.0f}s){extra}", flush=True)
        results.append(ok)
        return ok

    def is_folder(fid):
        m = get_meta(fid, "id,mimeType,trashed")
        return bool(m) and m["mimeType"] == FOLDER and not m.get("trashed"), ""

    def probe(rel):
        """Upload a generated text file, download it, compare sha256 + Drive md5; return its metadata."""
        data = f"render runner selftest {now()} {secrets.token_hex(16)}\n".encode()
        path = os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), f"selftest-{secrets.token_hex(4)}.txt")
        with open(path, "wb") as f:
            f.write(data)
        with open(path, "rb") as f:
            meta = upload(f, rel)
        os.remove(path)
        if not meta:
            return None
        download(meta, path + ".dl")
        with open(path + ".dl", "rb") as f:
            back = f.read()
        os.remove(path + ".dl")
        same = hashlib.sha256(back).digest() == hashlib.sha256(data).digest() and meta["md5Checksum"] == hashlib.md5(data).hexdigest()
        return meta if same else None

    def gone(fid):
        m = get_meta(fid, "id,trashed")
        return not m or bool(m.get("trashed"))

    if not check("auth", lambda: (bool(AUTH.get()), "")):
        sys.exit(1)
    studio_ok, final_ok = check("studio-folder", lambda: is_folder(STUDIO)), check("final-folder", lambda: is_folder(FINAL))
    if not (studio_ok and final_ok):
        sys.exit(1)
    check("final-video-folders", lambda: (all(video_folder(f"V00{i}") for i in range(1, 7)), ""))

    def studio_roundtrip():
        sel = lookup(SELFTEST, create=True)
        st["a"], st["b"] = mkdir(sel["id"], tag + "-a", STUDIO)["id"], mkdir(sel["id"], tag + "-b", STUDIO)["id"]
        meta = probe(f"{SELFTEST}/{tag}-a/probe.txt")
        if not meta:
            return False, " (upload/download)"
        st["f"] = meta["id"]
        r = _json(api("PATCH", f"{DRIVE_API}/{need_in(st['f'], STUDIO)}", {"fields": "id,name"},
                      json.dumps({"name": "probe-renamed.txt"}).encode(), {"Content-Type": "application/json"}, what="rename"))
        if r.get("name") != "probe-renamed.txt":
            return False, " (rename)"
        r = _json(api("PATCH", f"{DRIVE_API}/{need_in(st['f'], STUDIO)}", {"addParents": need_in(st["b"], STUDIO),
                      "removeParents": st["a"], "fields": "id,parents"}, b"{}", {"Content-Type": "application/json"}, what="move"))
        META.pop(st["f"], None); ROOT_OF.pop(st["f"], None)
        return r.get("parents") == [st["b"]], "" if r.get("parents") == [st["b"]] else " (move)"
    check("studio-roundtrip", studio_roundtrip)

    def studio_delete():
        for k in ("a", "b"):
            if k in st:
                delete_selftest(st[k])
        return {"a", "b"} <= set(st) and all(gone(st[k]) for k in ("a", "b", "f") if k in st), ""
    check("studio-delete", studio_delete)

    def final_roundtrip():
        vf = video_folder("V003")
        meta = probe(f"06_FINAL_EXPORTS/2026/{vf['name']}/QA/_selftest-{tag}/probe.txt") if vf else None
        if not meta:
            return False, " (upload/download)"
        st["ff"], st["fd"] = meta["id"], meta["parents"][0]
        delete_selftest(st["ff"])
        delete_selftest(st["fd"])
        return gone(st["ff"]) and gone(st["fd"]), ""
    check("final-create-delete", final_roundtrip)

    def visible():
        n, outside = boundary()
        return outside == 0, f" visible items: {n}, outside studio/final: {outside}"
    check("boundary", visible)
    sys.exit(0 if all(results) else 1)


COMMANDS = {"bundle": (cmd_bundle, 1), "pull": (cmd_pull, -3), "pull-spec": (cmd_pull_spec, 3), "fetch": (cmd_fetch, 2),
            "push": (cmd_push, 4), "finalize": (cmd_finalize, 5), "logs": (cmd_logs, 2), "selftest": (cmd_selftest, 1)}

if __name__ == "__main__":
    fn, n = COMMANDS.get(sys.argv[1] if len(sys.argv) > 1 else "", (None, 0))
    args = sys.argv[2:]
    if fn is None or (len(args) != n if n >= 0 else len(args) < -n):
        die("usage: see the module docstring")
    if fn is not cmd_fetch:
        STUDIO = env("DRIVE_STUDIO_FOLDER_ID", r"[A-Za-z0-9_-]{10,100}")
        FINAL = env("DRIVE_FINAL_FOLDER_ID", r"[A-Za-z0-9_-]{10,100}")
        if STUDIO == FINAL:
            die("studio and final folders must differ")
    try:
        fn(*args)
    except SystemExit:
        raise
    except Exception as e:                       # no traceback: it could quote a URL or an id
        die(f"{fn.__name__}: {type(e).__name__}")
