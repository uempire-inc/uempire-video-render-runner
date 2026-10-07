#!/usr/bin/env python3
"""Authenticated host tool of the render runner (stdlib only). It is the ONLY code that holds a Google credential.

Auth: OAuth refresh token of the OWNER's account (a dedicated OAuth client) -> short-lived access token (kept in memory
only, re-exchanged on expiry or HTTP 401, then the operation is retried once). Google would let that token reach the
owner's whole Drive, so THIS code enforces the boundary: exactly two roots, both from variables, the source/studio
folder $DRIVE_STUDIO_FOLDER_ID and the final output root $DRIVE_FINAL_FOLDER_ID. Nothing else, ever.
- Top-down provenance: KNOWN = {id: root} is seeded with the two roots; an id enters it only as a child returned by a
  scoped children() query of a KNOWN parent, or as the result of a create/upload under a KNOWN parent. Parents are never
  requested or walked upwards.
- Single choke point: api() -> guard() refuses, BEFORE any HTTP call, any files.list whose q is not
  "'<KNOWN id>' in parents and trashed = false" (+ an optional exact-name clause), any /files/<id> whose id is not KNOWN, any create,
  upload or move under an unknown parent, and any parameter outside a small allowlist (no account-wide or drive-wide search parameter).
  Every passing call is appended to an in-memory journal (never printed) that the selftest asserts on.
- 06_FINAL_EXPORTS/2026/<V00X_*>/{MASTER,REEL,QA,SUBTITLES,THUMBNAILS,MANIFEST} maps to <final>/<V00X_*>/<SUB>; every
  other path lives in the studio folder; each prefix only ever goes to its own root.
- Deletes: only ids whose recorded top-down path runs through <studio>/01_PROJECT_CONTROL/_selftest/ or
  <final>/V003_*/QA/_selftest-<run>/.

  drive.py bundle <out>                                download $DRIVE_BUNDLE_PATH, verify $DRIVE_BUNDLE_SHA256
  drive.py pull <stage> <manifest> <path>...           required Drive files -> staging tree
  drive.py pull-spec <stage> <manifest> <spec.json>    optional files/folders listed by the container (untrusted)
  drive.py fetch <stage> <spec.json>                   prefetch allowlisted HTTPS URLs (no Google credential sent)
  drive.py push <stage> <manifest> <scope> <report>    upload NEW/CHANGED allowlisted files, verify md5 + size
  drive.py finalize <stage> <result.json> <deliverable> <start> <report>   FINAL ledger record (exit 1 unless ready)
  drive.py logs <dir> <run-name>                       upload the private logs
  drive.py selftest <run-name>                         boundary self-test A-K ('<check> PASS|FAIL' only)
  drive.py selftest-offline                            checks I-K + account enforcement, no credential and no network (tripwire)
  drive.py revoke                                      end of production: revoke the refresh token, prove it is dead

Account: every fresh access token is checked against $DRIVE_ACCOUNT_EMAIL (Drive 'about') before any use; mismatch -> exit.
Env: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN, DRIVE_ACCOUNT_EMAIL, DRIVE_STUDIO_FOLDER_ID, DRIVE_FINAL_FOLDER_ID
(+ DRIVE_BUNDLE_PATH, DRIVE_BUNDLE_SHA256 for bundle). Output: no credential, URL, file id, file name or configuration
value is ever printed; progress goes to stderr (private log). Container outputs (spec, result, staged files) are
untrusted data: validated, never executed, symlinks never followed.
"""
import contextlib, datetime, fnmatch, hashlib, hmac, io, json, os, re, secrets, shutil, stat, sys, time, urllib.error, urllib.parse, urllib.request

DRIVE_API = "https://www.googleapis.com/drive/v3/files"
UPLOAD_API = "https://www.googleapis.com/upload/drive/v3/files"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
ABOUT_API = "https://www.googleapis.com/drive/v3/about"
EMAIL = r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}"
FOLDER = "application/vnd.google-apps.folder"
CHUNK = 32 << 20                     # resumable upload chunk (multiple of 256 KiB)
DELIVERABLE = re.compile(r"V5-V00[1-6]-(master|reel)")
FETCH_HOST, FETCH_PREFIX = "storage.googleapis.com", "/xi-backend/"
SEGMENT = re.compile(r"[\w .,()+&@#=-]{1,200}")   # per path segment (unicode letters/digits allowed), no quotes or slashes
PATTERN = re.compile(r"[A-Za-z0-9_.*?\[\]-]{1,64}")

# Paths (relative to the studio folder) the host may READ (pull) and WRITE (push). Writes are bound to one deliverable.
READ_ALLOW = re.compile(r"(01_PROJECT_CONTROL/(jobs|render-ledger)|05_WORK_IN_PROGRESS|06_FINAL_EXPORTS/2026/V\d{3}_[^/]+/(AUDIO|QA))(/.*)?")
WRITE_ALLOW = (   # bound to ONE deliverable: {v}=V00X, {k}=MASTER|REEL (a reel job can never touch master files)
    r"06_FINAL_EXPORTS/2026/{v}_[^/]+/{k}/[^/]*[-_]{k}[-_][^/]+",
    r"06_FINAL_EXPORTS/2026/{v}_[^/]+/(QA|THUMBNAILS|MANIFEST|SUBTITLES)/[^/]*[-_]{k}[-_][^/]+",
    r"06_FINAL_EXPORTS/2026/{v}_[^/]+/AUDIO/[^/]+",
    r"04_AUDIO/{v}_[^/]+/[^/]+",
    r"05_WORK_IN_PROGRESS/V5_QA_FAIL/{v}_[^/]+/[^/]*[-_]{k}[-_][^/]+",
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
            self.token = None
            token, expires = self._exchange()
            self._account(token)          # every fresh access token must belong to $DRIVE_ACCOUNT_EMAIL, else die
            self.token, self.expires = token, expires
        return self.token

    @staticmethod
    def _form():
        return urllib.parse.urlencode({
            "client_id": env("GOOGLE_CLIENT_ID", r"[0-9]{6,30}-[a-z0-9]{10,64}\.apps\.googleusercontent\.com"),
            "client_secret": env("GOOGLE_CLIENT_SECRET", r"[A-Za-z0-9_-]{10,128}"),
            "refresh_token": env("GOOGLE_REFRESH_TOKEN", r"[A-Za-z0-9_./-]{20,1024}"),
            "grant_type": "refresh_token"}).encode()

    @staticmethod
    def _exchange():
        try:
            r = _json(_req("POST", TOKEN_URL, Auth._form(), {"Content-Type": "application/x-www-form-urlencoded"}))
            return r["access_token"], time.time() + min(int(r.get("expires_in", 3600)), 3600)
        except urllib.error.HTTPError as e:
            die(f"credential exchange refused (HTTP {e.code})")
        except (urllib.error.URLError, KeyError, ValueError):
            die("credential exchange failed")

    @staticmethod
    def _account(token):
        """The credential must be the expected Google account (Drive 'about', fixed fields, no file id)."""
        want = env("DRIVE_ACCOUNT_EMAIL", EMAIL).lower()
        JOURNAL.append(("GET", "about", True))
        try:
            r = _json(_req("GET", ABOUT_API + "?fields=user(emailAddress)", headers={"Authorization": "Bearer " + token}, timeout=60))
            got = str((r.get("user") or {}).get("emailAddress", "")).lower()
        except (urllib.error.URLError, ValueError, AttributeError):
            die("account check failed")
        if not hmac.compare_digest(got.encode(), want.encode()):
            die("refused: the credential belongs to another Google account")

    @staticmethod
    def revoke():
        """End of production: revoke the grant, then prove the refresh token no longer exchanges -> (revoked, refused)."""
        ct = {"Content-Type": "application/x-www-form-urlencoded"}
        tok = urllib.parse.urlencode({"token": env("GOOGLE_REFRESH_TOKEN", r"[A-Za-z0-9_./-]{20,1024}")}).encode()
        try:
            _req("POST", REVOKE_URL, tok, ct, timeout=60).close(); revoked = True
        except urllib.error.HTTPError as e:
            e.close(); revoked = e.code == 400      # already revoked / invalid
        except urllib.error.URLError:
            revoked = False
        try:
            _req("POST", TOKEN_URL, Auth._form(), ct, timeout=60).close(); refused = False
        except urllib.error.HTTPError as e:
            e.close(); refused = e.code in (400, 401)
        except urllib.error.URLError:
            refused = False
        return revoked, refused


AUTH = Auth()


JOURNAL = []                         # in-memory call journal (never printed): (method, kind, scoped_or_known)
LIST_Q = re.compile(r"'([A-Za-z0-9_-]{1,128})' in parents and trashed = false(?: and name = '(?:[^'\\]|\\.)*')?")
PARAMS_OK = {"q", "pageSize", "pageToken", "fields", "alt", "uploadType", "addParents", "removeParents"}


def guard(method, url, params, body):
    """THE choke point: refuse, BEFORE any HTTP call, every request that is not provably scoped to a KNOWN item.
    Returns the journal kind. Lists must be '<KNOWN id>' in parents; every /files/<id> must be KNOWN; creates,
    uploads and moves must target KNOWN parents. No corpora / spaces / drive-wide or account-wide parameter exists."""
    if set(params) - PARAMS_OK:
        die("refused: request parameter outside the allowlist")
    for k in ("addParents", "removeParents"):
        if k in params and params[k] not in KNOWN:
            die("refused: move to or from an unknown folder")
    def parents_known():
        try:
            meta = json.loads(body or b"{}")
        except ValueError:
            die("refused: malformed metadata")
        ps = meta.get("parents")
        if not (isinstance(ps, list) and len(ps) == 1 and ps[0] in KNOWN):
            die("refused: create under an unknown parent")
    if url == DRIVE_API and method == "GET":
        m = LIST_Q.fullmatch(params.get("q", ""))
        if not m or m.group(1) not in KNOWN:
            die("refused: list not scoped to a known parent")
        return "list"
    if url in (DRIVE_API, UPLOAD_API) and method == "POST":
        parents_known()
        return "create" if url == DRIVE_API else "upload-init"
    for base, kinds in ((DRIVE_API + "/", {"GET": "get", "PATCH": "update", "DELETE": "delete"}), (UPLOAD_API + "/", {"PATCH": "upload-update"})):
        if url.startswith(base) and method in kinds:
            if url[len(base):] not in KNOWN:
                die("refused: request on an id that was not reached top-down")
            return kinds[method]
    die("refused: endpoint outside the allowlist")


def api(method, url, params=None, body=None, headers=None, ok=(200,), what="request"):
    """Authenticated call through guard(). 401 -> re-exchange once and retry; 429/5xx -> bounded backoff. Never logs the URL."""
    kind = guard(method, url, dict(params or {}), body)
    JOURNAL.append((method, kind, True))
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


# ---------------------------------------------------------------- top-down provenance: two roots, nothing else, ever
STUDIO = None                        # DRIVE_STUDIO_FOLDER_ID (working tree, ledger, logs, audio, QA-fail, _selftest)
FINAL = None                         # DRIVE_FINAL_FOLDER_ID  (<V00X_*>/{MASTER,REEL,QA,SUBTITLES,THUMBNAILS,MANIFEST})
FINAL_SUBS = ("MASTER", "REEL", "QA", "SUBTITLES", "THUMBNAILS", "MANIFEST")
FINAL_ROUTE = re.compile(r"06_FINAL_EXPORTS/2026/(V\d{3})_[^/]+/(MASTER|REEL|QA|SUBTITLES|THUMBNAILS|MANIFEST)(?:/(.+))?")
SELFTEST_DIR = re.compile(r"_selftest-[A-Za-z0-9-]{1,80}")   # disposable folder under <final>/V003_*/QA only
FIELDS = "id,name,mimeType,md5Checksum,sha256Checksum,size,modifiedTime,trashed,webViewLink"
KNOWN, VIA = {}, {}                  # id -> root id; id -> names from that root (the top-down path that reached it)


def seed(studio, final):
    global STUDIO, FINAL
    STUDIO, FINAL = studio, final
    KNOWN.clear(); VIA.clear()
    KNOWN.update({studio: studio, final: final}); VIA.update({studio: (), final: ()})


def register(child_id, parent_id, name):
    """An id becomes KNOWN only as the child of a KNOWN parent (scoped list result, or a create/upload under it)."""
    if parent_id not in KNOWN:
        die("refused: parent was not reached top-down")
    KNOWN[child_id], VIA[child_id] = KNOWN[parent_id], VIA[parent_id] + (name,)


def need_in(file_id, root=None):
    """KNOWN check (no HTTP): the id was reached top-down from the given root (root=None: from either root)."""
    if file_id not in KNOWN or (root is not None and KNOWN[file_id] != root):
        die("refused: id not reached top-down from its allowed root")
    return file_id


def get_meta(file_id, fields=FIELDS, ok=(200,)):
    """Metadata of a KNOWN id (dies without any HTTP call otherwise); None on an allowed 404."""
    r = api("GET", f"{DRIVE_API}/{need_in(file_id)}", {"fields": fields}, ok=ok, what="metadata")
    if (r.code if isinstance(r, urllib.error.HTTPError) else r.status) != 200:
        r.close(); return None
    return _json(r)


def children(folder_id, name=None):
    """Children of ONE KNOWN folder (scoped query, never a global search); duplicate names: the newest wins."""
    q = f"'{need_in(folder_id)}' in parents and trashed = false"
    if name is not None:
        q += " and name = '" + name.replace("\\", "\\\\").replace("'", "\\'") + "'"
    out, token = [], None
    while True:
        p = {"q": q, "pageSize": "1000", "fields": f"nextPageToken,files({FIELDS})"}
        if token:
            p["pageToken"] = token
        r = _json(api("GET", DRIVE_API, p, what="list"))
        out += r.get("files", [])
        token = r.get("nextPageToken")
        if not token:
            break
    newest = {}
    for f in sorted(out, key=lambda f: f.get("modifiedTime", "")):
        newest[(f["name"], f["mimeType"] == FOLDER)] = f
    for f in newest.values():
        register(f["id"], folder_id, f["name"])
    return list(newest.values())


def mkdir(parent, name, root):
    meta = _json(api("POST", DRIVE_API, {"fields": FIELDS}, json.dumps(
        {"name": name, "mimeType": FOLDER, "parents": [need_in(parent, root)]}).encode(),
        {"Content-Type": "application/json"}, what="mkdir"))
    register(meta["id"], parent, name)
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
        hits = children(parent, part)
        last = i == len(parts) - 1
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
    """Create or replace <rel> under its root from an open local file; return verified metadata or None."""
    if not upload_allowed(need_path(rel)):
        die("refused: upload outside the allowlisted prefixes")
    size = os.fstat(src.fileno()).st_size
    md5 = digest(src); src.seek(0)
    sha = digest(src, "sha256"); src.seek(0)
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
    if not session.startswith(UPLOAD_API + "?"):
        die("upload session refused")
    pos, result, stalls = 0, None, 0
    while result is None:
        src.seek(pos)
        chunk = src.read(CHUNK)
        rng = f"bytes {pos}-{pos + len(chunk) - 1}/{size}" if chunk else f"bytes */{size}"
        JOURNAL.append(("PUT", "upload-session", True))
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
            JOURNAL.append(("PUT", "upload-session", True))
            try:
                _req("PUT", session, b"", {"Content-Range": f"bytes */{size}", "Authorization": "Bearer " + AUTH.get()}).close()
                break                                      # completed meanwhile; the metadata check below is authoritative
            except urllib.error.HTTPError as e:
                got = e.headers.get("Range", "") if e.code == 308 else ""
                pos = int(got.rsplit("-", 1)[1]) + 1 if got else 0; e.close()
            except urllib.error.URLError:
                pass
    if (result or {}).get("id"):
        register(result["id"], parent["id"], name)       # created under a KNOWN parent
    fid = (result or {}).get("id") or (lookup(rel) or {}).get("id")
    meta = file_meta(fid) if fid else None
    for _ in range(5):                                     # Drive may publish sha256Checksum a moment after md5
        if not meta or meta.get("sha256Checksum"):
            break
        time.sleep(3); meta = file_meta(fid)
    ok = (bool(meta) and meta.get("md5Checksum") == md5 and meta.get("sha256Checksum") == sha
          and int(meta.get("size", -1)) == size)
    return meta if ok else None


def deletable(file_id):
    """Only an id reached top-down THROUGH <studio>/01_PROJECT_CONTROL/_selftest/ (strictly below it) or through
    <final>/V003_*/QA/_selftest-<run> (that folder or below). Decided from the recorded path, no HTTP call."""
    if file_id not in KNOWN or file_id in (STUDIO, FINAL):
        return False
    root, via = KNOWN[file_id], VIA[file_id]
    if root == STUDIO:
        return len(via) >= 3 and via[:2] == tuple(SELFTEST.split("/"))
    return (root == FINAL and len(via) >= 3 and via[0].startswith("V003_") and via[1] == "QA"
            and SELFTEST_DIR.fullmatch(via[2]) is not None)


def delete_selftest(file_id):
    """Permanent delete, ONLY inside the two self-test sandboxes (see deletable)."""
    if not deletable(file_id):
        die("refused: delete outside the self-test sandboxes")
    api("DELETE", f"{DRIVE_API}/{file_id}", ok=(200, 204), what="delete").close()


def upload_allowed(rel):
    """Generic upload backstop (push additionally binds writes to ONE deliverable)."""
    any_v = {"v": r"V\d{3}", "k": "(?:MASTER|REEL)", "cid": DELIVERABLE.pattern}
    return (any(re.fullmatch(p.format(**any_v), rel) for p in WRITE_ALLOW) or bool(PLAN_WRITE.fullmatch(rel))
            or re.fullmatch(rf"{LOGS_ROOT}/[^/]+/[^/]+", rel) is not None
            or re.fullmatch(rf"{SELFTEST}/[^/]+/[^/]+", rel) is not None
            or re.fullmatch(r"06_FINAL_EXPORTS/2026/V003_[^/]+/QA/_selftest-[A-Za-z0-9-]{1,80}/[^/]+", rel) is not None)


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
              and meta.get("md5Checksum") == q.get("md5") and meta.get("sha256Checksum") == q.get("sha256")
              and int(meta.get("size", -1)) == q.get("size_bytes") and report["uploads"].get(mp4, "verified") == "verified")
        files.append({"FILE": mp4.rsplit("/", 1)[1] if isinstance(mp4, str) else None, "PATH": mp4 if meta else None,
                      "QA_STATUS": q.get("status", "MISSING"), "DRIVE_ID": meta["id"] if meta else None,
                      "DRIVE_URL": meta.get("webViewLink") if meta else None,
                      "SIZE": int(meta["size"]) if meta else None,
                      "CHECKSUM": {"md5": meta.get("md5Checksum") if meta else None, "sha256": meta.get("sha256Checksum") if meta else None},
                      "VERIFIED": ok, "_qa": q})
    ready = (len(files) == (1 if kind == "master" else 2) and all(f["VERIFIED"] for f in files) and report.get("all_verified") is True)
    for f in files:                              # one manifest per verified output, next to it in <V00X>/MANIFEST
        q = f.pop("_qa")
        if f["VERIFIED"]:
            ok_manifest = write_manifest(stage, report_path, cid, video, kind, f, q, ready)
            ready &= ok_manifest
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


def write_manifest(stage, report_path, cid, video, kind, f, q, ready):
    """Final manifest: technical values from the container QA (typed, re-validated), Drive facts from the host."""
    val = lambda k, t: (lambda v: v if isinstance(v, t) and not isinstance(v, bool) else None)(((q.get("checks") or {}).get(k) or {}).get("value"))
    stem = f["FILE"][:-4]
    folder = f["PATH"].rsplit("/", 2)[0]
    spec = (load_json(local_path(stage, f"{folder}/MANIFEST/{stem}-MANIFEST.json")) or {}).get("render") or {}
    ref = lambda v: v if isinstance(v, (str, dict, list)) and len(json.dumps(v)) < 4096 else None
    m = {"video_id": video, "composition_id": cid, "type": kind.upper(), "file": f["FILE"], "render_timestamp_utc": now(),
         "duration_s": val("duration_s", (int, float)), "width": val("width", int), "height": val("height", int), "fps": val("fps", (int, float)),
         "video_codec": val("video_codec", str), "audio_codec": val("audio_codec", str), "audio_loudness_lufs": val("integrated_lufs", (int, float)),
         "true_peak_dbtp": val("true_peak_dbtp", (int, float)), "file_size": f["SIZE"], "sha256": f["CHECKSUM"]["sha256"], "md5": f["CHECKSUM"]["md5"],
         "drive_file_id": f["DRIVE_ID"], "drive_url": f["DRIVE_URL"], "drive_destination": "FINAL_ROOT/" + "/".join(f["PATH"].split("/")[2:4]),
         "narration_reference": ref((spec.get("stems") or {}).get("vo")), "music_reference": ref((spec.get("stems") or {}).get("music")),
         "audio_sources": ref([{k: a.get(k) for k in ("dest_name", "generation_id", "kind") if isinstance(a, dict)} for a in spec.get("audio") or []][:40]),
         "subtitle_reference": ref(spec.get("subtitles")),
         "qa_results": {k: bool(c.get("pass")) for k, c in (q.get("checks") or {}).items() if isinstance(c, dict) and SEGMENT.fullmatch(str(k))},
         "qa_status": q.get("status"), "FINAL_READY": ready}
    path = os.path.join(os.path.dirname(os.path.abspath(report_path)), f"{stem}-FINAL-MANIFEST.json")
    with open(path, "w") as out:
        json.dump(m, out, ensure_ascii=False, indent=1)
    with open(path, "rb") as fh:
        return upload(fh, f"{folder}/MANIFEST/{stem}-FINAL-MANIFEST.json") is not None


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


def probes(stage):
    """Check I: synthetic unauthorized requests. Each must be refused (die) BEFORE any HTTP call (check J)."""
    rand = secrets.token_urlsafe(25)[:33]
    return [
        ("dotdot-path", lambda: lookup("01_PROJECT_CONTROL/../x")),
        ("absolute-path", lambda: lookup("/etc/passwd")),
        ("read-outside-prefixes", lambda: cmd_pull(stage, os.path.join(stage, "m.json"), "07_ARCHIVE/x")),
        ("upload-outside-prefixes", lambda: upload(io.BytesIO(b"x"), "07_ARCHIVE/x.txt")),
        ("get-unknown-id", lambda: get_meta(rand)),
        ("download-unknown-id", lambda: download({"id": rand, "mimeType": "text/plain", "md5Checksum": "0", "size": "1"},
                                                 os.path.join(stage, "dl"))),
        ("upload-into-unknown-parent", lambda: api("POST", UPLOAD_API, {"uploadType": "resumable"},
                                                   json.dumps({"name": "x", "parents": [rand]}).encode())),
        ("update-unknown-id", lambda: api("PATCH", f"{UPLOAD_API}/{rand}", {"uploadType": "resumable"}, b"{}")),
        ("delete-unknown-id", lambda: delete_selftest(rand)),
        ("list-unknown-parent", lambda: children(rand)),
        ("move-to-unknown-parent", lambda: api("PATCH", f"{DRIVE_API}/{STUDIO}", {"addParents": rand}, b"{}")),
        ("unscoped-list", lambda: api("GET", DRIVE_API, {"q": "trashed = false"})),
        ("name-only-search", lambda: api("GET", DRIVE_API, {"q": "name = 'x'"})),
        ("root-alias", lambda: api("GET", DRIVE_API, {"q": "'root' in parents and trashed = false"})),
        ("shared-with-me", lambda: api("GET", DRIVE_API, {"q": "sharedWithMe = true"})),
        ("corpora-user", lambda: api("GET", DRIVE_API, {"q": f"'{STUDIO}' in parents and trashed = false", "corpora": "user"})),
        ("write-outside-deliverable", lambda: write_allowed("06_FINAL_EXPORTS/2026/V001_X/MASTER/V001-X-MASTER-FR.mp4", "V5-V003-reel")
                                                or die("refused: write outside the deliverable scope")),
        ("delete-studio-root", lambda: delete_selftest(STUDIO)),
        ("delete-final-root", lambda: delete_selftest(FINAL)),
        ("delete-outside-selftest", lambda: delete_selftest(next((i for i in KNOWN if i not in (STUDIO, FINAL) and not deletable(i)), rand))),
    ]


def boundary_checks(stage, check):
    """Checks I, J, K (shared by the online selftest and selftest-offline)."""
    refused, quiet = [], True
    for name, fn in probes(stage):
        before = len(JOURNAL)
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                fn()
            ok = False                            # not refused
        except SystemExit:
            ok = len(JOURNAL) == before           # refused by a check, not by a later failure (e.g. no credential)
        except Exception:
            ok = False
        refused.append(ok)
        quiet &= len(JOURNAL) == before
    check("I-unauthorized-requests-refused", lambda: all(refused))
    check("J-refused-before-any-http", lambda: quiet)
    check("K-journal-scoped-only", lambda: all(scoped and kind in ("about", "list", "get", "create", "update", "delete", "upload-init",
                                                                   "upload-update", "upload-session") for _, kind, scoped in JOURNAL))


def runner(check_results):
    def check(label, fn):
        try:
            with contextlib.redirect_stderr(io.StringIO()) if label[0] in "IJK" else contextlib.nullcontext():
                ok = bool(fn())
        except SystemExit:
            ok = False
        except Exception as e:                    # no traceback: it could quote an id
            log(f"{label}: {type(e).__name__}"); ok = False
        print(f"{label} {'PASS' if ok else 'FAIL'}", flush=True)
        check_results.append(ok)
        return ok
    return check


def cmd_selftest(run_name):
    """Host-only proof of the application boundary (A-K). Console: '<check> PASS|FAIL' only."""
    results, st = [], {}
    check = runner(results)
    tag = need_path(f"{run_name}-{secrets.token_hex(4)}")
    stage = os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), f"selftest-{secrets.token_hex(4)}")
    os.makedirs(stage, exist_ok=True)
    data = f"render runner selftest {now()} {secrets.token_hex(16)}\n".encode()

    def is_folder(fid):
        m = get_meta(fid, "id,mimeType,trashed")
        return bool(m) and m["mimeType"] == FOLDER and not m.get("trashed")

    if not check("A-auth-and-expected-account", lambda: AUTH.get()):
        sys.exit(1)
    check("B-source-root-folder", lambda: is_folder(STUDIO))
    check("C-final-root-and-videos", lambda: is_folder(FINAL) and all(video_folder(f"V00{i}") for i in range(1, 7)))

    def create():
        vf = video_folder("V003")
        st["paths"] = {"studio": f"{SELFTEST}/{tag}/probe.txt", "final": f"06_FINAL_EXPORTS/2026/{vf['name']}/QA/_selftest-{tag}/probe.txt"}
        p = os.path.join(stage, "probe.txt")
        with open(p, "wb") as f:
            f.write(data)
        for k, rel in st["paths"].items():
            with open(p, "rb") as f:
                meta = upload(f, rel)
            if not meta:
                return False
            st[k] = meta
            st[k + "-dir"] = lookup(rel.rsplit("/", 1)[0])["id"]
        return True
    check("D-create-probe-files", create)

    def read_back():
        for k in ("studio", "final"):
            download(st[k], os.path.join(stage, k))
        return True
    check("E-read-back", read_back)

    def compare():
        for k in ("studio", "final"):
            with open(os.path.join(stage, k), "rb") as f:
                back = f.read()
            if (hashlib.sha256(back).digest() != hashlib.sha256(data).digest() or st[k]["md5Checksum"] != hashlib.md5(data).hexdigest()
                    or st[k].get("sha256Checksum") != hashlib.sha256(data).hexdigest()):
                return False
        return True
    check("F-sha256-and-md5", compare)

    def delete():
        for k in ("studio", "final", "studio-dir", "final-dir"):
            delete_selftest(st[k]["id"] if isinstance(st[k], dict) else st[k])
        return True
    check("G-delete-files-then-run-folders", delete)

    def gone():
        ids = [st[k]["id"] if isinstance(st[k], dict) else st[k] for k in ("studio", "final", "studio-dir", "final-dir")]
        return all((lambda m: m is None or m.get("trashed"))(get_meta(i, "id,trashed", ok=(200, 404))) for i in ids)
    check("H-deletion-confirmed", gone)

    boundary_checks(stage, check)
    shutil.rmtree(stage, ignore_errors=True)
    sys.exit(0 if all(results) else 1)


def cmd_selftest_offline():
    """Checks I, J, K with no credential and no network: every HTTP attempt is a tripwire."""
    global _req
    def tripwire(*a, **k):
        NETWORK.append(1)
        raise urllib.error.URLError("offline")
    _req = tripwire
    seed("offlineStudioRoot0000", "offlineFinalRoot00000")
    register("offlineV003Folder0001", FINAL, "V003_EXAMPLE")          # a synthetic top-down tree (no HTTP)
    register("offlineV003QAFolder01", "offlineV003Folder0001", "QA")
    register("offlineQAFile00000001", "offlineV003QAFolder01", "V003-EXAMPLE-REEL-9x16-FR-QA.json")
    register("offlineCtrlFolder0001", STUDIO, "01_PROJECT_CONTROL")
    register("offlineLedgerFolder01", "offlineCtrlFolder0001", "render-ledger")
    register("offlineLedgerFile0001", "offlineLedgerFolder01", "V5-V003-reel.final.json")
    results = []
    check = runner(results)
    stage = os.path.join(os.environ.get("TMPDIR", "/tmp"), f"selftest-offline-{secrets.token_hex(4)}")
    os.makedirs(stage, exist_ok=True)
    check("offline-no-credentials-loaded", lambda: AUTH.token is None)
    check("I0-qa-file-outside-sandbox-not-deletable", lambda: not deletable("offlineQAFile00000001"))
    boundary_checks(stage, check)
    check("offline-no-network-attempted", lambda: not NETWORK)
    w = lambda rel, scope: write_allowed(rel, scope)
    check("W-reel-writes-own-outputs", lambda: all(w(f"06_FINAL_EXPORTS/2026/V003_X/{r}", "V5-V003-reel") for r in (
        "REEL/UEMPIRE_V5_V003_REEL_9x16.mp4", "REEL/UEMPIRE_V5_V003_REEL_9x16_1080x1920.mp4", "QA/UEMPIRE_V5_V003_REEL_9x16-QA.json",
        "MANIFEST/UEMPIRE_V5_V003_REEL_9x16-FINAL-MANIFEST.json", "THUMBNAILS/UEMPIRE_V5_V003_REEL_9x16.jpg")))
    check("W-reel-cannot-touch-master-or-other-video", lambda: not any(w(rel, "V5-V003-reel") for rel in (
        "06_FINAL_EXPORTS/2026/V003_X/MASTER/UEMPIRE_V5_V003_MASTER_4K.mp4", "06_FINAL_EXPORTS/2026/V003_X/REEL/UEMPIRE_V5_V003_MASTER_4K.mp4",
        "06_FINAL_EXPORTS/2026/V003_X/QA/UEMPIRE_V5_V003_MASTER_4K-QA.json", "06_FINAL_EXPORTS/2026/V001_X/REEL/UEMPIRE_V5_V001_REEL_9x16.mp4",
        "01_PROJECT_CONTROL/render-ledger/V5-V003-master.jsonl", "01_PROJECT_CONTROL/render-ledger/V5-V003-reel.final.json")))
    check("W-traversal-and-absolute-paths-invalid", lambda: not any(valid_path(r) for r in (
        "06_FINAL_EXPORTS/2026/V003_X/REEL/../MASTER/x_REEL_.mp4", "/06_FINAL_EXPORTS/x", "a//b", "./a", "a/ b")))

    def about(email):                             # a canned Drive 'about' answer; any other URL is a tripwire
        def answer(method, url, body=None, headers=None, timeout=300):
            if not url.startswith(ABOUT_API + "?"):
                return tripwire()
            return io.BytesIO(json.dumps({"user": {"emailAddress": email}}).encode())
        return answer
    os.environ.update(DRIVE_ACCOUNT_EMAIL="owner@example.com")
    def account(email):
        global _req
        _req = about(email)
        try:
            Auth._account("offline-token-" + "x" * 20)
            return True
        except SystemExit:
            return False
        finally:
            _req = tripwire
    check("A0-expected-account-accepted", lambda: account("Owner@Example.com"))
    check("A0-other-account-refused", lambda: not account("someone.else@example.com"))
    check("A0-empty-account-refused", lambda: not account(""))
    check("offline-no-network-attempted-after-account-tests", lambda: not NETWORK)
    shutil.rmtree(stage, ignore_errors=True)
    sys.exit(0 if all(results) else 1)


def cmd_revoke():
    """End of production: revoke the grant, then prove the credential no longer works. Console: '<check> PASS|FAIL' only."""
    revoked, refused = AUTH.revoke()
    print(f"revoke {'PASS' if revoked else 'FAIL'}", flush=True)
    print(f"post-revoke-auth-refused {'PASS' if refused else 'FAIL'}", flush=True)
    sys.exit(0 if revoked and refused else 1)


NETWORK = []
COMMANDS = {"bundle": (cmd_bundle, 1), "pull": (cmd_pull, -3), "pull-spec": (cmd_pull_spec, 3), "fetch": (cmd_fetch, 2),
            "push": (cmd_push, 4), "finalize": (cmd_finalize, 5), "logs": (cmd_logs, 2), "selftest": (cmd_selftest, 1),
            "selftest-offline": (cmd_selftest_offline, 0), "revoke": (cmd_revoke, 0)}

if __name__ == "__main__":
    fn, n = COMMANDS.get(sys.argv[1] if len(sys.argv) > 1 else "", (None, 0))
    args = sys.argv[2:]
    if fn is None or (len(args) != n if n >= 0 else len(args) < -n):
        die("usage: see the module docstring")
    if fn not in (cmd_fetch, cmd_selftest_offline, cmd_revoke):
        seed(env("DRIVE_STUDIO_FOLDER_ID", r"[A-Za-z0-9_-]{10,100}"), env("DRIVE_FINAL_FOLDER_ID", r"[A-Za-z0-9_-]{10,100}"))
        if STUDIO == FINAL:
            die("studio and final folders must differ")
    try:
        fn(*args)
    except SystemExit:
        raise
    except Exception as e:                       # no traceback: it could quote a URL or an id
        die(f"{fn.__name__}: {type(e).__name__}")
