"""
auth.py — cryptography + token handling for the lab.

Everything here is hand-rolled on top of the Python standard library so the
mechanisms are visible and hackable:

  * JWT (JSON Web Token) is implemented directly with HMAC-SHA256.
  * Password hashing is MD5 (vuln) vs PBKDF2-HMAC-SHA256 (secure).

For EACH sensitive operation there is a `*_vuln` and a `*_secure` variant. app.py
picks which to call based on APP_MODE. Read the two side by side to see the fix.
"""

import os
import hmac
import json
import time
import base64
import hashlib
import secrets

# NOTE: In a real app this comes from a secrets manager and is long + random.
# It is intentionally weak/guessable here so the JWT-forgery exercise is easy.
JWT_SECRET = os.environ.get("JWT_SECRET", "secret").encode()

PBKDF2_ITERATIONS = 200_000


# --------------------------------------------------------------------------
# base64url helpers (JWTs use base64url without padding)
# --------------------------------------------------------------------------
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# --------------------------------------------------------------------------
# Password hashing
# --------------------------------------------------------------------------
def hash_password(password: str, mode: str):
    """Return (password_hash_hex, salt_or_None, scheme)."""
    if mode == "secure":
        # SECURE: per-user random salt + slow KDF.
        salt = secrets.token_hex(16)
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt), PBKDF2_ITERATIONS
        )
        return dk.hex(), salt, "pbkdf2"
    else:
        # VULN: unsalted MD5 — fast to brute force, rainbow-tableable,
        #       identical passwords produce identical hashes.
        return hashlib.md5(password.encode()).hexdigest(), None, "md5"


def verify_password(password: str, row) -> bool:
    """Verify a plaintext password against a stored user row (dict-like)."""
    scheme = row["hash_scheme"]
    if scheme == "pbkdf2":
        expected = row["password_hash"]
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            bytes.fromhex(row["salt"]),
            PBKDF2_ITERATIONS,
        ).hex()
        # constant-time comparison avoids timing side channels
        return hmac.compare_digest(dk, expected)
    else:  # md5
        # VULN: plain, non-constant-time comparison of a fast unsalted hash.
        return hashlib.md5(password.encode()).hexdigest() == row["password_hash"]


# --------------------------------------------------------------------------
# JWT — signing
# --------------------------------------------------------------------------
def _sign(signing_input: bytes) -> str:
    sig = hmac.new(JWT_SECRET, signing_input, hashlib.sha256).digest()
    return b64url_encode(sig)


def jwt_encode(payload: dict, exp_seconds: int = 3600) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    body = dict(payload)
    body.setdefault("iat", int(time.time()))
    body.setdefault("exp", int(time.time()) + exp_seconds)
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(body, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    return f"{h}.{p}.{_sign(signing_input)}"


# --------------------------------------------------------------------------
# JWT — verification (the interesting part)
# --------------------------------------------------------------------------
def jwt_decode_vuln(token: str):
    """VULN: decode WITHOUT verifying the signature.

    Two classic flaws in one:
      1. The signature is never checked, so any payload is accepted.
      2. `alg: none` is honored, so an attacker can strip the signature entirely.
    Result: an attacker can mint a token with role=admin for any user.
    """
    try:
        h_b64, p_b64, *rest = token.split(".")
        header = json.loads(b64url_decode(h_b64))
        payload = json.loads(b64url_decode(p_b64))
    except Exception:
        return None

    # "alg: none" -> accept with no signature at all.
    if header.get("alg") == "none":
        return payload

    # Otherwise... we STILL don't verify the signature. Whatever the payload
    # says, we believe it. (This is the bug.)
    return payload


def jwt_decode_secure(token: str):
    """SECURE: verify algorithm, signature (constant time), and expiry."""
    try:
        h_b64, p_b64, s_b64 = token.split(".")
    except ValueError:
        return None
    try:
        header = json.loads(b64url_decode(h_b64))
    except Exception:
        return None

    # 1. Pin the algorithm. Reject 'none' and any algorithm confusion.
    if header.get("alg") != "HS256":
        return None

    # 2. Recompute and compare the signature in constant time.
    expected = _sign(f"{h_b64}.{p_b64}".encode())
    if not hmac.compare_digest(expected, s_b64):
        return None

    # 3. Only now is the payload trustworthy.
    try:
        payload = json.loads(b64url_decode(p_b64))
    except Exception:
        return None

    # 4. Enforce expiry.
    if int(payload.get("exp", 0)) < int(time.time()):
        return None

    return payload


# --------------------------------------------------------------------------
# "Remember me" tokens
# --------------------------------------------------------------------------
def remember_cookie_vuln(user) -> str:
    """VULN: the cookie is just base64(username). It carries no secret and is
    trivially forgeable — set remember=<base64 of any username> to become them."""
    return b64url_encode(user["username"].encode())


def remember_username_from_vuln_cookie(cookie_val: str):
    try:
        return b64url_decode(cookie_val).decode()
    except Exception:
        return None


def new_remember_token_secure():
    """SECURE: return (raw_token_for_cookie, sha256_hash_for_db).

    The raw token is 256 bits of CSPRNG output. Only its hash is stored, so a
    read of the DB does not reveal usable tokens; the cookie value is
    unguessable and is looked up server-side."""
    raw = secrets.token_urlsafe(32)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    return raw, digest


def hash_remember_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()
