"""
Authentication primitives: JWT (HMAC-SHA256) and password hashing.

Each sensitive operation has a vulnerable and a secure variant; app.py chooses
based on APP_MODE. Compare the two side by side to see the fix.
"""

import os
import hmac
import json
import time
import base64
import hashlib
import secrets

# Signing key for the JWT. Intentionally short/guessable so the token-forgery
# exercise is easy; in production this is long, random and secret.
JWT_SECRET = os.environ.get("JWT_SECRET", "campus_secret").encode()

PBKDF2_ITERATIONS = 200_000


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# --- password hashing ----------------------------------------------------
def hash_password(password: str, mode: str):
    """Return (hash_hex, salt_or_None, scheme)."""
    if mode == "secure":
        salt = secrets.token_hex(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), PBKDF2_ITERATIONS)
        return dk.hex(), salt, "pbkdf2"
    # VULN: unsalted MD5 stored in the database (fast to brute force / rainbow).
    return hashlib.md5(password.encode()).hexdigest(), None, "md5"


def verify_password(password: str, row) -> bool:
    if row["hash_scheme"] == "pbkdf2":
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                 bytes.fromhex(row["salt"]), PBKDF2_ITERATIONS).hex()
        return hmac.compare_digest(dk, row["password_hash"])
    return hashlib.md5(password.encode()).hexdigest() == row["password_hash"]


# --- JWT -----------------------------------------------------------------
def _sign(signing_input: bytes) -> str:
    return b64url_encode(hmac.new(JWT_SECRET, signing_input, hashlib.sha256).digest())


def jwt_encode(payload: dict, exp_seconds: int = 3600) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    body = dict(payload)
    body.setdefault("iat", int(time.time()))
    body.setdefault("exp", int(time.time()) + exp_seconds)
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(body, separators=(",", ":")).encode())
    return f"{h}.{p}.{_sign(f'{h}.{p}'.encode())}"


def jwt_decode_vuln(token: str):
    # VULN: the signature is never verified and alg:none is accepted, so any
    # payload (e.g. role=admin) is trusted.
    try:
        h_b64, p_b64, *_ = token.split(".")
        header = json.loads(b64url_decode(h_b64))
        payload = json.loads(b64url_decode(p_b64))
    except Exception:
        return None
    if header.get("alg") == "none":
        return payload
    return payload


def jwt_decode_secure(token: str):
    # SECURE: pin the algorithm, verify the signature in constant time, check exp.
    try:
        h_b64, p_b64, s_b64 = token.split(".")
        header = json.loads(b64url_decode(h_b64))
    except Exception:
        return None
    if header.get("alg") != "HS256":
        return None
    if not hmac.compare_digest(_sign(f"{h_b64}.{p_b64}".encode()), s_b64):
        return None
    try:
        payload = json.loads(b64url_decode(p_b64))
    except Exception:
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    return payload
