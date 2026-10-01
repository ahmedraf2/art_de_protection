"""
Cryptography helpers: symmetric encryption for data at rest, and Ed25519
digital signatures for certifications.

Encryption  -> AES-256-GCM (authenticated encryption)
Signatures  -> Ed25519 (issuer signs each certification; anyone can verify)
Integrity   -> HMAC-SHA256 is used for the JWT (see auth.py)

Keys are generated on first run and kept in ./keys (git-ignored).
"""

import os
import json
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

HERE = os.path.dirname(os.path.abspath(__file__))
KEY_DIR = os.path.join(HERE, "keys")
AES_KEY_PATH = os.path.join(KEY_DIR, "aes.key")
SIGN_PRIV_PATH = os.path.join(KEY_DIR, "issuer_ed25519.pem")
SIGN_PUB_PATH = os.path.join(KEY_DIR, "issuer_ed25519.pub")


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


def ensure_keys():
    """Create the AES key and the Ed25519 issuer keypair if they don't exist."""
    os.makedirs(KEY_DIR, exist_ok=True)

    if not os.path.exists(AES_KEY_PATH):
        with open(AES_KEY_PATH, "wb") as f:
            f.write(AESGCM.generate_key(bit_length=256))
        os.chmod(AES_KEY_PATH, 0o600)

    if not os.path.exists(SIGN_PRIV_PATH):
        priv = ed25519.Ed25519PrivateKey.generate()
        with open(SIGN_PRIV_PATH, "wb") as f:
            f.write(priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
        os.chmod(SIGN_PRIV_PATH, 0o600)
        with open(SIGN_PUB_PATH, "wb") as f:
            f.write(priv.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))


# --- symmetric encryption (data at rest) ---------------------------------
def _aes_key() -> bytes:
    with open(AES_KEY_PATH, "rb") as f:
        return f.read()


def encrypt(plaintext: str) -> str:
    """Return base64(nonce || ciphertext+tag)."""
    aes = AESGCM(_aes_key())
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext.encode(), None)
    return _b64e(nonce + ct)


def decrypt(token: str) -> str:
    raw = _b64d(token)
    nonce, ct = raw[:12], raw[12:]
    aes = AESGCM(_aes_key())
    return aes.decrypt(nonce, ct, None).decode()


# --- digital signatures (certifications) ---------------------------------
def _signing_key() -> ed25519.Ed25519PrivateKey:
    with open(SIGN_PRIV_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def public_key_pem() -> str:
    with open(SIGN_PUB_PATH, "r") as f:
        return f.read()


def cert_payload(student_id, title, grade, issued_date) -> bytes:
    """Canonical bytes that get signed. Any change here breaks the signature."""
    return json.dumps(
        {"student_id": student_id, "title": title,
         "grade": grade, "issued_date": issued_date},
        sort_keys=True, separators=(",", ":"),
    ).encode()


def sign_cert(student_id, title, grade, issued_date) -> str:
    sig = _signing_key().sign(cert_payload(student_id, title, grade, issued_date))
    return _b64e(sig)


def verify_cert(student_id, title, grade, issued_date, signature_b64) -> bool:
    if not signature_b64:
        return False
    try:
        pub = _signing_key().public_key()
        pub.verify(_b64d(signature_b64),
                   cert_payload(student_id, title, grade, issued_date))
        return True
    except Exception:
        return False
