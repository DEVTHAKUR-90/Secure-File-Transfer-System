"""
crypto_engine.py
================
Core cryptographic engine for the Secure File Transfer System.

Implements:
  - AES-256-GCM authenticated encryption / decryption
  - RSA-2048 key-pair generation and OAEP-padded key wrapping
  - CSPRNG-based session key generation
  - SHA-256 file integrity hashing
  - Utility helpers for Base64 serialisation

Security notes:
  - Keys are NEVER hardcoded. All session keys are ephemeral.
  - AES-GCM provides both confidentiality AND authenticity (AEAD).
  - RSA is used ONLY to encrypt the AES session key (key-wrapping),
    never for bulk data encryption.
  - Nonces are randomly generated per encryption call (never reused).
"""

import os
import hashlib
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
AES_KEY_BITS   = 256          # AES key size in bits
AES_KEY_BYTES  = AES_KEY_BITS // 8
GCM_NONCE_BYTES = 12          # NIST-recommended 96-bit nonce for GCM
RSA_KEY_BITS   = 2048         # RSA modulus size


# ---------------------------------------------------------------------------
# 1.  Session Key Generation  (CSPRNG)
# ---------------------------------------------------------------------------

def generate_session_key() -> bytes:
    """
    Generate a cryptographically-secure 256-bit AES session key.
    Uses os.urandom() which is backed by the OS CSPRNG (/dev/urandom on Linux).
    """
    return os.urandom(AES_KEY_BYTES)


def generate_nonce() -> bytes:
    """Generate a fresh 96-bit GCM nonce. MUST be unique per encryption call."""
    return os.urandom(GCM_NONCE_BYTES)


# ---------------------------------------------------------------------------
# 2.  AES-256-GCM  (Authenticated Encryption with Associated Data)
# ---------------------------------------------------------------------------

def aes_encrypt(plaintext: bytes, key: bytes) -> dict:
    """
    Encrypt *plaintext* with AES-256-GCM.

    Returns a dict with:
      - 'ciphertext'  : Base64-encoded ciphertext + GCM auth tag
      - 'nonce'       : Base64-encoded nonce (send alongside ciphertext)
      - 'tag_included': True  (GCM appends the 16-byte tag to ciphertext)
    """
    if len(key) != AES_KEY_BYTES:
        raise ValueError(f"AES key must be {AES_KEY_BYTES} bytes, got {len(key)}")

    nonce = generate_nonce()
    aesgcm = AESGCM(key)
    # AESGCM.encrypt() returns ciphertext || tag  (tag is last 16 bytes)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    return {
        "ciphertext":   base64.b64encode(ciphertext).decode(),
        "nonce":        base64.b64encode(nonce).decode(),
        "tag_included": True,
    }


def aes_decrypt(ciphertext_b64: str, nonce_b64: str, key: bytes) -> bytes:
    """
    Decrypt and authenticate a ciphertext produced by aes_encrypt().
    Raises InvalidTag if the authentication tag verification fails
    (i.e., data was tampered with or the key is wrong).
    """
    if len(key) != AES_KEY_BYTES:
        raise ValueError(f"AES key must be {AES_KEY_BYTES} bytes")

    ciphertext = base64.b64decode(ciphertext_b64)
    nonce      = base64.b64decode(nonce_b64)

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


# ---------------------------------------------------------------------------
# 3.  RSA-2048  (Key Wrapping only — NOT bulk encryption)
# ---------------------------------------------------------------------------

def generate_rsa_keypair():
    """
    Generate an RSA-2048 key pair.
    Returns (private_key, public_key) as cryptography objects.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_BITS,
        backend=default_backend(),
    )
    return private_key, private_key.public_key()


def serialize_public_key(public_key) -> str:
    """Serialise a public key to PEM string for transmission."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode()


def load_public_key_from_pem(pem_str: str):
    """Deserialise a PEM-encoded public key."""
    return serialization.load_pem_public_key(
        pem_str.encode(), backend=default_backend()
    )


def rsa_encrypt_session_key(session_key: bytes, public_key) -> str:
    """
    Wrap *session_key* with the recipient's RSA public key (OAEP + SHA-256).
    Returns Base64-encoded encrypted key blob.

    ⚠️  This is sent on a SEPARATE channel from the encrypted file payload.
    """
    encrypted = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(encrypted).decode()


def rsa_decrypt_session_key(encrypted_key_b64: str, private_key) -> bytes:
    """
    Unwrap the RSA-encrypted session key using the recipient's private key.
    """
    encrypted = base64.b64decode(encrypted_key_b64)
    return private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ---------------------------------------------------------------------------
# 4.  SHA-256 File Integrity
# ---------------------------------------------------------------------------

def sha256_file(filepath: str) -> str:
    """
    Compute SHA-256 hash of a file. Reads in 64 KB chunks to support
    arbitrarily large files without loading them fully into memory.
    """
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hash of a bytes object."""
    return hashlib.sha256(data).hexdigest()


def verify_integrity(expected_hash: str, actual_hash: str) -> bool:
    """
    Constant-time comparison of two hex digests to prevent timing attacks.
    Returns True if they match.
    """
    return hmac_compare(expected_hash.encode(), actual_hash.encode())


def hmac_compare(a: bytes, b: bytes) -> bool:
    """Constant-time bytes comparison (avoids timing side-channels)."""
    import hmac
    return hmac.compare_digest(a, b)
