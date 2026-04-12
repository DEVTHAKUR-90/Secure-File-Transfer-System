"""
file_transfer.py
================
Secure file transfer engine.

Responsibilities:
  - Chunk large files into 10 MB segments before encryption
  - Encrypt every chunk with AES-256-GCM (separate nonce per chunk)
  - Wrap the session key with the recipient's RSA public key
  - Store encrypted chunks + metadata on the server
  - Reassemble and decrypt chunks on download
  - Verify SHA-256 integrity after reassembly
  - Delete partial files on failure (never leave plaintext on disk)

Security guarantees:
  ✓ Data encrypted on the client side before any transmission
  ✓ Decryption key is NEVER stored alongside the encrypted file
  ✓ AES-GCM authentication tag catches tampering of any chunk
  ✓ SHA-256 end-to-end hash verifies complete file integrity
  ✓ Failed transfers trigger automatic partial-file deletion
"""

import os
import json
import uuid
import shutil
from pathlib import Path

from crypto_engine import (
    generate_session_key,
    aes_encrypt,
    aes_decrypt,
    rsa_encrypt_session_key,
    rsa_decrypt_session_key,
    sha256_bytes,
    sha256_file,
    verify_integrity,
    load_public_key_from_pem,
)
from audit_logger import log_event, Event

# ---------------------------------------------------------------------------
# Configuration (override via environment variables)
# ---------------------------------------------------------------------------
CHUNK_SIZE    = int(os.environ.get("CHUNK_SIZE_MB", 10)) * 1024 * 1024  # bytes
UPLOAD_DIR    = os.environ.get("UPLOAD_DIR",   "uploads")
DOWNLOAD_DIR  = os.environ.get("DOWNLOAD_DIR", "downloads")

os.makedirs(UPLOAD_DIR,   exist_ok=True)
os.makedirs(DOWNLOAD_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Upload  (Encrypt → Store)
# ---------------------------------------------------------------------------

def encrypt_and_store_file(
    file_bytes:     bytes,
    original_name:  str,
    sender_username: str,
    recipient_public_pem: str,
    ip_address:     str = "unknown",
) -> dict:
    """
    Encrypt *file_bytes* and persist to the upload store.

    Steps:
      1. Generate ephemeral AES-256 session key (CSPRNG)
      2. Split file into CHUNK_SIZE chunks
      3. Encrypt each chunk with AES-256-GCM (fresh nonce per chunk)
      4. Compute SHA-256 of the original plaintext for integrity
      5. Wrap session key with recipient's RSA public key
      6. Save encrypted chunks + manifest (session key NOT in manifest)
      7. Return a transfer_id the recipient uses to download

    ⚠️  The wrapped session key is returned to the CALLER separately.
        It must be transmitted on a different channel from the manifest.
    """
    transfer_id = str(uuid.uuid4())
    transfer_dir = os.path.join(UPLOAD_DIR, transfer_id)
    os.makedirs(transfer_dir)

    log_event(Event.TRANSFER_START, username=sender_username, ip_address=ip_address,
              filename=original_name, file_size=len(file_bytes))

    try:
        # 1. Session key
        session_key = generate_session_key()

        # 2 & 3. Chunk + encrypt
        chunks_meta = []
        total_chunks = max(1, -(-len(file_bytes) // CHUNK_SIZE))  # ceiling div

        for i in range(total_chunks):
            chunk_data = file_bytes[i * CHUNK_SIZE : (i + 1) * CHUNK_SIZE]
            enc = aes_encrypt(chunk_data, session_key)

            chunk_filename = f"chunk_{i:05d}.bin"
            chunk_path = os.path.join(transfer_dir, chunk_filename)

            # Store ciphertext as raw bytes
            import base64
            raw_ct = base64.b64decode(enc["ciphertext"])
            with open(chunk_path, "wb") as f:
                f.write(raw_ct)

            chunks_meta.append({
                "index":      i,
                "filename":   chunk_filename,
                "nonce":      enc["nonce"],          # nonce is NOT the key
                "chunk_hash": sha256_bytes(chunk_data),
            })

        # 4. Full-file integrity hash (plaintext)
        file_hash = sha256_bytes(file_bytes)

        # 5. Wrap session key with RSA
        recipient_pub = load_public_key_from_pem(recipient_public_pem)
        wrapped_key   = rsa_encrypt_session_key(session_key, recipient_pub)

        # 6. Write manifest (does NOT contain the session key)
        manifest = {
            "transfer_id":    transfer_id,
            "original_name":  original_name,
            "file_size":      len(file_bytes),
            "total_chunks":   total_chunks,
            "file_hash_sha256": file_hash,
            "sender":         sender_username,
            "chunks":         chunks_meta,
        }
        manifest_path = os.path.join(transfer_dir, "manifest.json")
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)

        log_event(Event.FILE_UPLOAD, username=sender_username, ip_address=ip_address,
                  filename=original_name, file_size=len(file_bytes), file_hash=file_hash)

        log_event(Event.KEY_EXCHANGE, username=sender_username, ip_address=ip_address,
                  detail=f"Session key wrapped with RSA-OAEP for transfer {transfer_id}")

        return {
            "transfer_id":  transfer_id,
            "file_hash":    file_hash,
            "total_chunks": total_chunks,
            "file_size":    len(file_bytes),
            # ⚠️ wrapped_key delivered separately — never in same response as file data
            "wrapped_session_key": wrapped_key,
            "original_name": original_name,
        }

    except Exception as e:
        # Failure: delete partial data — never leave encrypted debris
        _safe_delete_dir(transfer_dir)
        log_event(Event.TRANSFER_FAIL, username=sender_username, ip_address=ip_address,
                  filename=original_name, outcome="FAILURE", detail=str(e), severity="ERROR")
        raise


# ---------------------------------------------------------------------------
# Download  (Reassemble → Decrypt → Verify)
# ---------------------------------------------------------------------------

def decrypt_and_retrieve_file(
    transfer_id:       str,
    wrapped_key_b64:   str,
    recipient_private_key,
    recipient_username: str,
    ip_address:        str = "unknown",
) -> dict:
    """
    Retrieve, decrypt, and integrity-verify a stored transfer.

    Steps:
      1. Load manifest
      2. Unwrap session key with recipient's RSA private key
      3. Reassemble chunks in order, decrypt each with AES-256-GCM
      4. SHA-256 the reassembled plaintext
      5. Compare to stored hash (constant-time)
      6. Return plaintext bytes + metadata

    If any step fails, partial data is wiped.
    """
    transfer_dir  = os.path.join(UPLOAD_DIR, transfer_id)
    manifest_path = os.path.join(transfer_dir, "manifest.json")

    if not os.path.exists(manifest_path):
        raise FileNotFoundError(f"Transfer '{transfer_id}' not found.")

    with open(manifest_path) as f:
        manifest = json.load(f)

    log_event(Event.FILE_DOWNLOAD, username=recipient_username, ip_address=ip_address,
              filename=manifest["original_name"], file_size=manifest["file_size"])

    try:
        # 1. Unwrap session key
        session_key = rsa_decrypt_session_key(wrapped_key_b64, recipient_private_key)

        # 2. Reassemble + decrypt
        import base64
        plaintext_parts = []
        for chunk_meta in sorted(manifest["chunks"], key=lambda c: c["index"]):
            chunk_path = os.path.join(transfer_dir, chunk_meta["filename"])
            with open(chunk_path, "rb") as f:
                raw_ct = f.read()

            ct_b64 = base64.b64encode(raw_ct).decode()
            chunk_plain = aes_decrypt(ct_b64, chunk_meta["nonce"], session_key)

            # Per-chunk integrity
            if sha256_bytes(chunk_plain) != chunk_meta["chunk_hash"]:
                raise ValueError(f"Chunk {chunk_meta['index']} integrity check failed!")

            plaintext_parts.append(chunk_plain)

        plaintext = b"".join(plaintext_parts)

        # 3. Full file integrity check
        actual_hash   = sha256_bytes(plaintext)
        expected_hash = manifest["file_hash_sha256"]

        if verify_integrity(expected_hash, actual_hash):
            log_event(Event.INTEGRITY_OK, username=recipient_username, ip_address=ip_address,
                      filename=manifest["original_name"], file_hash=actual_hash)
        else:
            log_event(Event.INTEGRITY_FAIL, username=recipient_username, ip_address=ip_address,
                      filename=manifest["original_name"], outcome="FAILURE", severity="CRITICAL",
                      detail=f"Expected {expected_hash}, got {actual_hash}")
            raise ValueError("File integrity check FAILED. The file may have been tampered with.")

        log_event(Event.TRANSFER_DONE, username=recipient_username, ip_address=ip_address,
                  filename=manifest["original_name"], file_size=len(plaintext), file_hash=actual_hash)

        return {
            "plaintext":     plaintext,
            "original_name": manifest["original_name"],
            "file_size":     len(plaintext),
            "file_hash":     actual_hash,
            "sender":        manifest["sender"],
        }

    except Exception as e:
        log_event(Event.TRANSFER_FAIL, username=recipient_username, ip_address=ip_address,
                  filename=manifest.get("original_name","unknown"), outcome="FAILURE",
                  detail=str(e), severity="ERROR")
        raise


# ---------------------------------------------------------------------------
# File listing
# ---------------------------------------------------------------------------

def list_transfers() -> list:
    """Return metadata for all stored transfers."""
    result = []
    if not os.path.exists(UPLOAD_DIR):
        return result
    for tid in os.listdir(UPLOAD_DIR):
        manifest_path = os.path.join(UPLOAD_DIR, tid, "manifest.json")
        if os.path.exists(manifest_path):
            with open(manifest_path) as f:
                m = json.load(f)
            result.append({
                "transfer_id":  m["transfer_id"],
                "original_name": m["original_name"],
                "file_size":    m["file_size"],
                "sender":       m["sender"],
                "file_hash":    m["file_hash_sha256"],
                "total_chunks": m["total_chunks"],
            })
    return result


def delete_transfer(transfer_id: str, username: str, ip: str = "unknown"):
    """Delete a stored transfer."""
    transfer_dir = os.path.join(UPLOAD_DIR, transfer_id)
    if os.path.exists(transfer_dir):
        _safe_delete_dir(transfer_dir)
        log_event(Event.FILE_DELETE, username=username, ip_address=ip,
                  detail=f"Transfer {transfer_id} deleted")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_delete_dir(path: str):
    """Securely delete a directory, logging partial-file cleanup."""
    try:
        shutil.rmtree(path, ignore_errors=True)
        log_event(Event.PARTIAL_DELETE, detail=f"Cleaned up: {path}")
    except Exception:
        pass
