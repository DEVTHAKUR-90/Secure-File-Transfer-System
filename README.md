# 🔐 Secure File Transfer System
### BTech Final Year Project — GRC, Cryptography & Secure Networking

---

## Project Overview

A full-stack, end-to-end encrypted file transfer system built with Python + Flask.  
Every security decision is documented for examiner review.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      BROWSER CLIENT                       │
│  Login/Register → Dashboard → Upload/Download → Audit    │
└───────────────────────┬─────────────────────────────────┘
                        │ HTTPS (TLS in production)
                        ▼
┌─────────────────────────────────────────────────────────┐
│                    FLASK WEB SERVER (app.py)              │
│  Auth Routes │ Upload/Download Routes │ Audit Routes      │
└──┬───────────┬─────────────┬──────────────────┬─────────┘
   │           │             │                  │
   ▼           ▼             ▼                  ▼
auth.py  crypto_engine.py  file_transfer.py  audit_logger.py
Argon2id  AES-256-GCM       Chunking +        Chain-hash
RBAC      RSA-2048 OAEP     E2EE storage      tamper log
Sessions  SHA-256 hash      Integrity check   SQLite DB
```

---

## File Structure

```
securetransfer/
├── app.py              ← Flask server, all API routes
├── auth.py             ← Argon2 hashing, RBAC, session tokens
├── crypto_engine.py    ← AES-256-GCM, RSA-2048, SHA-256
├── file_transfer.py    ← Chunking, E2EE encrypt/decrypt
├── audit_logger.py     ← Tamper-evident chain-hash logging
├── templates/
│   ├── index.html      ← Login / Register page
│   └── dashboard.html  ← GRC dashboard UI
├── requirements.txt
├── .env.example
├── uploads/            ← Encrypted file chunks (auto-created)
├── logs/               ← Flat audit log file (auto-created)
├── users.db            ← SQLite user DB (auto-created)
└── audit.db            ← SQLite audit DB (auto-created)
```

---

## Setup & Run

### 1. Install Python dependencies

```bash
cd securetransfer
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env — at minimum change FLASK_SECRET and ADMIN_PASSWORD
```

### 3. Run the server

```bash
python app.py
```

Open your browser at: **http://localhost:5000**

Default credentials: `admin` / `Admin@1234`  
⚠️ Change the admin password immediately after first login.

---

## How to Use (Step-by-Step)

### Sender workflow
1. Register/Login as a user with role `sender`
2. Go to **Key Management** → Generate RSA Key Pair
3. Go to **Encrypt & Send** → select a file, enter recipient username
4. Copy the **Transfer Receipt** (Transfer ID + Wrapped Session Key)
5. Send the receipt to the recipient via a separate channel (email, etc.)

### Receiver workflow
1. Register/Login as a user with role `receiver`
2. Go to **Key Management** → Generate RSA Key Pair (must do BEFORE sender uploads)
3. Go to **Receive & Decrypt** → paste Transfer ID + Wrapped Session Key
4. File is decrypted and downloaded with SHA-256 integrity verified

---

## Security Implementation Details

### Password Security (auth.py)
- **Argon2id** with time_cost=2, memory_cost=65536, parallelism=2
- Random 16-byte salt built into every hash (argon2-cffi)
- Raw password discarded immediately after hashing
- **Zero plain-text passwords ever reach the database**
- Transparent hash upgrade if Argon2 parameters change

### Cryptographic Engine (crypto_engine.py)
| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Session Key | `os.urandom(32)` CSPRNG | 256-bit AES key per transfer |
| Bulk Encryption | AES-256-GCM | Confidentiality + Authenticity |
| Key Wrapping | RSA-2048 OAEP (SHA-256) | Session key exchange |
| Integrity | SHA-256 | End-to-end file hash |
| Nonce | `os.urandom(12)` | Fresh 96-bit IV per chunk |

### File Transfer Security (file_transfer.py)
- File split into **10 MB chunks** to prevent memory overflow
- Each chunk encrypted with AES-256-GCM + **unique nonce** per chunk
- GCM authentication tag protects every chunk against tampering
- Session key wrapped with RSA — **never stored alongside encrypted data**
- Full-file SHA-256 hash verified on reassembly (constant-time comparison)
- Failed transfers: **partial files are deleted** — no plaintext left on disk

### RBAC Roles (auth.py)
| Role | Send | Receive | View Logs | Manage Users |
|------|------|---------|-----------|--------------|
| admin | ✓ | ✓ | ✓ | ✓ |
| sender | ✓ | ✗ | ✗ | ✗ |
| receiver | ✗ | ✓ | ✗ | ✗ |
| viewer | ✗ | ✗ | ✓ | ✗ |

### Audit Logging (audit_logger.py)
- Every event logged: timestamp, IP, username, filename, hash, outcome
- **Chain-hash integrity**: each row hashes previous row + current data
- Any deletion or modification of past records is detectable
- Append-only SQLite + rotating flat-file secondary record
- `/api/stats` exposes chain verification result in the dashboard

### MITM Protection
- RSA key exchange uses **OAEP padding with SHA-256** (no PKCS#1 v1.5)
- Decryption key is **never sent in the same response as file data**
- In production: wrap with TLS (nginx + Let's Encrypt)

### Security Headers (app.py)
Every HTTP response includes:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Cache-Control: no-store`
- `Content-Security-Policy` (restrictive)

---

## Critical Examiner Checklist

| Requirement | Implementation | File |
|-------------|----------------|------|
| No hardcoded keys | `os.urandom()` + `.env` vars | `crypto_engine.py`, `.env.example` |
| No plain-text passwords | Argon2id hash at input layer | `auth.py` |
| Data at rest encrypted | AES-256-GCM chunks on disk | `file_transfer.py` |
| Data in transit encrypted | Session key wrapped in RSA | `crypto_engine.py` |
| MITM protection | RSA-OAEP + separate channels | `crypto_engine.py`, `app.py` |
| Integrity verification | SHA-256 pre/post hash compare | `file_transfer.py` |
| Partial file cleanup | `_safe_delete_dir` on failure | `file_transfer.py` |
| Tamper-evident logs | SHA-256 chain hash per row | `audit_logger.py` |
| RBAC | Role-based permission checks | `auth.py` |
| Session expiry | 1-hour TTL, HttpOnly cookie | `auth.py` |

---

## Testing

```bash
# Test crypto engine
python -c "
from crypto_engine import *
key = generate_session_key()
enc = aes_encrypt(b'Hello, World!', key)
dec = aes_decrypt(enc['ciphertext'], enc['nonce'], key)
assert dec == b'Hello, World!'
print('AES-256-GCM: PASS')

priv, pub = generate_rsa_keypair()
wrapped = rsa_encrypt_session_key(key, pub)
unwrapped = rsa_decrypt_session_key(wrapped, priv)
assert unwrapped == key
print('RSA-2048 Key Wrap: PASS')
"

# Run server (then use Wireshark on loopback to verify ciphertext)
python app.py
```

---

## Production Hardening (Before Deployment)

1. Add HTTPS via nginx + Let's Encrypt (set `secure=True` on cookies)
2. Replace SQLite with PostgreSQL
3. Move RSA private keys to an HSM or HashiCorp Vault
4. Add rate limiting (Flask-Limiter) on login endpoint
5. Enable file type validation and size limits on upload
6. Set `debug=False` (already done)
7. Use a WSGI server: `gunicorn app:app`

---

*Built for BTech Final Year Project — GRC, Cryptography & Secure Networking*
