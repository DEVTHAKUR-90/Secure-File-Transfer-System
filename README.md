```
███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝
███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝
███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝

         S E C U R E   F I L E   T R A N S F E R
```

<div align="center">

**BTech Final Year Project — Cryptography, Secure Networking & GRC**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)](https://python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.x-000000?style=flat-square&logo=flask)](https://flask.palletsprojects.com/)
[![AES-256](https://img.shields.io/badge/Encryption-AES--256--GCM-success?style=flat-square&logo=letsencrypt)](https://en.wikipedia.org/wiki/AES)
[![Argon2](https://img.shields.io/badge/Hashing-Argon2-blueviolet?style=flat-square)](https://en.wikipedia.org/wiki/Argon2)

*End-to-end encrypted file transfer with role-based access, audit trails, and zero plain-text exposure.*

</div>

---

## Overview

**SecureTransfer** is a cryptographically hardened file transfer system built as a BTech Final Year Project. It goes beyond a typical file-sharing app — every layer of the stack applies real-world security principles drawn from cryptography, GRC (Governance, Risk & Compliance), and secure network design.

Files are encrypted before they ever leave the sender. Passwords are never stored. Every action is logged and tamper-evident. It was designed to behave like a system you'd actually trust.

---

## Security at a Glance

```
┌──────────────────────┬──────────────────────────────────────────────┐
│  SECURITY LAYER      │  IMPLEMENTATION                              │
├──────────────────────┼──────────────────────────────────────────────┤
│  🔐 Confidentiality  │  AES-256-GCM file encryption                 │
├──────────────────────┼──────────────────────────────────────────────┤
│  🔑 Key Exchange     │  RSA-2048 asymmetric key wrapping             │
├──────────────────────┼──────────────────────────────────────────────┤
│  🧾 Integrity        │  SHA-256 hash verified pre & post transfer    │
├──────────────────────┼──────────────────────────────────────────────┤
│  👤 Authentication   │  Argon2id password hashing, unique salts      │
├──────────────────────┼──────────────────────────────────────────────┤
│  🛡️ Access Control   │  RBAC — Admin / Sender / Receiver roles       │
├──────────────────────┼──────────────────────────────────────────────┤
│  📊 Audit Logging    │  Chain-hashed logs, IP & timestamp tracking   │
├──────────────────────┼──────────────────────────────────────────────┤
│  🔒 Sessions         │  CSPRNG tokens with expiry enforcement        │
└──────────────────────┴──────────────────────────────────────────────┘
```

---

## System Architecture

```
  Client (Browser)
        │
        │  HTTPS (TLS in production)
        ▼
  ┌─────────────────────────────────────────┐
  │            Flask Server                 │
  │                                         │
  │  ┌─────────────┐  ┌──────────────────┐  │
  │  │  auth.py    │  │  crypto_engine   │  │
  │  │  Argon2 +   │  │  AES-256-GCM +   │  │
  │  │  RBAC +     │  │  RSA-2048 +      │  │
  │  │  Sessions   │  │  SHA-256         │  │
  │  └─────────────┘  └──────────────────┘  │
  │                                         │
  │  ┌─────────────┐  ┌──────────────────┐  │
  │  │ file_       │  │  audit_logger    │  │
  │  │ transfer.py │  │  Chain-hash log  │  │
  │  │ Chunked I/O │  │  GRC Compliance  │  │
  │  └─────────────┘  └──────────────────┘  │
  └─────────────────────────────────────────┘
        │
        ▼
  SQLite (users.db + audit.db)
```

---

## Transfer Flow

### Sender

```
  1. Login / Register
        │
        ▼
  2. Generate RSA Key Pair
        │
        ▼
  3. Upload file
        │   ──▶  AES-256-GCM encryption
        │   ──▶  SHA-256 hash computed
        │   ──▶  Chunked write to disk
        ▼
  4. Share  [ Transfer ID ]  +  [ Encrypted Key ]  with receiver
```

### Receiver

```
  1. Login / Register
        │
        ▼
  2. Generate RSA Key Pair
        │
        ▼
  3. Enter  [ Transfer ID ]  +  [ Encrypted Key ]
        │
        ▼
  4. Download
        │   ──▶  SHA-256 integrity check
        │   ──▶  AES-256-GCM decryption
        ▼
  5. Verified file delivered ✓
```

---

## Project Structure

```
securetransfer/
│
├── app.py                  # Application entry point & routing
├── auth.py                 # Argon2 auth, RBAC, session management
├── crypto_engine.py        # AES-256-GCM, RSA-2048, SHA-256
├── file_transfer.py        # Chunked upload/download logic
├── audit_logger.py         # Chain-hashed GRC audit trail
│
├── templates/
│   ├── index.html          # Login / landing page
│   └── dashboard.html      # User dashboard
│
├── requirements.txt
├── .env.example
│
├── uploads/                # Auto-generated at runtime
├── logs/                   # Auto-generated at runtime
├── users.db                # Auto-generated at runtime
└── audit.db                # Auto-generated at runtime
```

---

## Getting Started

### Prerequisites

- Python `3.10+`
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/DEVTHAKUR-90/Secure-File-Transfer-System.git
cd securetransfer

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
```

Edit `.env` and update the following before running:

```env
SECRET_KEY=your-strong-secret-key
ADMIN_PASSWORD=your-secure-admin-password
```

### Run

```bash
python app.py
```

Visit `http://127.0.0.1:5000` in your browser.

---

## Audit Logging & GRC Compliance

Every action in the system — login attempts, file uploads, downloads, role changes — is written to a chain-hashed audit log. Each entry links to the previous one cryptographically, making silent tampering detectable.

```
┌─────────────────────────────────────────────────────────────┐
│  Log Entry #N                                               │
│  ─────────────────────────────────────────────────────────  │
│  User       │  dev@example.com                              │
│  Action     │  FILE_DOWNLOAD                                │
│  Timestamp  │  2025-07-14  21:04:17 UTC                     │
│  IP Address │  192.168.1.42                                 │
│  Chain Hash │  sha256(entry[N-1] + entry[N])                │
└─────────────────────────────────────────────────────────────┘
```

This design supports compliance requirements around traceability and non-repudiation.

---

## Production Deployment

This project ships with a development server. For a production deployment:

```bash
# Install Gunicorn
pip install gunicorn

# Run with Gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

Pair with **Nginx** as a reverse proxy and enable **TLS** via Let's Encrypt for full HTTPS support.

> ⚠️ Always change default admin credentials before any deployment. The `.env.example` file documents every value that must be rotated.

---

## Testing

| Test Area | Method |
|-----------|--------|
| Encryption / Decryption | Standalone Python scripts against known vectors |
| File Integrity | SHA-256 comparison pre and post transfer |
| Network exposure | Packet capture confirms only ciphertext is transmitted |
| Auth hardening | Verified no plain-text credentials in DB or logs |

---

## Roadmap

- [x] AES-256-GCM file encryption
- [x] RSA-2048 key exchange
- [x] Argon2id password hashing
- [x] Role-based access control
- [x] Chain-hashed audit logging
- [ ] Full client-side end-to-end encryption
- [ ] HTTPS / TLS deployment guide
- [ ] Cloud storage backend (S3-compatible)
- [ ] Advanced admin dashboard with log visualisation

---

## Author

**Dev Thakur**

Cybersecurity enthusiast and developer focused on building systems where security is a first-class concern — not an afterthought.

[![GitHub](https://img.shields.io/badge/GitHub-DevThakur-181717?style=flat-square&logo=github)](https://github.com/DEVTHAKUR-90)

---

<div align="center">
  <sub>Built as a BTech Final Year Project — demonstrating cryptography, secure networking, and GRC principles in practice.</sub>
</div>
