# 🔐 Secure File Transfer System

### 🎓 BTech Final Year Project — GRC, Cryptography & Secure Networking

---

## 📌 Project Overview

This project implements a **secure file transfer system** designed to ensure:

* 🔐 Confidentiality (AES-256 Encryption)
* 🧾 Data Integrity (SHA-256 Hashing)
* 👤 Secure Authentication (Argon2 Password Hashing)
* 🛡️ Access Control (RBAC)
* 📊 Audit Logging (GRC Compliance)

The system is built using **Python (Flask)** and follows modern security practices used in real-world systems.

---

## 🏗️ System Architecture

```
Client (Browser)
    │
    │ HTTPS (in production)
    ▼
Flask Server (app.py)
 ├── Authentication (auth.py)
 ├── Cryptography Engine (crypto_engine.py)
 ├── File Transfer Logic (file_transfer.py)
 └── Audit Logging (audit_logger.py)
```

---

## 📂 Project Structure

```
securetransfer/
├── app.py
├── auth.py
├── crypto_engine.py
├── file_transfer.py
├── audit_logger.py
├── templates/
│   ├── index.html
│   └── dashboard.html
├── requirements.txt
├── .env.example
├── uploads/      (auto-generated)
├── logs/         (auto-generated)
├── users.db      (auto-generated)
└── audit.db      (auto-generated)
```

---

## 🚀 Features

* 🔐 AES-256-GCM Encryption for file security
* 🔑 RSA-based Key Exchange
* 🧾 SHA-256 Integrity Verification
* 👤 Secure Login with Argon2 hashing
* 🛡️ Role-Based Access Control (Admin, Sender, Receiver)
* 📊 Audit Logging with tamper detection
* 📦 Chunk-based file transfer (prevents memory issues)

---

## ⚙️ Setup & Run

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
```

Update `.env`:

* Change secret key
* Change admin password

---

### 3. Run the application

```bash
python app.py
```

Open in browser:

```
http://127.0.0.1:5000
```

---

## 👨‍💻 Usage Flow

### 🔄 Sender

1. Login/Register
2. Generate RSA Key Pair
3. Upload & encrypt file
4. Share Transfer ID + Key with receiver

### 📥 Receiver

1. Login/Register
2. Generate RSA Key Pair
3. Enter Transfer ID + Key
4. Download decrypted file

---

## 🔐 Security Implementation

### Password Security

* Argon2 hashing
* Unique salt per user
* No plain-text passwords stored

### Encryption

* AES-256-GCM for file encryption
* RSA-2048 for key exchange

### Integrity

* SHA-256 hash verification before and after transfer

### Secure Sessions

* Tokens generated using CSPRNG
* Session expiry implemented

---

## 📊 Audit Logging (GRC)

* Logs include user activity, timestamps, and IP
* Chain-hash ensures tamper detection
* Supports system monitoring and compliance

---

## ⚠️ Important Notes

* Default admin credentials must be changed
* Development server is used (not production-ready)
* Use **Gunicorn + Nginx** for deployment

---

## 🧪 Testing

* Encryption and decryption tested using Python scripts
* File integrity verified using SHA-256
* Network sniffing shows encrypted data only

---

## 🚀 Future Improvements

* Full client-side E2EE
* HTTPS deployment
* Cloud storage integration
* Advanced dashboard UI

---

## 👨‍💻 Author

**DEV THAKUR**

---

*This project demonstrates secure system design using cryptography, networking, and GRC principles.*
