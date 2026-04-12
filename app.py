"""
app.py
======
Flask web server for the Secure File Transfer System.

Routes:
  GET  /                  → Login / landing page
  GET  /dashboard         → GRC dashboard (auth required)
  POST /api/register      → Register a new user
  POST /api/login         → Authenticate and get session token
  POST /api/logout        → Invalidate session
  POST /api/upload        → Encrypt and upload a file
  GET  /api/files         → List available transfers
  POST /api/download      → Decrypt and download a file
  GET  /api/audit         → Audit log viewer (admin/viewer only)
  GET  /api/stats         → Dashboard statistics
  GET  /api/keygen        → Generate RSA key pair for the session
  GET  /api/health        → System health check

Security headers are set on every response.
"""

import os
import json
import base64
from functools import wraps
from flask import (Flask, request, jsonify, render_template,
                   send_file, session as flask_session, redirect, url_for)
from io import BytesIO

import auth
import audit_logger
import file_transfer
from crypto_engine import generate_rsa_keypair, serialize_public_key

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(32))

# In-memory RSA key store per session (swap for HSM/vault in production)
# Maps username → (private_key object, public_pem string)
_session_keys: dict = {}

# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
auth.init_db()
audit_logger.init_audit_db()


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]         = "DENY"
    response.headers["X-XSS-Protection"]        = "1; mode=block"
    response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"]           = "no-store, no-cache, must-revalidate"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline';"
    )
    return response


# ---------------------------------------------------------------------------
# Auth decorator
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("session_token") or request.headers.get("X-Session-Token")
        user  = auth.validate_session(token)
        if not user:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect("/")
        request.current_user = user
        request.session_token = token
        return f(*args, **kwargs)
    return decorated


def require_perm(permission):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.cookies.get("session_token") or request.headers.get("X-Session-Token")
            try:
                user = auth.require_permission(token, permission)
                request.current_user = user
                request.session_token = token
            except PermissionError as e:
                return jsonify({"error": str(e)}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=request.current_user)


# ---------------------------------------------------------------------------
# Auth API
# ---------------------------------------------------------------------------
@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400
    try:
        result = auth.register_user(
            data.get("username", "").strip(),
            data.get("password", ""),
            data.get("role", "receiver"),
        )
        audit_logger.log_event(
            audit_logger.Event.REGISTER,
            username=data.get("username"),
            ip_address=request.remote_addr,
        )
        return jsonify(result), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400
    try:
        result = auth.login_user(data.get("username",""), data.get("password",""))
        audit_logger.log_event(
            audit_logger.Event.LOGIN_OK,
            username=data.get("username"),
            ip_address=request.remote_addr,
        )
        resp = jsonify({"message": "Login successful", "username": result["username"],
                        "role": result["role"], "permissions": result["permissions"]})
        resp.set_cookie(
            "session_token", result["token"],
            httponly=True, samesite="Strict",
            secure=False,   # Set True in production with HTTPS
            max_age=auth.SESSION_TTL_SECONDS,
        )
        return resp
    except ValueError as e:
        audit_logger.log_event(
            audit_logger.Event.LOGIN_FAIL,
            username=data.get("username","unknown"),
            ip_address=request.remote_addr,
            outcome="FAILURE", severity="WARN", detail=str(e),
        )
        return jsonify({"error": str(e)}), 401


@app.route("/api/logout", methods=["POST"])
@login_required
def api_logout():
    auth.logout_user(request.session_token)
    audit_logger.log_event(
        audit_logger.Event.LOGOUT,
        username=request.current_user["username"],
        ip_address=request.remote_addr,
    )
    resp = jsonify({"message": "Logged out"})
    resp.delete_cookie("session_token")
    return resp


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------
@app.route("/api/keygen", methods=["POST"])
@login_required
def api_keygen():
    """Generate an RSA key pair for this user session and store the public key."""
    username = request.current_user["username"]
    private_key, public_key = generate_rsa_keypair()
    pub_pem = serialize_public_key(public_key)

    # Store in memory (private key) and DB (public key only)
    _session_keys[username] = (private_key, pub_pem)
    conn = auth._get_conn()
    row  = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    if row:
        auth.store_user_public_key(row[0], pub_pem)

    audit_logger.log_event(
        audit_logger.Event.KEY_EXCHANGE,
        username=username,
        ip_address=request.remote_addr,
        detail="RSA-2048 key pair generated; public key stored",
    )
    return jsonify({"message": "Key pair generated", "public_key_pem": pub_pem})


# ---------------------------------------------------------------------------
# File upload (encrypt & store)
# ---------------------------------------------------------------------------
@app.route("/api/upload", methods=["POST"])
@require_perm("can_send")
def api_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file in request"}), 400

    f            = request.files["file"]
    recipient    = request.form.get("recipient", "").strip()
    file_bytes   = f.read()
    sender       = request.current_user["username"]

    if not recipient:
        return jsonify({"error": "recipient username required"}), 400

    # Get recipient public key
    pub_pem = auth.get_user_public_key(recipient)
    if not pub_pem:
        return jsonify({"error": f"No public key found for user '{recipient}'. Ask them to generate keys first."}), 404

    try:
        result = file_transfer.encrypt_and_store_file(
            file_bytes         = file_bytes,
            original_name      = f.filename,
            sender_username    = sender,
            recipient_public_pem = pub_pem,
            ip_address         = request.remote_addr,
        )
        return jsonify({
            "message":        "File encrypted and stored successfully",
            "transfer_id":    result["transfer_id"],
            "file_hash":      result["file_hash"],
            "file_size":      result["file_size"],
            "total_chunks":   result["total_chunks"],
            "original_name":  result["original_name"],
            # Wrapped key delivered in this response — file data is stored server-side
            # In a true E2EE system this would be sent peer-to-peer
            "wrapped_session_key": result["wrapped_session_key"],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# File listing
# ---------------------------------------------------------------------------
@app.route("/api/files", methods=["GET"])
@login_required
def api_files():
    return jsonify(file_transfer.list_transfers())


# ---------------------------------------------------------------------------
# File download (decrypt & serve)
# ---------------------------------------------------------------------------
@app.route("/api/download", methods=["POST"])
@require_perm("can_receive")
def api_download():
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    transfer_id = data.get("transfer_id", "").strip()
    wrapped_key = data.get("wrapped_session_key", "").strip()
    username    = request.current_user["username"]

    if not transfer_id or not wrapped_key:
        return jsonify({"error": "transfer_id and wrapped_session_key required"}), 400

    # Get this user's private key from memory
    if username not in _session_keys:
        return jsonify({"error": "No private key in session. Please generate keys first."}), 400

    private_key, _ = _session_keys[username]

    try:
        result = file_transfer.decrypt_and_retrieve_file(
            transfer_id          = transfer_id,
            wrapped_key_b64      = wrapped_key,
            recipient_private_key = private_key,
            recipient_username   = username,
            ip_address           = request.remote_addr,
        )
        return send_file(
            BytesIO(result["plaintext"]),
            download_name = result["original_name"],
            as_attachment = True,
            mimetype      = "application/octet-stream",
        )
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 500


# ---------------------------------------------------------------------------
# Audit + Stats (GRC Dashboard)
# ---------------------------------------------------------------------------
@app.route("/api/audit", methods=["GET"])
@require_perm("can_view_logs")
def api_audit():
    limit = int(request.args.get("limit", 100))
    events = audit_logger.get_recent_events(limit)
    return jsonify(events)


@app.route("/api/stats", methods=["GET"])
@login_required
def api_stats():
    stats = audit_logger.get_stats()
    chain = audit_logger.verify_chain_integrity()
    stats["log_chain_integrity"] = chain["ok"]
    stats["chain_broken_at"]     = chain["broken_at"]
    return jsonify(stats)


@app.route("/api/users", methods=["GET"])
@require_perm("can_manage_users")
def api_users():
    return jsonify(auth.get_all_users())


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({"status": "ok", "service": "Secure File Transfer System"})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("  Secure File Transfer System")
    print("  Default admin: admin / Admin@1234")
    print("  ⚠️  Change admin password before deployment!")
    print("=" * 60)
    app.run(debug=False, host="0.0.0.0", port=5000)
