#!/usr/bin/env python3
"""
Scenario 14: Vulnerable Flask Login Application (Rate Limiting Disabled).

WARNING: This application is INTENTIONALLY VULNERABLE for educational purposes.
DO NOT deploy this in any production or internet-facing environment.

Features intentionally absent:
- No rate limiting on login endpoint
- No account lockout after failed attempts
- No CAPTCHA or anti-automation
- Plaintext password storage (for demo)
"""

import os
import sqlite3

from flask import Flask, request, jsonify, g

app = Flask(__name__)
DATABASE = os.path.join(os.path.dirname(__file__), "users.db")


def get_db():
    """Get database connection (stored in Flask's g object)."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Initialize database with sample user accounts."""
    db = sqlite3.connect(DATABASE)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            full_name TEXT,
            locked INTEGER DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS login_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            src_ip TEXT,
            success INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        -- Sample users (passwords are intentionally plaintext for demo)
        INSERT OR IGNORE INTO users (id, username, password, email, role, full_name) VALUES
            (1, 'admin', 'admin123!', 'admin@acmecorp.local', 'admin', 'System Administrator'),
            (2, 'john.doe', 'password123', 'john@acmecorp.local', 'user', 'John Doe'),
            (3, 'jane.smith', 'letmein', 'jane@acmecorp.local', 'user', 'Jane Smith'),
            (4, 'bob.wilson', 'qwerty2024', 'bob@acmecorp.local', 'manager', 'Bob Wilson'),
            (5, 'alice.chen', 'welcome1', 'alice@acmecorp.local', 'user', 'Alice Chen'),
            (6, 'carlos.garcia', 'trustno1', 'carlos@acmecorp.local', 'user', 'Carlos Garcia'),
            (7, 'emma.johnson', 'iloveyou', 'emma@acmecorp.local', 'user', 'Emma Johnson'),
            (8, 'david.lee', 'dragon2024', 'david@acmecorp.local', 'user', 'David Lee'),
            (9, 'sarah.brown', 'sunshine1', 'sarah@acmecorp.local', 'user', 'Sarah Brown'),
            (10, 'mike.taylor', 'monkey123', 'mike@acmecorp.local', 'user', 'Mike Taylor'),
            (11, 'svc_backup', 'BackupS3rv1ce!', 'svc@acmecorp.local', 'service', 'Backup Service'),
            (12, 'svc_web', 'W3bServ!ce', 'svc_web@acmecorp.local', 'service', 'Web Service');
    """)
    db.commit()
    db.close()


# ============================================================
# VULNERABLE ENDPOINTS (intentionally insecure)
# ============================================================

@app.route("/")
def index():
    return jsonify({
        "app": "WCACE Vulnerable Login App",
        "warning": "INTENTIONALLY VULNERABLE - Educational use only",
        "endpoints": ["/login", "/status", "/users"],
        "rate_limiting": "DISABLED",
        "account_lockout": "DISABLED",
    })


@app.route("/login", methods=["POST"])
def login():
    """VULNERABLE: No rate limiting, no lockout, no CAPTCHA."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    src_ip = request.remote_addr

    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password required"}), 400

    db = get_db()

    # Check credentials (using parameterized query - SQLi is not the vuln here)
    result = db.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, password)
    ).fetchone()

    if result:
        # Log successful login
        db.execute(
            "INSERT INTO login_history (username, src_ip, success) VALUES (?, ?, 1)",
            (username, src_ip)
        )
        # Reset failed attempts on success
        db.execute(
            "UPDATE users SET failed_attempts=0 WHERE username=?",
            (username,)
        )
        db.commit()
        return jsonify({
            "status": "success",
            "message": f"Welcome {result['full_name']}",
            "role": result["role"],
            "username": result["username"],
        })

    # Log failed login - NO LOCKOUT (intentionally vulnerable)
    db.execute(
        "INSERT INTO login_history (username, src_ip, success) VALUES (?, ?, 0)",
        (username, src_ip)
    )
    # Increment failed attempts but don't lock
    db.execute(
        "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username=?",
        (username,)
    )
    db.commit()

    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


@app.route("/status")
def status():
    """Show login statistics (for monitoring)."""
    db = get_db()

    total_attempts = db.execute("SELECT COUNT(*) FROM login_history").fetchone()[0]
    failed_attempts = db.execute(
        "SELECT COUNT(*) FROM login_history WHERE success=0"
    ).fetchone()[0]
    successful_logins = db.execute(
        "SELECT COUNT(*) FROM login_history WHERE success=1"
    ).fetchone()[0]

    recent_failures = db.execute(
        "SELECT username, src_ip, timestamp FROM login_history "
        "WHERE success=0 ORDER BY timestamp DESC LIMIT 10"
    ).fetchall()

    return jsonify({
        "total_attempts": total_attempts,
        "failed_attempts": failed_attempts,
        "successful_logins": successful_logins,
        "recent_failures": [dict(r) for r in recent_failures],
    })


@app.route("/users")
def list_users():
    """List user accounts and their failed attempt counts."""
    db = get_db()
    results = db.execute(
        "SELECT id, username, email, role, full_name, locked, failed_attempts FROM users"
    ).fetchall()
    return jsonify({"users": [dict(r) for r in results]})


if __name__ == "__main__":
    init_db()
    print("[*] Vulnerable login app starting on http://localhost:5000")
    print("[!] WARNING: This app is intentionally vulnerable!")
    print("[!] Rate limiting: DISABLED")
    print("[!] Account lockout: DISABLED")
    app.run(host="0.0.0.0", port=5000, debug=False)
